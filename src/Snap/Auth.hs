{-# LANGUAGE GeneralizedNewtypeDeriving, DeriveDataTypeable,
             OverloadedStrings #-}
module Snap.Auth
  ( MonadAuth
  , UserId(..)
  , authenticate
  , checkAndAdd
  , performLogin
  , performLogout
  ) where

import           Char
import           Maybe
import           Random

import           Control.Monad.Reader
import           Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as B
import           Data.Generics hiding ((:+:))
import           Data.Time.Clock

import           Snap.Auth.Password
import           Snap.Types


sESSION_COOKIE :: ByteString
sESSION_COOKIE = "snap-sid"


------------------------------------------------------------------------------
-- | Convenience function for creating the session cookie.
mkSessionCookie :: SessionId -> Maybe UTCTime -> Response -> Response
mkSessionCookie sid expiration = addCookie $
    Cookie "snap-sid" (B.pack $ show sid) expiration Nothing (Just "/")


------------------------------------------------------------------------------
-- | Sets the session cookie.
setSessionCookie :: MonadSnap m => SessionId -> Integer -> m ()
setSessionCookie sid ttl = do
    cur <- liftIO getCurrentTime
    modifyResponse $ mkSessionCookie sid
        (Just $ addUTCTime (fromInteger ttl) cur)


------------------------------------------------------------------------------
-- | Clears the session cookie.
clearSessionCookie :: MonadSnap m => m ()
clearSessionCookie = setSessionCookie (SessionId 0) 0


------------------------------------------------------------------------------
-- | Type representing session identifiers.
newtype SessionId = SessionId { unSid :: Integer }
    deriving (Read,Show,Ord,Eq,Typeable,Data,Num,Random)


------------------------------------------------------------------------------
-- | Generates a random session ID.  This needs to be large and strong enough
-- to provent session hijacking.
genSessionId :: MonadAuth m => m SessionId
genSessionId = do
    r <- liftIO $ randomRIO (0, 2^(128::Integer) - 1)
    return $ SessionId r

------------------------------------------------------------------------------
-- | Represents user identifiers.  This could be a username, email address, or
-- some other token supplied by the user that uniquely identifies him/her.
newtype UserId = UserId { unUid :: [ByteString] }
    deriving (Read,Show,Ord,Eq,Typeable,Data)


------------------------------------------------------------------------------
-- | Type representing session identifiers.
data User = User {
    userid :: UserId,
    userpass :: SaltedHash
} deriving (Read,Show,Ord,Eq,Typeable,Data)


------------------------------------------------------------------------------
-- | Type class defining the set of functions needed to support user sessions
-- and authentication.
class MonadSnap m => MonadAuth m where
    authHash :: m HashFunc
    createSession :: UserId -> SessionId -> m Bool
    removeSession :: SessionId -> m Bool
    getUser :: UserId -> m (Maybe User)
    addUser :: UserId -> SaltedHash -> m (Maybe UserId)


------------------------------------------------------------------------------
-- | Logs a user in.  This involves creating a session and setting the session
authenticate :: MonadAuth m => UserId -> ByteString -> m Bool
authenticate uid password = do
    hf <- authHash
    user <- getUser uid
    return $ fromMaybe False $
        fmap (checkSalt hf password) (fmap userpass user)


------------------------------------------------------------------------------
-- | Logs a user in.  This involves creating a session and setting the session
-- cookie.  This function assumes that the caller has already authenticated
-- the user.
performLogin :: MonadAuth m => UserId -> m Bool
performLogin user = do
    sid <- genSessionId
    setSessionCookie sid 2678400
    createSession user sid


------------------------------------------------------------------------------
-- | Logs a user out.  This involves deleting the session and clearing the
-- session cookie.  Returns a boolean flag indicating whether the session was
-- existed and was successfully removed.
performLogout :: MonadAuth m => m Bool
performLogout = do
    sid <- getSessionId
    clearSessionCookie
    maybe (return False) removeSession sid


------------------------------------------------------------------------------
-- | Gets the 'SessionId' for the current user.
getSessionId :: MonadAuth m => m (Maybe SessionId)
getSessionId = getCookie sESSION_COOKIE >>=
    return . fmap (read . B.unpack . cookieValue)


------------------------------------------------------------------------------
-- | Adds a user with the specified UserId and password.
register :: MonadAuth m => UserId -> ByteString -> m (Maybe UserId)
register user password = do
  hf <- authHash
  h <- liftIO $ buildSaltAndHash hf password
  addUser user h


------------------------------------------------------------------------------
-- | This function might need to be offloaded to the user as a part of the
-- 'MonadAuth' type class to allow atomicity guarantees.
checkAndAdd :: MonadAuth m => m a -> m a -> UserId -> ByteString -> m a
checkAndAdd uExists good user password = do
  u <- register user password
  maybe uExists (const good <=< performLogin) u


