{-| 

  This module provides simple and secure high-level authentication
  functionality for Snap applications.

-}
module Snap.Auth
  ( 

  -- * Higher Level Functions
  -- $higherlevel
    mkAuthCredentials
  , authLogin
  , performLogout
  , requireUser
  , currentUser
  , isLoggedIn

  -- * MonadAuth Class
  , MonadAuth(..)

  -- * Types
  , UserId(..)
  , ExternalUserId(..)
  , User(..)

  -- * Crypto Stuff You May Need
  , HashFunc

  ) where

import           Maybe

import           Control.Monad.Reader
import           Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString as B
import           Data.Generics hiding ((:+:))
import qualified Data.Map as M
import           Data.Time

import           Snap.Auth.Password
import           Snap.Types
import           Snap.Extension.Session


------------------------------------------------------------------------------
-- | Internal representation of a 'User'. By convention, we demand that the
-- application is able to directly fetch a 'User' using this identifier.
--
-- Think of this type as a secure, authenticated user. You should normally
-- never see this type unless a user has been authenticated.
newtype UserId = UserId { unUid :: ByteString }
    deriving (Read,Show,Ord,Eq,Typeable,Data)


------------------------------------------------------------------------------
-- | External / end-user-facing identifier for a 'User'. 
--
-- For example, this could be a (\"username\", \"john.doe\") pair submitted
-- through a web form.
newtype ExternalUserId = EUId { unEuid :: Params } 
    deriving (Read,Show,Ord,Eq,Typeable,Data)


------------------------------------------------------------------------------
-- | Type representing the concept of a User in your application.
--
-- At a minimum, we require that your users have a unique internal identifier
-- and a scrambled password field. It may also have a parametric field that you
-- can define so that you have access to additional information that your
-- application may require. 
data User = User 
  { userId :: UserId
  , userEncryptedPassword :: ByteString
  , userSalt :: ByteString
  , userActivatedAt :: Maybe UTCTime
  , userSuspendedAt :: Maybe UTCTime
  , userPerishableToken :: ByteString
  , userPersistanceToken :: ByteString
  , userSingleAccessToken :: ByteString
  , userLoginCount :: Int
  , userFailedLoginCount :: Int
  , userLastRequest :: Maybe UTCTime
  , userCurrentLogin :: Maybe UTCTime
  , userLastLogin :: Maybe UTCTime
  , userCurrentLoginIp :: Maybe Int
  , userLastLoginIp :: Maybe Int
  } deriving (Read,Show,Ord,Eq)


------------------------------------------------------------------------------
-- | A blank 'User' as a starting point
emptyUser = User
  { userId = UserId ""
  , userEncryptedPassword = ""
  , userSalt = ""
  , userActivatedAt = Nothing
  , userSuspendedAt = Nothing
  , userPerishableToken = ""
  , userPersistanceToken = ""
  , userSingleAccessToken = ""
  , userLoginCount = 0
  , userFailedLoginCount = 0
  , userLastRequest = Nothing
  , userCurrentLogin = Nothing
  , userLastLogin = Nothing
  , userCurrentLoginIp = Nothing
  , userLastLoginIp = Nothing
  } 


------------------------------------------------------------------------------
-- | Make 'SaltedHash' from 'User'
mkSaltedHash :: User -> SaltedHash
mkSaltedHash u = SaltedHash s' p'
  where s' = Salt (B.unpack s)
        p' = B.unpack p
        p = userEncryptedPassword u
        s = userSalt u

------------------------------------------------------------------------------
-- | Typeclass for authentication and user session functionality.
--
-- Your have to make your Application's monad a member of this typeclass. 
-- Minimum complete definition: 'getUserInternal', 'getUserExternal'
--
-- Requirements:
--
--  - Your app monad has to be a 'MonadSnap'.
--
--  - Your app monad has to be a 'MonadSession'. See 'Snap.Extension.Session'.
--  This is needed so we can persist your users' login in session.
class (MonadSnap m, MonadSession m) => MonadAuth m where

    --------------------------------------------------------------------------
    -- | Define a hash function to be used. Defaults to 'defaultHash', which
    -- should be quite satisfactory for most purposes.
    authHash :: m HashFunc
    authHash = return defaultHash 


    --------------------------------------------------------------------------
    -- | Define a function that can resolve to a 'User' from an internal
    -- 'UserId'. 
    --
    -- The 'UserId' is persisted in your application's session
    -- to check for the existence of an authenticated user in your handlers.
    -- A typical 'UserId' would be the unique database key given to your user's
    -- record.
    getUserInternal :: UserId -> m (Maybe User)


    --------------------------------------------------------------------------
    -- | Define a function that can resolve to a 'User' using the external, user
    -- supplied 'ExternalUserId' identifier. 
    --
    -- This is typically passed directly from the POST request.
    getUserExternal :: ExternalUserId -> m (Maybe User)


    --------------------------------------------------------------------------
    -- | Persist the given 'UserId' identifier in your session so that it can
    -- later be accessed using 'currentUser'. A default is included using
    -- Snap.Extension.Session.
    --
    -- Please note that this is the primary way of logging a user in.  Once the
    -- the user's id has been persisted this way, 'currentUser' method will
    -- return the 'User' associated with this id.
    --
    -- If the given value is 'Nothing', your application should interpret it as
    -- removing the UserId from the session.
    --
    -- This function will be made obsolete once we figure out a standardized
    -- way to handle session persistence. snap-auth will then do it for you.
    setCurrentUserId :: Maybe UserId -> m ()
    setCurrentUserId u = do
      s <- getSession 
      let ns = maybe (M.delete "sauth_user_id" s) 
                     (\u' -> M.insert "sauth_user_id" (unUid u') s) 
                     u
      setSession ns


    --------------------------------------------------------------------------
    -- | If the user is authenticated, the 'UserId' should be persisted
    -- somewhere in your session through the first 'setCurrentUserId' call.
    -- A default is included using Snap.Extension.Session.
    --
    -- This function will be made obsolete once we figure out a standardized
    -- way to handle session persistence. snap-auth will then do it for you.
    getCurrentUserId :: m (Maybe UserId)
    getCurrentUserId = getSession 
                       >>= return . fmap UserId . M.lookup "sauth_user_id"


------------------------------------------------------------------------------
-- | Authenticates a user using user-supplied 'ExternalUserId'.
--
-- Returns the internal 'UserId' if successful, 'Nothing' otherwise.
-- Note that this will not persist the authentication. See 'performLogin' for
-- that.
authenticate :: MonadAuth m 
             => ExternalUserId        -- ^ External user identifiers
             -> ByteString            -- ^ Password
             -> m (Maybe UserId)      -- ^ Internal ID of user if match exists.
authenticate uid password = do
    hf <- authHash
    user <- getUserExternal uid
    authSucc <- return $ fromMaybe False $
        fmap (checkSalt hf password) (fmap mkSaltedHash user)
    return $ case authSucc of
      True -> fmap userId user
      False -> Nothing



-- $higherlevel
-- These are the key functions you will use in your handlers. Once you have set
-- up your application's monad with 'MonadAuth', you really should not need to
-- use anything other than what is in this section.


------------------------------------------------------------------------------
-- | Given an 'ExternalUserId', authenticates the user and persists the
-- authentication in the session if successful. 
authLogin :: MonadAuth m 
          => ExternalUserId        -- ^ External user identifiers
          -> ByteString            -- ^ Password
          -> m (Maybe UserId)      -- ^ Internal ID of user if match exists.
authLogin euid p = authenticate euid p >>= maybe (return Nothing) login
  where login uid = setCurrentUserId (Just uid) >> return (Just uid)


------------------------------------------------------------------------------
-- | Logs a user out from the current session.
performLogout :: MonadAuth m => m ()
performLogout = setCurrentUserId Nothing


------------------------------------------------------------------------------
-- | Takes a clean-text password and returns a fresh pair of password and salt
-- to be stored in your app's DB.
mkAuthCredentials :: MonadAuth m
                  => ByteString                   
                  -- ^ A given password
                  -> m (ByteString, ByteString)   
                  -- ^ (Salt, Encrypted password)
mkAuthCredentials pwd = do
  hf <- authHash
  SaltedHash (Salt s) pwd' <- liftIO $ buildSaltAndHash hf pwd
  return $ (B.pack s, B.pack pwd')


------------------------------------------------------------------------------
-- | True if a user is present in current session.
isLoggedIn :: MonadAuth m => m Bool
isLoggedIn = getCurrentUserId >>= return . maybe False (const True)


------------------------------------------------------------------------------
-- | Get the current 'User' if authenticated, 'Nothing' otherwise.
currentUser :: MonadAuth m => m (Maybe User)
currentUser = getCurrentUserId >>= maybe (return Nothing) getUserInternal


------------------------------------------------------------------------------
-- | Require that an authenticated 'User' is present in the current session.
--
-- This function has no DB cost - only checks to see if a user_id is present in
-- the current session.
requireUser :: MonadAuth m => m a   
            -- ^ Do this if no authenticated user is present.
            -> m a    
            -- ^ Do this if an authenticated user is present.
            -> m a
requireUser bad good = getCurrentUserId >>= maybe bad (const good)
