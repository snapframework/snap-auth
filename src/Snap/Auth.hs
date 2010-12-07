{-| 

  This module is intended for high-level authentication functionality for Snap
  applications.

-}
module Snap.Auth
  ( 
  -- * Auth Class
    MonadAuth(..)

  -- * Types
  , UserId(..)
  , ExternalUserId(..)
  , User(..)

  -- * Higher Level Helper Functions
  , registerUser
  , performLogin
  , performLogout
  , requireUser
  , currentUser

  ) where

import           Char
import           Maybe
import           Random

import           Control.Monad.Reader
import           Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as B
import           Data.Generics hiding ((:+:))
import           Data.Map (Map)
import           Data.Time.Clock

import           Snap.Auth.Password
import           Snap.Types


------------------------------------------------------------------------------
-- | Internal representation of a 'User'. By convention, we demand that the
-- application is able to directly fetch a 'User' using this identifier.
newtype UserId = UserId { unUid :: ByteString }
    deriving (Read,Show,Ord,Eq,Typeable,Data)


------------------------------------------------------------------------------
-- | External / end-user-facing identifier for a 'User'. 
--
-- For example, this could be a (\"username\", \"john.doe\") pair submitted
-- through a web form.
newtype ExternalUserId = EUId { unEuid :: Map ByteString ByteString } 
    deriving (Read,Show,Ord,Eq,Typeable,Data)


------------------------------------------------------------------------------
-- | Type representing the concept of a User in your application.
--
-- At a minimum, we require that your users have a unique internal identifier
-- and a scrambled password field. It may also have a parametric field that you
-- can define so that you have access to additional information that your
-- application may requrie. 
data User t = User 
  { userId :: UserId
  , userPass :: SaltedHash
  , userData :: t
  } deriving (Read,Show,Ord,Eq,Typeable,Data)


------------------------------------------------------------------------------
-- | Type class defining the set of functions needed to support user
-- authentication.
--
-- Your have to make your Application's monad a member of this typeclass and
-- implement the following functions:
class MonadSnap m => MonadAuth m where

    --------------------------------------------------------------------------
    -- | Define a hash function to be used. Use 'defaultHash' if you are unsure.
    authHash :: m HashFunc


    --------------------------------------------------------------------------
    -- | Define a function that can resolve to a 'User' from an internal
    -- 'UserId'. 
    --
    -- The 'UserId' is persisted in your application's session
    -- to check for the existence of an authenticated user in your handlers.
    -- A typical 'UserId' would be the unique database key given to your user's
    -- record.
    getUserInternal :: UserId -> m (Maybe (User t))


    --------------------------------------------------------------------------
    -- | Define a function that can resolve to a 'User' using the external, user
    -- supplied 'User' identifier.
    getUserExternal :: ExternalUserId -> m (Maybe (User t))


    --------------------------------------------------------------------------
    -- | Persist the given 'UserId' identifier in your session so that it
    -- can later be accessed using 'currentUser'.
    setCurrentUserId :: UserId -> m ()


    --------------------------------------------------------------------------
    -- | If the user is authenticated, the 'UserId' should be persisted somewhere
    -- in your session through the first 'setCurrentUserId' call. Define
    -- a function that can retrieve it.
    getCurrentUserId :: m (Maybe UserId)


    --------------------------------------------------------------------------
    -- | Define a function that creates a user record in your DB. 
    addUser :: ExternalUserId   
            -- ^ User-facing identifiers; typically passed through a web form.
            -> SaltedHash   
            -- ^ Scrambled password text; Snap.Auth will supply this to you.
            -> Params   
            -- ^ Submitted web-form params; in case you want to store other
            -- user-specific information.
            -> m (Maybe UserId)   
            -- ^ If the call succeeds, an application-internal user id.


------------------------------------------------------------------------------
-- | Authenticates a user using user-supplied 'ExternalUserId'.
--
-- Returns the internal 'UserId' if successful, 'Nothing' otherwise.
-- Note that this will not persist the authentication. See 'performLogin' for
-- that.
authenticate :: MonadAuth m => ExternalUserId -> ByteString -> m (Maybe UserId)
authenticate uid password = do
    hf <- authHash
    user <- getUserExternal uid
    authSucc <- return $ fromMaybe False $
        fmap (checkSalt hf password) (fmap userPass user)
    return $ case authSucc of
      True -> fmap userId user
      False -> Nothing


------------------------------------------------------------------------------
-- | Authenticates a user and persists the authentication in the session if
-- successful.
performLogin :: MonadAuth m => ExternalUserId -> ByteString -> m (Maybe UserId)
performLogin uid password = do
  uid <- authenticate uid password
  case uid of
    Just uid' -> setCurrentUserId uid' >> return (Just uid')
    Nothing -> return Nothing


------------------------------------------------------------------------------
-- | Logs a user out.  
performLogout :: MonadAuth m => m ()
performLogout = setCurrentUserId $ UserId ""


------------------------------------------------------------------------------
-- | Adds a user to DB with the specified 'ExternalUserId' and password.
registerUser :: MonadAuth m => ExternalUserId 
             -> ByteString 
             -> Params
             -> m (Maybe UserId)
registerUser user password params = do
  hf <- authHash
  h <- liftIO $ buildSaltAndHash hf password
  addUser user h params


------------------------------------------------------------------------------
-- | Get the current 'User' if authenticated, 'Nothing' otherwise.
currentUser :: MonadAuth m => m (Maybe (User t))
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
