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
  , currentAuthUser
  , isLoggedIn

  -- * MonadAuth Class
  , MonadAuth(..)
  , MonadAuthUser(..)

  -- * Types
  , AuthUser(..)
  , emptyAuthUser
  , UserId(..)
  , ExternalUserId(..)
  , Password(..)

  -- * Crypto Stuff You May Need
  , HashFunc

  ) where

import           Maybe

import           Control.Applicative
import           Control.Monad.Reader
import           Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString as B
import           Data.Time

import           Snap.Auth.Password
import           Snap.Types
import           Snap.Extension.Session
import           Snap.Extension.Session.Types

------------------------------------------------------------------------------
-- | External / end-user-facing identifier for a 'AuthUser'. 
--
-- For example, this could be a (\"username\", \"john.doe\") pair submitted
-- through a web form.
newtype ExternalUserId = EUId { unEuid :: Params } 
    deriving (Read,Show,Ord,Eq)


------------------------------------------------------------------------------
-- | Password is clear when supplied by the user and encrypted later when
-- returned from the db.
data Password = ClearText ByteString
              | Encrypted ByteString
              deriving (Read, Show, Ord, Eq)

------------------------------------------------------------------------------
-- | Type representing the concept of a User in your application.
data AuthUser = AuthUser 
  { userId :: Maybe UserId
  , userEmail :: Maybe ByteString
  , userPassword :: Maybe Password
  , userSalt :: Maybe ByteString
  , userActivatedAt :: Maybe UTCTime
  , userSuspendedAt :: Maybe UTCTime
  {-, userPerishableToken :: Maybe ByteString-}
  {-, userPersistanceToken :: Maybe ByteString-}
  {-, userSingleAccessToken :: Maybe ByteString-}
  , userLoginCount :: Int
  , userFailedLoginCount :: Int
  {-, userLastRequest :: Maybe UTCTime-}
  {-, userCurrentLogin :: Maybe UTCTime-}
  {-, userLastLogin :: Maybe UTCTime-}
  {-, userCurrentLoginIp :: Maybe Int-}
  {-, userLastLoginIp :: Maybe Int-}
  , userCreatedAt :: Maybe UTCTime
  , userUpdatedAt :: Maybe UTCTime
  } deriving (Read,Show,Ord,Eq)


------------------------------------------------------------------------------
-- | A blank 'User' as a starting point
emptyAuthUser :: AuthUser
emptyAuthUser = AuthUser
  { userId = Nothing
  , userEmail = Nothing
  , userPassword = Nothing
  , userSalt = Nothing
  , userActivatedAt = Nothing
  , userSuspendedAt = Nothing
  {-, userPerishableToken = Nothing-}
  {-, userPersistanceToken = Nothing-}
  {-, userSingleAccessToken = Nothing-}
  , userLoginCount = 0
  , userFailedLoginCount = 0
  {-, userLastRequest = Nothing-}
  {-, userCurrentLogin = Nothing-}
  {-, userLastLogin = Nothing-}
  {-, userCurrentLoginIp = Nothing-}
  {-, userLastLoginIp = Nothing-}
  , userCreatedAt = Nothing
  , userUpdatedAt = Nothing
  } 


------------------------------------------------------------------------------
-- | Make 'SaltedHash' from 'AuthUser'
mkSaltedHash :: AuthUser -> SaltedHash
mkSaltedHash u = SaltedHash s p'
  where s = Salt . B.unpack $ s'
        s' = maybe (error "No user salt") id $ userSalt u
        p' = case p of 
          ClearText x -> 
            error "Can't mkSaltedHash with a ClearText user password"
          Encrypted x -> B.unpack x
        p = maybe (error "Can't mkSaltedHash with empty password") id $ 
            userPassword u



class (MonadAuth m) => MonadAuthUser m t | m -> t where

    --------------------------------------------------------------------------
    -- | Define a function that can resolve to a 'AuthUser' from an internal
    -- 'UserId'. 
    --
    -- The 'UserId' is persisted in your application's session
    -- to check for the existence of an authenticated user in your handlers.
    -- A typical 'UserId' would be the unique database key given to your user's
    -- record.
    getUserInternal :: UserId -> m (Maybe (AuthUser, t))


    --------------------------------------------------------------------------
    -- | Define a function that can resolve to a 'AuthUser' using the external,
    -- user supplied 'ExternalUserId' identifier. 
    --
    -- This is typically passed directly from the POST request.
    getUserExternal :: ExternalUserId -> m (Maybe (AuthUser, t))


    --------------------------------------------------------------------------
    -- | Implement a way to save given user in the DB.
    saveAuthUser :: (AuthUser, t) -> m (Maybe AuthUser)
  






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


    authUserTable :: m String
    authUserTable = return "users"


    authPasswordRange :: m (Int, Int)
    authPasswordRange = return (7, 25)


    authAuthenticationKeys :: m [ByteString]
    authAuthenticationKeys = return ["email"]


    -- | Remember period in seconds. Defaults to 2 weeks.
    authRememberPeriod :: m Int
    authRememberPeriod = return $ 60 * 60 * 24 * 14


    authRememberAcrossBrowsers :: m Bool
    authRememberAcrossBrowsers = return True


    authEmailValidationRegex :: m ByteString
    authEmailValidationRegex = 
      return "^([\\w\\.%\\+\\-]+)@([\\w\\-]+\\.)+([\\w]{2,})$"


    -- | Lockout after x tries, re-allow entry after y seconds
    authLockoutStrategy :: m (Maybe (Int, Int))
    authLockoutStrategy = return Nothing



------------------------------------------------------------------------------
-- | Authenticates a user using user-supplied 'ExternalUserId'.
--
-- Returns the internal 'UserId' if successful, 'Nothing' otherwise.
-- Note that this will not persist the authentication. See 'performLogin' for
-- that.
authenticate :: MonadAuthUser m t
             => ExternalUserId        -- ^ External user identifiers
             -> ByteString            -- ^ Password
             -> m (Maybe (AuthUser, t))      
authenticate uid password = do
    hf <- authHash
    user <- getUserExternal uid
    case user of
      Nothing -> return Nothing
      Just user'@(u', _) -> case check hf password u' of
        True -> do
          incrementLoginCounter user'
          return user
        False -> do
          incrementFailedLoginCounter user'
          return Nothing
    where
      check hf p u = checkSalt hf p $ mkSaltedHash u
      incrementLoginCounter usr@(u, d) = saveAuthUser (u', d)
        where u' = u { userLoginCount = userLoginCount u + 1 }
      incrementFailedLoginCounter usr@(u, d) = saveAuthUser (u', d)
        where u' = u { userFailedLoginCount = userFailedLoginCount u + 1 }
        

-- $higherlevel
-- These are the key functions you will use in your handlers. Once you have set
-- up your application's monad with 'MonadAuth', you really should not need to
-- use anything other than what is in this section.


------------------------------------------------------------------------------
-- | Given an 'ExternalUserId', authenticates the user and persists the
-- authentication in the session if successful. 
authLogin :: MonadAuthUser m t
          => ExternalUserId        -- ^ External user identifiers
          -> ByteString            -- ^ Password
          -> m (Maybe (AuthUser, t))      
authLogin euid p = authenticate euid p >>= maybe (return Nothing) login
  where 
    login x@(user, _) = do
      setSessionUserId (userId user) 
      return (Just x)


------------------------------------------------------------------------------
-- | Logs a user out from the current session.
performLogout :: MonadAuthUser m t => m ()
performLogout = setSessionUserId Nothing


------------------------------------------------------------------------------
-- | Takes a clean-text password and returns a fresh pair of password and salt
-- to be stored in your app's DB.
mkAuthCredentials :: MonadAuthUser m t
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
isLoggedIn :: MonadAuthUser m t => m Bool
isLoggedIn = getSessionUserId >>= return . maybe False (const True)


------------------------------------------------------------------------------
-- | Get the current 'AuthUser' if authenticated, 'Nothing' otherwise.
currentAuthUser :: MonadAuthUser m t => m (Maybe (AuthUser, t))
currentAuthUser = getSessionUserId >>= maybe (return Nothing) getUserInternal


------------------------------------------------------------------------------
-- | Require that an authenticated 'AuthUser' is present in the current session.
--
-- This function has no DB cost - only checks to see if a user_id is present in
-- the current session.
requireUser :: MonadAuthUser m t => m a   
            -- ^ Do this if no authenticated user is present.
            -> m a    
            -- ^ Do this if an authenticated user is present.
            -> m a
requireUser bad good = getSessionUserId >>= maybe bad (const good)
