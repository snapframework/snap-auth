{-| 

  This module provides simple and secure high-level authentication
  functionality for Snap applications.

-}
module Snap.Auth
  ( 

  -- * Higher Level Functions
  -- $higherlevel
    mkAuthCredentials
  , performLogin
  , performLogout
  , currentAuthUser
  , isLoggedIn
  , authenticatedUserId

  -- * MonadAuth Class
  , MonadAuth(..)
  , MonadAuthUser(..)

  -- * Types
  , AuthUser(..)
  , emptyAuthUser
  , UserId(..)
  , ExternalUserId(..)
  , Password(..)
  , AuthFailure(..)

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
import           Snap.Extension.Session.Common
import           Snap.Extension.Session.SecureCookie
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
-- | Authentication failures indicate what went wrong during authentication.
-- They may provide useful information to the developer, although it is
-- generally not advisable to show the user the exact details about why login
-- failed.
data AuthFailure = ExternalIdFailure
                 | PasswordFailure
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
  , userPersistenceToken :: Maybe ByteString
  {-, userSingleAccessToken :: Maybe ByteString-}
  , userLoginCount :: Int
  , userFailedLoginCount :: Int
  , userCurrentLoginAt :: Maybe UTCTime
  , userLastLoginAt :: Maybe UTCTime
  , userCurrentLoginIp :: Maybe ByteString
  , userLastLoginIp :: Maybe ByteString
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
  , userPersistenceToken = Nothing
  {-, userSingleAccessToken = Nothing-}
  , userLoginCount = 0
  , userFailedLoginCount = 0
  , userCurrentLoginAt = Nothing
  , userLastLoginAt = Nothing
  , userCurrentLoginIp = Nothing
  , userLastLoginIp = Nothing
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
    -- | A way to find users by the remember token.
    getUserByRememberToken :: ByteString -> m (Maybe (AuthUser, t))


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


    -- | Name of the table that will store user data   
    authUserTable :: m String
    authUserTable = return "users"


    -- | Password length range
    authPasswordRange :: m (Int, Int)
    authPasswordRange = return (7, 25)


    -- | What are the database fields and the user-supplied ExternalUserId
    -- fields that are going to be used to find a user?
    authAuthenticationKeys :: m [ByteString]
    authAuthenticationKeys = return ["email"]


    -- | Cookie name for the remember token
    authRememberCookieName :: m ByteString
    authRememberCookieName = return "auth_remember_token"


    -- | Remember period in seconds. Defaults to 2 weeks.
    authRememberPeriod :: m Int
    authRememberPeriod = return $ 60 * 60 * 24 * 14


    -- | Should it be possible to login multiple times?
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
             -> Bool                  -- ^ Remember user?
             -> m (Either AuthFailure (AuthUser, t))      
authenticate uid password remember = do
    hf <- authHash
    user <- getUserExternal uid
    case user of
      Nothing            -> return $ Left ExternalIdFailure
      Just user'@(u', _) -> case check hf password u' of
        True -> do
          markLogin user'
          return $ Right user'
        False -> do
          markLoginFail user'
          return $ Left PasswordFailure
    where
      check hf p u = checkSalt hf p $ mkSaltedHash u

      markLoginFail (u,d) = do
        u' <- incFailLogCtr u
        saveAuthUser (u', d)

      markLogin :: (MonadAuthUser m t) => (AuthUser, t) -> m (Maybe AuthUser)
      markLogin (u,d) = do
        u' <- (incLogCtr >=> updateIP >=> updateLoginTS >=> 
               setPersistenceToken) u
        saveAuthUser (u', d)

      incLogCtr :: (MonadAuthUser m t) => AuthUser -> m AuthUser
      incLogCtr u = return $ u { userLoginCount = userLoginCount u + 1 }

      incFailLogCtr :: (MonadAuthUser m t) => AuthUser -> m AuthUser
      incFailLogCtr u = return $
        u { userFailedLoginCount = userFailedLoginCount u + 1 }

      updateIP :: (MonadAuthUser m t) => AuthUser -> m AuthUser
      updateIP u = do
        ip <- getRequest >>= return . rqRemoteAddr
        return $
          u { userCurrentLoginIp = Just ip
            , userLastLoginIp = userCurrentLoginIp u }

      updateLoginTS :: (MonadAuthUser m t) => AuthUser -> m AuthUser
      updateLoginTS u = do
        t <- liftIO getCurrentTime
        return $ 
          u { userCurrentLoginAt = Just t
            , userLastLoginAt = userCurrentLoginAt u }

      setPersistenceToken u = do
        multi_logon <- authRememberAcrossBrowsers
        to <- authRememberPeriod
        site_key <- secureSiteKey
        cn <- authRememberCookieName
        rt <- liftIO $ randomToken 15
        token <- case userPersistenceToken u of
          Nothing -> return rt
          Just x -> if multi_logon then return x else return rt
        case remember of
          False -> return u
          True -> do
            setSecureCookie cn site_key token (Just to)
            return $ u { userPersistenceToken = Just token }



-- $higherlevel
-- These are the key functions you will use in your handlers. Once you have set
-- up your application's monad with 'MonadAuth', you really should not need to
-- use anything other than what is in this section.


------------------------------------------------------------------------------
-- | Given an 'ExternalUserId', authenticates the user and persists the
-- authentication in the session if successful. 
performLogin :: MonadAuthUser m t
             => ExternalUserId        -- ^ External user identifiers
             -> ByteString            -- ^ Password
             -> Bool                  -- ^ Remember user?
             -> m (Either AuthFailure (AuthUser, t))      
performLogin euid p r = authenticate euid p r >>= either (return . Left) login
  where 
    login x@(user, _) = do
      setSessionUserId (userId user) 
      return (Right x)


------------------------------------------------------------------------------
-- | Logs a user out from the current session.
performLogout :: MonadAuthUser m t => m ()
performLogout = do
  cn <- authRememberCookieName
  let ck = Cookie cn "" Nothing Nothing (Just "/")
  modifyResponse $ addResponseCookie ck
  setSessionUserId Nothing


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
isLoggedIn = authenticatedUserId >>= return . maybe False (const True)


------------------------------------------------------------------------------
-- | Get the current 'AuthUser' if authenticated, 'Nothing' otherwise.
currentAuthUser :: MonadAuthUser m t => m (Maybe (AuthUser, t))
currentAuthUser = authenticatedUserId >>= maybe (return Nothing) getUserInternal


------------------------------------------------------------------------------
-- | Return if there is an authenticated user id. Try to remember the user
-- if possible.
authenticatedUserId :: MonadAuthUser m t => m (Maybe UserId)
authenticatedUserId = getSessionUserId >>= maybe rememberUser (return . Just)

------------------------------------------------------------------------------
-- | Remember user from remember token if possible.
rememberUser :: MonadAuthUser m t => m (Maybe UserId)
rememberUser = do
  to <- authRememberPeriod
  key <- secureSiteKey
  cn <- authRememberCookieName
  remToken <- getSecureCookie cn key (Just to)
  u <- maybe (return Nothing) getUserByRememberToken remToken
  case u of
    Nothing -> return Nothing
    Just (au, _) -> do 
      setSessionUserId $ userId au
      return $ userId au
