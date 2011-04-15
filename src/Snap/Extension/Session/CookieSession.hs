{-|

  This module provides an implementation of 'Snap.Extension.Session' using
  secure cookies shuttled back-and-forth between the web server and the user of
  your application.

  The resulting cookie contents will not be readable to the end-user. However,
  you should still never put critical information inside the session. Storing
  a user_id may be fine, but never put, say the remaining balance on an account
  in a session.

  Note that this method leaves your system open to replay, aka session
  hi-jacking attacks. To prevent this, consider always on SSL.

-}

module Snap.Extension.Session.CookieSession
  ( 

    -- * Important Types
    Session
  , UserId(..)

    -- * Key Functionality
  , MonadSession(
        getSession
      , setSession
      , getFromSession
      , setInSession
      , deleteFromSession
      , touchSession
      , clearSession
      , getSessionUserId
      , setSessionUserId
      , sessionCSRFToken)


    -- * Cookie-based Session Instance
  , CookieSessionState(..)
  , defCookieSessionState
  , HasCookieSessionState(..)
  , cookieSessionStateInitializer
  ) where

import Control.Monad.Reader
import Data.ByteString (ByteString)

import Web.ClientSession

import Snap.Extension
import Snap.Extension.Session
import Snap.Extension.Session.SecureCookie
import Snap.Extension.Session.Types


------------------------------------------------------------------------------
-- | 
data CookieSessionState = CookieSessionState
  { csSiteKey :: Key                -- ^ Cookie encryption key
  , csKeyPath :: FilePath           -- ^ Where the encryption key is stored
  , csCookieName :: ByteString      -- ^ Cookie name for your app's session
  , csTimeout :: Maybe Int          -- ^ Replay-attack timeout in seconds
  }


------------------------------------------------------------------------------
-- | 'defCookieSessionState' is a good starting point when initializing your
-- app. The default configuration is:
--
-- > csKeyPath = "site_key.txt"
-- > csCookieName = "snap-session"
-- > csTimeout = Just 30
-- > csAuthToken = True
defCookieSessionState :: CookieSessionState
defCookieSessionState = CookieSessionState 
                          { csKeyPath = "site_key.txt"
                          , csSiteKey = ""
                          , csCookieName = "snap-session"
                          , csTimeout = Just (30 * 60)
                          }


------------------------------------------------------------------------------
-- |
class HasCookieSessionState s where

  ----------------------------------------------------------------------------
  -- | Getter to get 'CookieSessionState' from your app's state.
  getCookieSessionState :: s -> CookieSessionState

------------------------------------------------------------------------------
-- | Initializes the given 'CookieSessionState'. It will read the encryption
-- key if present, create one at random and save if missing.
cookieSessionStateInitializer 
  :: CookieSessionState
  -> Initializer CookieSessionState
cookieSessionStateInitializer cs = do
  st <- liftIO $ do
    k <- getKey (csKeyPath cs) 
    return $ cs { csSiteKey = k }
  mkInitializer st


------------------------------------------------------------------------------
-- | Register CookieSessionState as an Extension.
instance InitializerState CookieSessionState where
  extensionId = const "Session/CookieSession"
  mkCleanup = const $ return ()
  mkReload = const $ return ()


------------------------------------------------------------------------------
-- |
instance HasCookieSessionState s => MonadSession (SnapExtend s) where

  ----------------------------------------------------------------------------
  -- | Serialize the session, inject into cookie, modify response.
  setSessionShell t = do
    cs <- asks getCookieSessionState
    key <- secureSiteKey
    setSecureCookie (csCookieName cs) key t (csTimeout cs)


  ----------------------------------------------------------------------------
  -- | Read the session from the cookie. If none is present, return default
  -- (empty) session.
  getSessionShell = do
    cs <- asks getCookieSessionState
    key <- secureSiteKey
    let cn = csCookieName cs
    let timeout = csTimeout cs
    d <- getSecureCookie cn key timeout
    return $ maybe defSessionShell id d


  secureSiteKey = asks $ csSiteKey . getCookieSessionState


