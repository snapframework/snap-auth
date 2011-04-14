{-|

  Provides generic, somewhat customizable handlers that can be plugged 
  directly into Snap applications.

  The core 'Snap.Auth' module is pretty much stand-alone and taking these as
  starting point examples, you should be able to write your own custom
  handlers.

-}

module Snap.Auth.Handlers 
  ( loginHandler
  , logoutHandler
  , requireUser
  , checkCSRF
  ) where

import Control.Applicative ( (<|>) )
import Control.Monad (when)

import Data.ByteString (ByteString)

import Snap.Types
import Snap.Auth
import Snap.Extension.Session.CookieSession (sessionCSRFToken)

------------------------------------------------------------------------------
-- | A 'MonadSnap' handler that processes a login form. 
--
-- The request paremeters are passed to 'performLogin'
loginHandler :: MonadAuthUser m t 
             => ByteString 
             -- ^ The password param field
             -> Maybe ByteString
             -- ^ Remember field; Nothing if you want to remember function.
             -> (AuthFailure -> m a)
             -- ^ Upon failure
             -> m a 
             -- ^ Upon success
             -> m a
loginHandler pwdf remf loginFailure loginSuccess = do
    euid <- getParams >>= return . EUId 
    password <- getParam pwdf
    remember <- maybe (return Nothing) getParam remf
    let r = maybe False (=="1") remember
    mMatch <- case password of
      Nothing -> return $ Left PasswordFailure
      Just p  -> performLogin euid p r
    either loginFailure (const loginSuccess) mMatch


------------------------------------------------------------------------------
-- | Simple handler to log the user out. Deletes user from session.
logoutHandler :: MonadAuthUser m t
              => m a 
              -- ^ What to do after logging out
              -> m a
logoutHandler target = performLogout >> target


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
requireUser bad good = authenticatedUserId >>= maybe bad (const good)


------------------------------------------------------------------------------
-- | Handler to protect against CSRF attacks. Chain this handler at the
-- beginning of your routing table to enable.
--
-- Example:
--
-- @redirError = logError "Someone tried to bypass CSRF" >> redirect "/"
--
-- checkCSRF redirError >> route [myHandler, myHandler2, ...]
-- @
--
-- The convention is to submit an "authenticity_token" parameter with each
-- 'POST' request. This action will confirm its presence against what is safely
-- embedded in the session and execute the given action if they don't match.
-- The exact name of the parameter is defined by 'authAuthenticityTokenParam'.
checkCSRF :: MonadAuth m => m ()
          -- ^ Do this if CSRF token does not match.
          -> m ()
checkCSRF failAct = method POST doCheck <|> return () 
  where 
    doCheck = do
      embeddedToken <- sessionCSRFToken
      param <- authAuthenticityTokenParam
      submitted <- maybe "" id `fmap` getParam param
      when (submitted /= embeddedToken) failAct
