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
