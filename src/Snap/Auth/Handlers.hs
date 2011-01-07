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
  ) where

import Data.ByteString (ByteString)

import Snap.Types
import Snap.Auth

------------------------------------------------------------------------------
-- | A 'MonadSnap' handler that processes a login form. 
--
-- The request paremeters are passed to 'authLogin' function as
-- 'ExternalUserId'.
loginHandler :: MonadAuthUser m t 
             => ByteString 
             -- ^ The password param field
             -> m a 
             -- ^ Upon failure
             -> m a 
             -- ^ Upon success
             -> m a
loginHandler pwdf loginFailure loginSuccess = do
    euid <- getParams >>= return . EUId 
    password <- getParam pwdf
    mMatch <- case password of
      Nothing -> return Nothing
      Just p -> authLogin euid p
    maybe loginFailure (const loginSuccess) mMatch


------------------------------------------------------------------------------
-- | Simple handler to log the user out. Deletes user from session.
logoutHandler :: MonadAuthUser m t
              => m a 
              -- ^ What to do after logging out
              -> m a
logoutHandler target = performLogout >> target
