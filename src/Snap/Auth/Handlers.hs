{-# LANGUAGE OverloadedStrings #-}

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

import Control.Monad (liftM2)
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)

import Snap.Types
import Snap.Auth

------------------------------------------------------------------------------
-- | A 'MonadSnap' handler that processes a login form. 
--
-- The request paremeters are passed to 'authLogin' function as
-- 'ExternalUserId'.
loginHandler :: MonadAuth m => ByteString 
             -- ^ The password param field
             -> m a 
             -- ^ Upon failure
             -> m a 
             -- ^ Upon success
             -> m a
loginHandler pwdf loginFailure loginSuccess = do
    euid <- getRequest >>= return . return . EUId . rqParams
    password <- getParam pwdf
    mMatch <- fromMaybe (return Nothing) $
        liftM2 authLogin euid password
    maybe loginFailure (const loginSuccess) mMatch


------------------------------------------------------------------------------
-- | Simple handler to log the user out. Deletes user from session.
logoutHandler :: MonadAuth m 
              => m a 
              -- ^ What to do after logging out
              -> m a
logoutHandler target = performLogout >> target
