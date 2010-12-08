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
  , createUserHandler
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
-- | Simple handler to log the user out. Simply sets the 'UserId' in the
-- session to empty string.
logoutHandler :: MonadAuth m 
              => m a 
              -- ^ What to do after logging out
              -> m a
logoutHandler target = performLogout >> target


------------------------------------------------------------------------------
-- | A 'MonadSnap' handler that processes a new user form. Usage is similar to 
-- 'loginHandler'.
--
-- Please note that this handler does no validation beyond checking that the
-- password and its confirmation are the same. You should probably chain
-- another handler before this one and do your validations there.
createUserHandler :: MonadAuth m => (ByteString, ByteString)
                  -- ^ Password and password confirmation param fields
                  -> m a 
                  -- ^ Action to perform upon failure
                  -> m a
                  -- ^ Successful; user has been logged, move onto this action
                  -> m a

createUserHandler (pf1, pf2) bad good = do
    pass1 <- getParam pf1
    pass2 <- getParam pf2
    fromMaybe bad $ liftM2 proc pass1 pass2
  where
    proc pass1 pass2
      | pass1 /= pass2 = bad
      | otherwise = registerAndLogin bad good pass1


------------------------------------------------------------------------------
-- | Register the new 'User' and perform the login. 
--
-- Called internally by 'createUserHandler'
registerAndLogin :: MonadAuth m => m a -> m a -> ByteString -> m a
registerAndLogin bad good password = do
  params <- getRequest >>= return . rqParams
  u <- registerUser (EUId params) password params
  maybe (return ()) (setCurrentUserId) u
  maybe bad (const good) u

