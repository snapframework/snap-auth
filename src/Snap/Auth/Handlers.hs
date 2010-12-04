{-# LANGUAGE OverloadedStrings #-}

{-|

  Provides generic, somewhat customizable handlers that can be plugged 
  directly into Snap applications.

-}

module Snap.Auth.Handlers 
  ( loginHandler
  , logoutHandler
  , newUserHandler
  ) where

import Control.Monad (liftM2, liftM3)
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)

import Snap.Types
import Snap.Auth

------------------------------------------------------------------------------
-- | A 'MonadSnap' handler that processes a login form. Pass fields that
-- uniquely identify a user (i.e. username, email address,
-- OpenID identifier, etc) and the password field.
--
-- Example Usage:
--
-- @loginHandler [\"account\", \"username\"] \"password\" lSuccess lFail@
--
-- TODO Add support for a challenge/response system to avoid transmitting
-- cleartext passwords.
loginHandler :: MonadAuth m 
             => [ByteString] 
             -- ^ A list of submitted params that uniquely identify a user
             -> ByteString 
             -- ^ The password param field
             -> m a 
             -- ^ Upon success
             -> m a 
             -- ^ Upon failure
             -> m a
loginHandler uidfs pwdf loginSuccess loginFailure = do
    uid <- mapM getParam uidfs >>= return . sequence
    password <- getParam pwdf
    mMatch <- fromMaybe (return False) $
        liftM2 authenticate (fmap UserId uid) password
    if mMatch then loginSuccess else loginFailure


------------------------------------------------------------------------------
-- | This function might be unnecessary.  Leaving it in until we see how
-- things flesh out in actual use.
logoutHandler :: MonadAuth m 
              => m a 
              -- ^ What to do after logging out
              -> m a
logoutHandler target = performLogout >> target


------------------------------------------------------------------------------
-- | A 'MonadSnap' handler that processes a new user form. Usage is similar to 
-- "loginHandler".
--
-- Example Usage:
--
-- @newUserHandler [\"account\", \"username\"] 
--                 (\"pass\", \"pass_conf\") 
--                 uValidate existsOrInvalid noMatch success@
newUserHandler :: MonadAuth m 
               => [ByteString]
               -- ^ A list of param fields that uniquely identify a user
               -> (ByteString, ByteString)
               -- ^ Password and password confirmation param fields
               -> ([ByteString] -> Bool)
               -- ^ A function that validates the given set of user identifiers
               -> m a 
               -- ^ Action to perform upon failure
               -> m a 
               -- ^ Passwords don't match
               -> (UserId -> m a) 
               -- ^ Successful; take new user and move on
               -> m a
newUserHandler uidfs (pf1,pf2) saneUsername existsOrInvalid noMatch success = do
    uid <- mapM getParam uidfs >>= return . sequence
    pass1 <- getParam pf1
    pass2 <- getParam pf2
    fromMaybe existsOrInvalid $ liftM3 proc uid pass1 pass2
  where
    proc uid pass1 pass2
      | not (saneUsername uid) = existsOrInvalid
      | pass1 /= pass2 = noMatch
      | otherwise = checkAndAdd existsOrInvalid (success (UserId uid)) (UserId uid) pass1

