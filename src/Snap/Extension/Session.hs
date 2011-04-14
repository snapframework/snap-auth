{-|
 
-}

module Snap.Extension.Session
  ( 
    SessionShell(..)
  , defSessionShell
  , Session
  , MonadSession(..)
  ) where

import Control.Monad
import Control.Monad.Trans
import Data.ByteString (ByteString)
import qualified Data.Map as Map

import Snap.Types
import Snap.Extension.Session.Types
import Snap.Extension.Session.Common (randomToken)


------------------------------------------------------------------------------
-- | The 'MonadCookieSession' class. 
class MonadSnap m => MonadSession m where

  ----------------------------------------------------------------------------
  getSessionShell :: m SessionShell


  ----------------------------------------------------------------------------
  setSessionShell :: SessionShell -> m ()


  ----------------------------------------------------------------------------
  -- | Return a secure encryption key specific to this application.
  secureSiteKey :: m ByteString


  ----------------------------------------------------------------------------
  updateSessionShell :: (SessionShell -> SessionShell) -> m ()
  updateSessionShell f = do
    ssh <- getSessionShell
    setSessionShell $ f ssh


  ----------------------------------------------------------------------------
  getSessionUserId :: m (Maybe UserId)
  getSessionUserId = fmap sesUserId getSessionShell


  ----------------------------------------------------------------------------
  setSessionUserId :: Maybe UserId -> m ()
  setSessionUserId uid = updateSessionShell f
    where f s = s { sesUserId = uid }


  ----------------------------------------------------------------------------
  sessionCSRFToken :: m ByteString
  sessionCSRFToken = do
    csrf <- liftM sesCSRFToken getSessionShell
    case csrf of
      Nothing -> do
        t <- liftIO $ randomToken 35
        updateSessionShell (\s -> s { sesCSRFToken = Just t })
        return t
      Just t -> return t


  ----------------------------------------------------------------------------
  -- | Function to get the session in your app's monad.
  --
  -- This will return a @Map ByteString ByteString@ data type, which you can
  -- then use freely to read/write values. 
  getSession :: m Session
  getSession = fmap sesSession getSessionShell


  ----------------------------------------------------------------------------
  -- | Set the session in your app's monad.
  setSession :: Session -> m ()
  setSession s = updateSessionShell f
    where f ssh = ssh { sesSession = s }


  ------------------------------------------------------------------------------
  -- | Get a value associated with given key from the 'Session'.
  getFromSession :: ByteString -> m (Maybe ByteString)
  getFromSession k = Map.lookup k `liftM` getSession


  ------------------------------------------------------------------------------
  -- | Remove the given key from 'Session'
  deleteFromSession :: ByteString -> m ()
  deleteFromSession k = Map.delete k `liftM` getSession >>= setSession


  ------------------------------------------------------------------------------
  -- | Set a value in the 'Session'.
  setInSession :: ByteString 
               -> ByteString 
               -> m ()
  setInSession k v = Map.insert k v `liftM` getSession >>= setSession


  ----------------------------------------------------------------------------
  -- | Clear the active session. Uses 'setSession'.
  clearSession :: m ()
  clearSession = setSession Map.empty


  ----------------------------------------------------------------------------
  -- | Touch session to reset the timeout. You can chain a handler to call this
  -- in every authenticated route to keep prolonging the session with each
  -- request.
  touchSession :: m ()
  touchSession = getSession >>= setSession



