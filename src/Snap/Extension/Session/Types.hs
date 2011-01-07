module Snap.Extension.Session.Types where

import Data.ByteString (ByteString)
import Data.Generics
import qualified Data.Map as Map
import Data.Map (Map)
import Data.Serialize

------------------------------------------------------------------------------
-- | Internal representation of a 'User'. By convention, we demand that the
-- application is able to directly fetch a 'User' using this identifier.
--
-- Think of this type as a secure, authenticated user. You should normally
-- never see this type unless a user has been authenticated.
newtype UserId = UserId { unUid :: ByteString }
    deriving (Read,Show,Ord,Eq,Typeable,Data)


------------------------------------------------------------------------------
-- | Base session on the fast and capable Map library.
--
-- This is the user-exposed universal and simple session type
type Session = Map ByteString ByteString


------------------------------------------------------------------------------
-- | The internal session datatype
data SessionShell = SessionShell
  { sesSession :: Session             -- ^ User exposed bit
  , sesUserId :: Maybe UserId         -- ^ Opaque user id
  , sesCSRFToken :: Maybe ByteString  -- ^ For CSRF protection
  } deriving (Eq, Show)


------------------------------------------------------------------------------
-- | A default 'SessionShell'
defSessionShell :: SessionShell
defSessionShell = SessionShell
  { sesSession = Map.empty
  , sesUserId = Nothing
  , sesCSRFToken = Nothing
  }


------------------------------------------------------------------------------
-- | Serialize 'SessionShell'
instance Serialize UserId where
    put (UserId u) = put u
    get            = UserId `fmap` get



------------------------------------------------------------------------------
-- | Serialize 'SessionShell'
instance Serialize SessionShell where
    put (SessionShell a b c) = put (a,b,c)
    get                      = (\(a,b,c) -> SessionShell a b c) `fmap` get
