{-|

  Convenience Splices to be used in your views. They go hand-in hand with
  handlers defined in this package to help automate some common patterns.

-}

module Snap.Auth.Splices 
  ( metaCSRFTag, hiddenCSRFTag ) where

import Control.Monad.Trans.Class (lift)
import Data.Text.Encoding as T

import Snap.Auth
import Snap.Extension.Session.CookieSession (MonadSession(..), sessionCSRFToken)

import qualified Text.XmlHtml as X
import           Text.Templating.Heist


metaCSRFTag
  :: (MonadAuth m)
  => Splice m
metaCSRFTag = do
  embeddedToken <- lift sessionCSRFToken
  param <- lift authAuthenticityTokenParam
  let metaToken = X.Element "meta"
                    [ ("name", "csrf-token")
                    , ("content", T.decodeUtf8 embeddedToken) ] []
  let metaParam = X.Element "meta" 
                    [ ("name", "csrf-param") 
                    , ("content", T.decodeUtf8 param) ] []
  return $ [metaParam, metaToken]


hiddenCSRFTag
  :: (MonadAuth m)
  => Splice m
hiddenCSRFTag = do
  embeddedToken <- lift sessionCSRFToken
  param <- lift authAuthenticityTokenParam
  return . return $ X.Element "input" 
    [ ("type", "hidden")
    , ("name", T.decodeUtf8 param) 
    , ("value", T.decodeUtf8 embeddedToken) 
    ] []
