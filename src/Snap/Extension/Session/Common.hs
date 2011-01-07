{-|

  This module contains functionality common among multiple back-ends.

-}

module Snap.Extension.Session.Common where


import           Numeric
import           Random
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B


------------------------------------------------------------------------------
-- | Generates a random salt.
randomToken :: IO ByteString
randomToken = do
    chars <- sequence $ take 15 $ repeat $
        randomRIO (0::Int,15) >>= return . flip showHex ""
    return $ B.pack $ concat chars



