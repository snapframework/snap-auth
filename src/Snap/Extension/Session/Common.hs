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
randomToken :: Int -> IO ByteString
randomToken n = do
    chars <- sequence $ take n $ repeat $
        randomRIO (0::Int,15) >>= return . flip showHex ""
    return $ B.pack $ concat chars



