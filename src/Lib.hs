{-# LANGUAGE OverloadedStrings #-}
module Lib
    ( fileSignatures
    , genInstructions
    , recreate
    ) where

import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as BL
import Data.Word (Word8)
import qualified Crypto.Hash.SHA1 as SHA1

type Signature = (BS.ByteString, Int)

fileSignatures :: BL.ByteString -> Integer -> [Signature]
fileSignatures bs blockSize = zip (map blockSig (splitBS bs blockSize)) [0..]

splitBS :: BL.ByteString -> Integer -> [BL.ByteString]
splitBS bs blockSize | fromIntegral (BL.length bs) < blockSize = [bs]
splitBS bs blockSize | otherwise =
                         (BL.take (fromIntegral blockSize) bs) :
                         splitBS (BL.drop (fromIntegral blockSize) bs) blockSize

blockSig :: BL.ByteString -> BS.ByteString
blockSig = SHA1.hash . BL.toStrict

data Instruction = RChar Word8
                 | RBlk  Int
                 deriving Show

genInstructions :: [Signature] -> Integer -> BL.ByteString -> [Instruction]
genInstructions f0sigs blockSize fnew =
  if (fnew == BL.empty)
  then []
  else
    let (blk, blks) = BL.splitAt (fromIntegral blockSize) fnew
        sig         = blockSig blk
    in
      case (lookup sig f0sigs) of
        Just (idx) -> RBlk (fromIntegral idx) : genInstructions f0sigs blockSize blks
        Nothing    -> RChar (BL.head blk) :
          genInstructions f0sigs blockSize (BL.tail (blk `mappend` blks))

recreate :: BL.ByteString -> Integer -> [Instruction] -> BL.ByteString
recreate f0 blockSize ins =
  let f0blocks = splitBS f0 blockSize
  in
    go f0blocks ins
  where go f0blocks [] = mempty
        go f0blocks (inst:insts) =
          case inst of
            RBlk i  -> (f0blocks !! i) `mappend` go f0blocks insts
            RChar w -> (BL.singleton w) `mappend` go f0blocks insts

