{-# LANGUAGE OverloadedStrings #-}
module Lib
    ( fileSignatures
    , genInstructions
    , recreate
    ) where

import Control.Monad.State
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as BL
import Data.Digest.Adler32 (adler32, adler32Update)
import qualified Data.Map as M
import Data.Word (Word8, Word32)
import qualified Crypto.Hash.MD4 as MD4

type Md4digest       = BS.ByteString
type Adler32checksum = Word32

type Signature     = (Md4digest, Adler32checksum, Int)

fileSignatures :: BL.ByteString -> Integer -> [Signature]
fileSignatures bs blockSize = zip3 strongsigs weaksigs [0..]
  where strongsigs = map blockSig (splitBS bs blockSize)
        weaksigs   = map adler32 (splitBS bs blockSize)

splitBS :: BL.ByteString -> Integer -> [BL.ByteString]
splitBS bs blockSize | fromIntegral (BL.length bs) < blockSize = [bs]
splitBS bs blockSize = BL.take (fromIntegral blockSize) bs :
  splitBS (BL.drop (fromIntegral blockSize) bs) blockSize

-- compute md4 digest (128 bits)
blockSig :: BL.ByteString -> BS.ByteString
blockSig = MD4.hash . BL.toStrict

weakSig :: BL.ByteString -> Adler32checksum
weakSig = adler32

data Instruction = RChar Word8
                 | RBlk  Int
                 deriving Show

genInstructions :: [Signature] -> Integer -> BL.ByteString -> [Instruction]
genInstructions f0sigs blockSize fnew =
  evalState (go fnew) sig0
  where
    sig0 = weakSig $ BL.take (fromIntegral blockSize) fnew
    go :: BL.ByteString -> State Adler32checksum [Instruction]
    go fnew | fnew == BL.empty = return []
            | otherwise = do
                let (blk, blks) = BL.splitAt (fromIntegral blockSize) fnew
                adlerSum <- get
                let matches = M.lookup adlerSum f0AdlerTable >>
                      M.lookup (blockSig blk) f0MD4Table
                case matches of
                  Just idxs -> do
                    modify (`adler32Update` blk)
                    is <- go blks
                    return $ RBlk (head idxs) : is
                  Nothing -> do
                    let c = BL.head blk
                    modify (`adler32Update`  BL.singleton c)
                    is <- go (BL.tail (blk `mappend` blks))
                    return $ RChar c : is
    f0AdlerTable = toAdlerMap f0sigs
    f0MD4Table   = toMD4Map f0sigs

toAdlerMap :: [Signature] -> M.Map Adler32checksum [Int]
toAdlerMap = foldr f M.empty
  where f sig m = let (_, aSig, idx) = sig in M.insertWith (++) aSig [idx] m

toMD4Map :: [Signature] -> M.Map Md4digest [Int]
toMD4Map = foldr f M.empty
  where f sig m = let (mSig, _, idx) = sig in M.insertWith (++) mSig [idx] m

recreate :: BL.ByteString -> Integer -> [Instruction] -> BL.ByteString
recreate f0 blockSize ins =
  let f0blocks = splitBS f0 blockSize
  in
    go f0blocks ins
  where go f0blocks [] = mempty
        go f0blocks (inst:insts) =
          case inst of
            RBlk i  -> (f0blocks !! i) `mappend` go f0blocks insts
            RChar w -> BL.singleton w `mappend` go f0blocks insts

rollingChecksum :: Int -> Int -> BL.ByteString -> Word32
rollingChecksum strtIdx lenBS bs = a `mod` m + ((fromIntegral b) `mod` m) * m
  where a    = BL.foldl (\acc x -> acc + (fromIntegral x)) 0 bs'
        b    = BL.foldl (\acc x -> acc + x) 0 (BL.pack wbs')
        bs'  = BL.take (fromIntegral lenBS) $ BL.drop (fromIntegral strtIdx) bs
        m    = 2^16
        wbs' = BL.zipWith (*) (BL.pack (reverse (map fromIntegral [1..(lenBS - strtIdx + 1)]))) bs'
