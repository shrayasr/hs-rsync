{-# LANGUAGE OverloadedStrings #-}
module Lib
    ( fileSignatures
    , genInstructions
    , recreate
    ) where

import Control.Monad.State
import Data.Bits (shiftL, shiftR, (.&.))
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as BL
import Data.Digest.Adler32 (adler32)
import qualified Data.Map as M
import Data.Word (Word8, Word32)
import qualified Crypto.Hash.MD4 as MD4

type Md4digest       = BS.ByteString
type Adler32checksum = Word32

type Checksum        = (Word32, Int, Int)

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
  evalState (go 0 fnew) sig0
  where
    sig0 = weakSig $ BL.take (fromIntegral blockSize) fnew
    go :: Integer -> BL.ByteString -> State Adler32checksum [Instruction]
    go startIdx fnew | fnew == BL.empty = return []
                     | otherwise = do
                         let (blk, blks) = BL.splitAt (fromIntegral blockSize) fnew
                             endIdx      = startIdx + fromIntegral (BL.length blk) - 1
                         adlerSum <- get
                         let matches = M.lookup adlerSum f0AdlerTable >>
                               M.lookup (blockSig blk) f0MD4Table
                         case matches of
                           Just idxs -> do
                             -- modify (`adler32Update` blk)
                             put $ rollingChecksum (fromIntegral startIdx) (fromIntegral endIdx) fnew
                             is <- go (endIdx + 1) blks
                             return $ RBlk (head idxs) : is
                           Nothing -> do
                             let c  = BL.head blk
                                 c' = BL.head blk -- FIX (should have been blks)
                             -- modify (`adler32Update`  BL.singleton c)
                             put $ rollingChecksumUpdate adlerSum c c' startIdx endIdx
                             is <- go (startIdx + 1) (BL.tail (blk `mappend` blks))
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
rollingChecksum strtIdx endIdx bs = a `mod` m + ((fromIntegral b) `mod` m) `shiftL` mb
  where a    = BL.foldl (\acc x -> acc + (fromIntegral x)) 0 bs'
        b    = BL.foldl (\acc x -> acc + x) 0 (BL.pack wbs')
        bs'  = BL.take (fromIntegral (endIdx - strtIdx + 1)) bs
        m    = 2^16
        mb   = 16
        wbs' = BL.zipWith (*) (BL.pack (reverse (map fromIntegral [1..(endIdx - strtIdx + 1)]))) bs'

checksum :: BL.ByteString -> Int -> Int -> Checksum
checksum bs strtIdx endIdx = (csval, strtIdx, endIdx)
  where csval   = a `mod` m + ((fromIntegral b) `mod` m) `shiftL` size
        buffer  = map fromIntegral $ take (endIdx - strtIdx) $ drop strtIdx $ BL.unpack bs
        indices = map fromIntegral [1..(endIdx - strtIdx + 1)]
        a       = sum buffer
        b       = sum $ zipWith (*) (reverse indices) buffer
        m       = 2^size
        size    = 16

-- given the checksum a(k, l) and b(k, l), find checksum a(k+1, l+1), b(k+1, l+1)
checksumUpdate :: Checksum -> BL.ByteString -> Checksum
checksumUpdate curCheckSum bs = (csval, oldStrtIdx + 1, oldEndIdx + 1)
  where (oldChecksum, oldStrtIdx, oldEndIdx) = curCheckSum
        csval   = a `mod` m + ((fromIntegral b) `mod` m) `shiftL` size
        m       = 2^size
        size    = 16
        bold    = oldChecksum `shiftR` size
        aold    = oldChecksum .&. (m - 1)
        xk      = head $ drop oldStrtIdx $ BL.unpack bs
        xlPlus1 = head $ drop (oldEndIdx + 1) $BL.unpack bs
        a       = aold - fromIntegral xk + fromIntegral xlPlus1
        b       = a + bold - (fromIntegral (oldEndIdx - oldStrtIdx + 1))

-- given the checksum of bytes from index: startIdx to endIdx, find
-- the checksum for the block from (startIdx + 1 .. endIdx + 1)
rollingChecksumUpdate :: Word32 -> Word8 -> Word8 -> Integer -> Integer -> Word32
rollingChecksumUpdate oldChecksum old new strtIdx endIdx =
  let b_Old = (oldChecksum `shiftR` 16) .&. 0xff
      a_Old = (oldChecksum .&. 0xff)
      a_New = (a_Old - (fromIntegral old) + (fromIntegral new)) `mod` m
      b_New = (b_Old - ((fromIntegral endIdx) - (fromIntegral strtIdx) + 1) * (fromIntegral old) + a_New) `mod` m
      m     = 2^16
  in
    a_New `mod` m + (b_New `mod` m) * m
