{-
* Copyright 2024 TidesDB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
-}

{-# LANGUAGE ForeignFunctionInterface #-}

module TidesDB where

import Foreign
import Foreign.C
import Foreign.Marshal.Array

data LSMT = LSMT (Ptr LSMT)
data Wal = Wal (Ptr Wal)
data Transaction = Transaction (Ptr Transaction)

foreign import ccall "libtidesdb_c.h LSMT_New"
  c_LSMT_New :: CString -> CInt -> CInt -> CInt -> IO (Ptr LSMT)

foreign import ccall "libtidesdb_c.h LSMT_Delete"
  c_LSMT_Delete :: Ptr LSMT -> IO ()

foreign import ccall "libtidesdb_c.h LSMT_Put"
  c_LSMT_Put :: Ptr LSMT -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO CInt

foreign import ccall "libtidesdb_c.h LSMT_Get"
  c_LSMT_Get :: Ptr LSMT -> Ptr CUChar -> CSize -> Ptr CSize -> IO (Ptr CUChar)

foreign import ccall "libtidesdb_c.h LSMT_DeleteKey"
  c_LSMT_DeleteKey :: Ptr LSMT -> Ptr CUChar -> CSize -> IO CInt

foreign import ccall "libtidesdb_c.h LSMT_Close"
  c_LSMT_Close :: Ptr LSMT -> IO ()

foreign import ccall "libtidesdb_c.h LSMT_BeginTransaction"
  c_LSMT_BeginTransaction :: Ptr LSMT -> IO (Ptr Transaction)

foreign import ccall "libtidesdb_c.h LSMT_CommitTransaction"
  c_LSMT_CommitTransaction :: Ptr LSMT -> Ptr Transaction -> IO CInt

foreign import ccall "libtidesdb_c.h LSMT_RollbackTransaction"
  c_LSMT_RollbackTransaction :: Ptr LSMT -> Ptr Transaction -> IO ()

foreign import ccall "libtidesdb_c.h LSMT_AddDelete"
  c_LSMT_AddDelete :: Ptr Transaction -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO ()

foreign import ccall "libtidesdb_c.h LSMT_AddPut"
  c_LSMT_AddPut :: Ptr Transaction -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO ()

foreign import ccall "libtidesdb_c.h Wal_NewWithPath"
  c_Wal_NewWithPath :: CString -> IO (Ptr Wal)

foreign import ccall "libtidesdb_c.h Wal_Recover"
  c_Wal_Recover :: Ptr Wal -> Ptr LSMT -> IO CInt

foreign import ccall "libtidesdb_c.h Wal_Close"
  c_Wal_Close :: Ptr Wal -> IO ()

foreign import ccall "libtidesdb_c.h LSMT_LessThan"
  c_LSMT_LessThan :: Ptr LSMT -> Ptr CUChar -> CSize -> Ptr CSize -> IO (Ptr (Ptr CUChar))

foreign import ccall "libtidesdb_c.h LSMT_GreaterThan"
  c_LSMT_GreaterThan :: Ptr LSMT -> Ptr CUChar -> CSize -> Ptr CSize -> IO (Ptr (Ptr CUChar))

foreign import ccall "libtidesdb_c.h LSMT_Range"
  c_LSMT_Range :: Ptr LSMT -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CSize -> IO (Ptr (Ptr CUChar))

foreign import ccall "libtidesdb_c.h LSMT_NRange"
  c_LSMT_NRange :: Ptr LSMT -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CSize -> IO (Ptr (Ptr CUChar))

foreign import ccall "libtidesdb_c.h LSMT_LessThanEq"
  c_LSMT_LessThanEq :: Ptr LSMT -> Ptr CUChar -> CSize -> Ptr CSize -> IO (Ptr (Ptr CUChar))

foreign import ccall "libtidesdb_c.h LSMT_GreaterThanEq"
  c_LSMT_GreaterThanEq :: Ptr LSMT -> Ptr CUChar -> CSize -> Ptr CSize -> IO (Ptr (Ptr CUChar))

newLSMT :: String -> Int -> Int -> Int -> IO LSMT
newLSMT directory memtableFlushSize compactionInterval maxCompactionThreads = do
  cDirectory <- newCString directory
  ptr <- c_LSMT_New cDirectory (fromIntegral memtableFlushSize) (fromIntegral compactionInterval) (fromIntegral maxCompactionThreads)
  free cDirectory
  return $ LSMT ptr

deleteLSMT :: LSMT -> IO ()
deleteLSMT (LSMT ptr) = c_LSMT_Delete ptr

putLSMT :: LSMT -> [CUChar] -> [CUChar] -> IO Int
putLSMT (LSMT ptr) key value = withArray key $ \cKey -> withArray value $ \cValue -> do
  result <- c_LSMT_Put ptr cKey (fromIntegral $ length key) cValue (fromIntegral $ length value)
  return $ fromIntegral result

getLSMT :: LSMT -> [CUChar] -> IO [CUChar]
getLSMT (LSMT ptr) key = withArray key $ \cKey -> alloca $ \valueLenPtr -> do
  valuePtr <- c_LSMT_Get ptr cKey (fromIntegral $ length key) valueLenPtr
  valueLen <- peek valueLenPtr
  value <- peekArray (fromIntegral valueLen) valuePtr
  free valuePtr
  return value

deleteKeyLSMT :: LSMT -> [CUChar] -> IO Int
deleteKeyLSMT (LSMT ptr) key = withArray key $ \cKey -> do
  result <- c_LSMT_DeleteKey ptr cKey (fromIntegral $ length key)
  return $ fromIntegral result

closeLSMT :: LSMT -> IO ()
closeLSMT (LSMT ptr) = c_LSMT_Close ptr

beginTransaction :: LSMT -> IO Transaction
beginTransaction (LSMT ptr) = do
  txPtr <- c_LSMT_BeginTransaction ptr
  return $ Transaction txPtr

commitTransaction :: LSMT -> Transaction -> IO Int
commitTransaction (LSMT ptr) (Transaction txPtr) = do
  result <- c_LSMT_CommitTransaction ptr txPtr
  return $ fromIntegral result

rollbackTransaction :: LSMT -> Transaction -> IO ()
rollbackTransaction (LSMT ptr) (Transaction txPtr) = c_LSMT_RollbackTransaction ptr txPtr

addDelete :: Transaction -> [CUChar] -> [CUChar] -> IO ()
addDelete (Transaction txPtr) key value = withArray key $ \cKey -> withArray value $ \cValue -> do
  c_LSMT_AddDelete txPtr cKey (fromIntegral $ length key) cValue (fromIntegral $ length value)

addPut :: Transaction -> [CUChar] -> [CUChar] -> IO ()
addPut (Transaction txPtr) key value = withArray key $ \cKey -> withArray value $ \cValue -> do
  c_LSMT_AddPut txPtr cKey (fromIntegral $ length key) cValue (fromIntegral $ length value)

newWalWithPath :: String -> IO Wal
newWalWithPath path = do
  cPath <- newCString path
  ptr <- c_Wal_NewWithPath cPath
  free cPath
  return $ Wal ptr

recoverWal :: Wal -> LSMT -> IO Int
recoverWal (Wal walPtr) (LSMT lsmtPtr) = do
  result <- c_Wal_Recover walPtr lsmtPtr
  return $ fromIntegral result

closeWal :: Wal -> IO ()
closeWal (Wal ptr) = c_Wal_Close ptr

convertToGoSlice :: Ptr (Ptr CUChar) -> CSize -> IO [[CUChar]]
convertToGoSlice cArray length = do
  result <- mapM (\i -> peekElemOff cArray (fromIntegral i) >>= \elemPtr -> peekArray0 0 elemPtr) [0..(length-1)]
  return result

lessThanLSMT :: LSMT -> [CUChar] -> IO [[CUChar]]
lessThanLSMT (LSMT ptr) key = withArray key $ \cKey -> alloca $ \resultLenPtr -> do
  cArray <- c_LSMT_LessThan ptr cKey (fromIntegral $ length key) resultLenPtr
  resultLen <- peek resultLenPtr
  result <- convertToGoSlice cArray resultLen
  free cArray
  return result

greaterThanLSMT :: LSMT -> [CUChar] -> IO [[CUChar]]
greaterThanLSMT (LSMT ptr) key = withArray key $ \cKey -> alloca $ \resultLenPtr -> do
  cArray <- c_LSMT_GreaterThan ptr cKey (fromIntegral $ length key) resultLenPtr
  resultLen <- peek resultLenPtr
  result <- convertToGoSlice cArray resultLen
  free cArray
  return result

rangeLSMT :: LSMT -> [CUChar] -> [CUChar] -> IO [[CUChar]]
rangeLSMT (LSMT ptr) start end = withArray start $ \cStart -> withArray end $ \cEnd -> alloca $ \resultLenPtr -> do
  cArray <- c_LSMT_Range ptr cStart (fromIntegral $ length start) cEnd (fromIntegral $ length end) resultLenPtr
  resultLen <- peek resultLenPtr
  result <- convertToGoSlice cArray resultLen
  free cArray
  return result

nRangeLSMT :: LSMT -> [CUChar] -> [CUChar] -> IO [[CUChar]]
nRangeLSMT (LSMT ptr) start end = withArray start $ \cStart -> withArray end $ \cEnd -> alloca $ \resultLenPtr -> do
  cArray <- c_LSMT_NRange ptr cStart (fromIntegral $ length start) cEnd (fromIntegral $ length end) resultLenPtr
  resultLen <- peek resultLenPtr
  result <- convertToGoSlice cArray resultLen
  free cArray
  return result

lessThanEqLSMT :: LSMT -> [CUChar] -> IO [[CUChar]]
lessThanEqLSMT (LSMT ptr) key = withArray key $ \cKey -> alloca $ \resultLenPtr -> do
  cArray <- c_LSMT_LessThanEq ptr cKey (fromIntegral $ length key) resultLenPtr
  resultLen <- peek resultLenPtr
  result <- convertToGoSlice cArray resultLen
  free cArray
  return result

greaterThanEqLSMT :: LSMT -> [CUChar] -> IO [[CUChar]]
greaterThanEqLSMT (LSMT ptr) key = withArray key $ \cKey -> alloca $ \resultLenPtr -> do
  cArray <- c_LSMT_GreaterThanEq ptr cKey (fromIntegral $ length key) resultLenPtr
  resultLen <- peek resultLenPtr
  result <- convertToGoSlice cArray resultLen
  free cArray
  return result