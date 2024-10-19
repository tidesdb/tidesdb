"""
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
"""

import ctypes
from ctypes import c_char_p, c_int, c_size_t, POINTER, c_void_p

# Load the shared library
libtidesdb = ctypes.CDLL('libtidesdb.so')

# Define the LSMT struct
class LSMT(ctypes.Structure):
    pass

# Define the Wal struct
class Wal(ctypes.Structure):
    pass

# Define the Transaction struct
class Transaction(ctypes.Structure):
    pass

# Define the function prototypes
libtidesdb.LSMT_New.argtypes = [c_char_p, c_int, c_int, c_int]
libtidesdb.LSMT_New.restype = POINTER(LSMT)

libtidesdb.LSMT_Delete.argtypes = [POINTER(LSMT)]
libtidesdb.LSMT_Delete.restype = None

libtidesdb.LSMT_Put.argtypes = [POINTER(LSMT), POINTER(ctypes.c_uint8), c_size_t, POINTER(ctypes.c_uint8), c_size_t]
libtidesdb.LSMT_Put.restype = c_int

libtidesdb.LSMT_Get.argtypes = [POINTER(LSMT), POINTER(ctypes.c_uint8), c_size_t, POINTER(c_size_t)]
libtidesdb.LSMT_Get.restype = POINTER(ctypes.c_uint8)

libtidesdb.LSMT_DeleteKey.argtypes = [POINTER(LSMT), POINTER(ctypes.c_uint8), c_size_t]
libtidesdb.LSMT_DeleteKey.restype = c_int

libtidesdb.LSMT_Close.argtypes = [POINTER(LSMT)]
libtidesdb.LSMT_Close.restype = None

libtidesdb.LSMT_BeginTransaction.argtypes = [POINTER(LSMT)]
libtidesdb.LSMT_BeginTransaction.restype = POINTER(Transaction)

libtidesdb.LSMT_CommitTransaction.argtypes = [POINTER(LSMT), POINTER(Transaction)]
libtidesdb.LSMT_CommitTransaction.restype = c_int

libtidesdb.LSMT_RollbackTransaction.argtypes = [POINTER(LSMT), POINTER(Transaction)]
libtidesdb.LSMT_RollbackTransaction.restype = None

libtidesdb.LSMT_AddDelete.argtypes = [POINTER(Transaction), POINTER(ctypes.c_uint8), c_size_t, POINTER(ctypes.c_uint8), c_size_t]
libtidesdb.LSMT_AddDelete.restype = None

libtidesdb.LSMT_AddPut.argtypes = [POINTER(Transaction), POINTER(ctypes.c_uint8), c_size_t, POINTER(ctypes.c_uint8), c_size_t]
libtidesdb.LSMT_AddPut.restype = None

libtidesdb.Wal_NewWithPath.argtypes = [c_char_p]
libtidesdb.Wal_NewWithPath.restype = POINTER(Wal)

libtidesdb.Wal_Recover.argtypes = [POINTER(Wal), POINTER(LSMT)]
libtidesdb.Wal_Recover.restype = c_int

libtidesdb.Wal_Close.argtypes = [POINTER(Wal)]
libtidesdb.Wal_Close.restype = None

libtidesdb.LSMT_NGet.argtypes = [POINTER(LSMT), POINTER(ctypes.c_uint8), c_size_t, POINTER(c_size_t)]
libtidesdb.LSMT_NGet.restype = POINTER(POINTER(ctypes.c_uint8))

libtidesdb.LSMT_LessThan.argtypes = [POINTER(LSMT), POINTER(ctypes.c_uint8), c_size_t, POINTER(c_size_t)]
libtidesdb.LSMT_LessThan.restype = POINTER(POINTER(ctypes.c_uint8))

libtidesdb.LSMT_GreaterThan.argtypes = [POINTER(LSMT), POINTER(ctypes.c_uint8), c_size_t, POINTER(c_size_t)]
libtidesdb.LSMT_GreaterThan.restype = POINTER(POINTER(ctypes.c_uint8))

libtidesdb.LSMT_Range.argtypes = [POINTER(LSMT), POINTER(ctypes.c_uint8), c_size_t, POINTER(ctypes.c_uint8), c_size_t, POINTER(c_size_t)]
libtidesdb.LSMT_Range.restype = POINTER(POINTER(ctypes.c_uint8))

libtidesdb.LSMT_NRange.argtypes = [POINTER(LSMT), POINTER(ctypes.c_uint8), c_size_t, POINTER(ctypes.c_uint8), c_size_t, POINTER(c_size_t)]
libtidesdb.LSMT_NRange.restype = POINTER(POINTER(ctypes.c_uint8))

libtidesdb.LSMT_LessThanEq.argtypes = [POINTER(LSMT), POINTER(ctypes.c_uint8), c_size_t, POINTER(c_size_t)]
libtidesdb.LSMT_LessThanEq.restype = POINTER(POINTER(ctypes.c_uint8))

libtidesdb.LSMT_GreaterThanEq.argtypes = [POINTER(LSMT), POINTER(ctypes.c_uint8), c_size_t, POINTER(c_size_t)]
libtidesdb.LSMT_GreaterThanEq.restype = POINTER(POINTER(ctypes.c_uint8))

# Define the LSMT class
class LSMTWrapper:
    def __init__(self, directory, memtable_flush_size, compaction_interval, max_compaction_threads):
        self.ptr = libtidesdb.LSMT_New(directory.encode('utf-8'), memtable_flush_size, compaction_interval, max_compaction_threads)

    def delete(self):
        libtidesdb.LSMT_Delete(self.ptr)

    def put(self, key, value):
        return libtidesdb.LSMT_Put(self.ptr, key, len(key), value, len(value))

    def get(self, key):
        value_len = c_size_t()
        value_ptr = libtidesdb.LSMT_Get(self.ptr, key, len(key), ctypes.byref(value_len))
        value = ctypes.string_at(value_ptr, value_len.value)
        libtidesdb.free(value_ptr)
        return value

    def delete_key(self, key):
        return libtidesdb.LSMT_DeleteKey(self.ptr, key, len(key))

    def close(self):
        libtidesdb.LSMT_Close(self.ptr)

    def begin_transaction(self):
        return TransactionWrapper(libtidesdb.LSMT_BeginTransaction(self.ptr))

    def commit_transaction(self, tx):
        return libtidesdb.LSMT_CommitTransaction(self.ptr, tx.ptr)

    def rollback_transaction(self, tx):
        libtidesdb.LSMT_RollbackTransaction(self.ptr, tx.ptr)

    def nget(self, key):
        result_len = c_size_t()
        c_array = libtidesdb.LSMT_NGet(self.ptr, key, len(key), ctypes.byref(result_len))
        return self.convert_to_python_list(c_array, result_len.value)

    def less_than(self, key):
        result_len = c_size_t()
        c_array = libtidesdb.LSMT_LessThan(self.ptr, key, len(key), ctypes.byref(result_len))
        return self.convert_to_python_list(c_array, result_len.value)

    def greater_than(self, key):
        result_len = c_size_t()
        c_array = libtidesdb.LSMT_GreaterThan(self.ptr, key, len(key), ctypes.byref(result_len))
        return self.convert_to_python_list(c_array, result_len.value)

    def range(self, start, end):
        result_len = c_size_t()
        c_array = libtidesdb.LSMT_Range(self.ptr, start, len(start), end, len(end), ctypes.byref(result_len))
        return self.convert_to_python_list(c_array, result_len.value)

    def nrange(self, start, end):
        result_len = c_size_t()
        c_array = libtidesdb.LSMT_NRange(self.ptr, start, len(start), end, len(end), ctypes.byref(result_len))
        return self.convert_to_python_list(c_array, result_len.value)

    def less_than_eq(self, key):
        result_len = c_size_t()
        c_array = libtidesdb.LSMT_LessThanEq(self.ptr, key, len(key), ctypes.byref(result_len))
        return self.convert_to_python_list(c_array, result_len.value)

    def greater_than_eq(self, key):
        result_len = c_size_t()
        c_array = libtidesdb.LSMT_GreaterThanEq(self.ptr, key, len(key), ctypes.byref(result_len))
        return self.convert_to_python_list(c_array, result_len.value)

    def convert_to_python_list(self, c_array, length):
        result = []
        for i in range(length):
            elem_ptr = c_array[i]
            elem_len = ctypes.c_int.from_address(elem_ptr).value
            result.append(ctypes.string_at(elem_ptr, elem_len))
        libtidesdb.free(c_array)
        return result

# Define the Transaction class
class TransactionWrapper:
    def __init__(self, ptr):
        self.ptr = ptr

    def add_delete(self, key, value):
        libtidesdb.LSMT_AddDelete(self.ptr, key, len(key), value, len(value))

    def add_put(self, key, value):
        libtidesdb.LSMT_AddPut(self.ptr, key, len(key), value, len(value))

# Define the Wal class
class WalWrapper:
    def __init__(self, path):
        self.ptr = libtidesdb.Wal_NewWithPath(path.encode('utf-8'))

    def recover(self, lsmt):
        return libtidesdb.Wal_Recover(self.ptr, lsmt.ptr)

    def close(self):
        libtidesdb.Wal_Close(self.ptr)