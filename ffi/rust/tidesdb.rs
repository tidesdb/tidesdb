/*
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
 */



use std::ffi::{CString, CStr};
use std::ptr;
use libc::{c_char, c_int, c_size_t, c_void, uint8_t};

#[repr(C)]
struct LSMT {
    ptr: *mut c_void,
}

#[repr(C)]
struct Wal {
    ptr: *mut c_void,
}

#[repr(C)]
struct Transaction {
    ptr: *mut c_void,
}

extern "C" {
    fn LSMT_New(directory: *const c_char, memtable_flush_size: c_int, compaction_interval: c_int, max_compaction_threads: c_int) -> *mut c_void;
    fn LSMT_Delete(ptr: *mut c_void);
    fn LSMT_Put(ptr: *mut c_void, key: *const uint8_t, key_len: c_size_t, value: *const uint8_t, value_len: c_size_t) -> c_int;
    fn LSMT_Get(ptr: *mut c_void, key: *const uint8_t, key_len: c_size_t, value_len: *mut c_size_t) -> *mut uint8_t;
    fn LSMT_DeleteKey(ptr: *mut c_void, key: *const uint8_t, key_len: c_size_t) -> c_int;
    fn LSMT_Close(ptr: *mut c_void);
    fn LSMT_BeginTransaction(ptr: *mut c_void) -> *mut c_void;
    fn LSMT_CommitTransaction(ptr: *mut c_void, tx_ptr: *mut c_void) -> c_int;
    fn LSMT_RollbackTransaction(ptr: *mut c_void, tx_ptr: *mut c_void);
    fn LSMT_AddDelete(tx_ptr: *mut c_void, key: *const uint8_t, key_len: c_size_t, value: *const uint8_t, value_len: c_size_t);
    fn LSMT_AddPut(tx_ptr: *mut c_void, key: *const uint8_t, key_len: c_size_t, value: *const uint8_t, value_len: c_size_t);
    fn Wal_NewWithPath(path: *const c_char) -> *mut c_void;
    fn Wal_Recover(wal_ptr: *mut c_void, lsmt_ptr: *mut c_void) -> c_int;
    fn Wal_Close(wal_ptr: *mut c_void);
    fn LSMT_NGet(ptr: *mut c_void, key: *const uint8_t, key_len: c_size_t, result_len: *mut c_size_t) -> *mut *mut uint8_t;
    fn LSMT_LessThan(ptr: *mut c_void, key: *const uint8_t, key_len: c_size_t, result_len: *mut c_size_t) -> *mut *mut uint8_t;
    fn LSMT_GreaterThan(ptr: *mut c_void, key: *const uint8_t, key_len: c_size_t, result_len: *mut c_size_t) -> *mut *mut uint8_t;
    fn LSMT_Range(ptr: *mut c_void, start: *const uint8_t, start_len: c_size_t, end: *const uint8_t, end_len: c_size_t, result_len: *mut c_size_t) -> *mut *mut uint8_t;
    fn LSMT_NRange(ptr: *mut c_void, start: *const uint8_t, start_len: c_size_t, end: *const uint8_t, end_len: c_size_t, result_len: *mut c_size_t) -> *mut *mut uint8_t;
    fn LSMT_LessThanEq(ptr: *mut c_void, key: *const uint8_t, key_len: c_size_t, result_len: *mut c_size_t) -> *mut *mut uint8_t;
    fn LSMT_GreaterThanEq(ptr: *mut c_void, key: *const uint8_t, key_len: c_size_t, result_len: *mut c_size_t) -> *mut *mut uint8_t;
}

impl LSMT {
    pub fn new(directory: &str, memtable_flush_size: i32, compaction_interval: i32, max_compaction_threads: i32) -> Self {
        let c_directory = CString::new(directory).unwrap();
        let ptr = unsafe { LSMT_New(c_directory.as_ptr(), memtable_flush_size, compaction_interval, max_compaction_threads) };
        LSMT { ptr }
    }

    pub fn delete(&self) {
        unsafe { LSMT_Delete(self.ptr) }
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> i32 {
        unsafe { LSMT_Put(self.ptr, key.as_ptr(), key.len() as c_size_t, value.as_ptr(), value.len() as c_size_t) as i32 }
    }

    pub fn get(&self, key: &[u8]) -> Vec<u8> {
        let mut value_len: c_size_t = 0;
        let value = unsafe { LSMT_Get(self.ptr, key.as_ptr(), key.len() as c_size_t, &mut value_len) };
        let result = unsafe { std::slice::from_raw_parts(value, value_len as usize).to_vec() };
        unsafe { libc::free(value as *mut c_void) };
        result
    }

    pub fn delete_key(&self, key: &[u8]) -> i32 {
        unsafe { LSMT_DeleteKey(self.ptr, key.as_ptr(), key.len() as c_size_t) as i32 }
    }

    pub fn close(&self) {
        unsafe { LSMT_Close(self.ptr) }
    }

    pub fn begin_transaction(&self) -> Transaction {
        let ptr = unsafe { LSMT_BeginTransaction(self.ptr) };
        Transaction { ptr }
    }

    pub fn commit_transaction(&self, tx: &Transaction) -> i32 {
        unsafe { LSMT_CommitTransaction(self.ptr, tx.ptr) as i32 }
    }

    pub fn rollback_transaction(&self, tx: &Transaction) {
        unsafe { LSMT_RollbackTransaction(self.ptr, tx.ptr) }
    }

    pub fn nget(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut result_len: c_size_t = 0;
        let c_array = unsafe { LSMT_NGet(self.ptr, key.as_ptr(), key.len() as c_size_t, &mut result_len) };
        convert_to_rust_vec(c_array, result_len)
    }

    pub fn less_than(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut result_len: c_size_t = 0;
        let c_array = unsafe { LSMT_LessThan(self.ptr, key.as_ptr(), key.len() as c_size_t, &mut result_len) };
        convert_to_rust_vec(c_array, result_len)
    }

    pub fn greater_than(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut result_len: c_size_t = 0;
        let c_array = unsafe { LSMT_GreaterThan(self.ptr, key.as_ptr(), key.len() as c_size_t, &mut result_len) };
        convert_to_rust_vec(c_array, result_len)
    }

    pub fn range(&self, start: &[u8], end: &[u8]) -> Vec<Vec<u8>> {
        let mut result_len: c_size_t = 0;
        let c_array = unsafe { LSMT_Range(self.ptr, start.as_ptr(), start.len() as c_size_t, end.as_ptr(), end.len() as c_size_t, &mut result_len) };
        convert_to_rust_vec(c_array, result_len)
    }

    pub fn nrange(&self, start: &[u8], end: &[u8]) -> Vec<Vec<u8>> {
        let mut result_len: c_size_t = 0;
        let c_array = unsafe { LSMT_NRange(self.ptr, start.as_ptr(), start.len() as c_size_t, end.as_ptr(), end.len() as c_size_t, &mut result_len) };
        convert_to_rust_vec(c_array, result_len)
    }

    pub fn less_than_eq(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut result_len: c_size_t = 0;
        let c_array = unsafe { LSMT_LessThanEq(self.ptr, key.as_ptr(), key.len() as c_size_t, &mut result_len) };
        convert_to_rust_vec(c_array, result_len)
    }

    pub fn greater_than_eq(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut result_len: c_size_t = 0;
        let c_array = unsafe { LSMT_GreaterThanEq(self.ptr, key.as_ptr(), key.len() as c_size_t, &mut result_len) };
        convert_to_rust_vec(c_array, result_len)
    }
}

impl Transaction {
    pub fn add_delete(&self, key: &[u8], value: &[u8]) {
        unsafe { LSMT_AddDelete(self.ptr, key.as_ptr(), key.len() as c_size_t, value.as_ptr(), value.len() as c_size_t) }
    }

    pub fn add_put(&self, key: &[u8], value: &[u8]) {
        unsafe { LSMT_AddPut(self.ptr, key.as_ptr(), key.len() as c_size_t, value.as_ptr(), value.len() as c_size_t) }
    }
}

impl Wal {
    pub fn new_with_path(path: &str) -> Self {
        let c_path = CString::new(path).unwrap();
        let ptr = unsafe { Wal_NewWithPath(c_path.as_ptr()) };
        Wal { ptr }
    }

    pub fn recover(&self, lsmt: &LSMT) -> i32 {
        unsafe { Wal_Recover(self.ptr, lsmt.ptr) as i32 }
    }

    pub fn close(&self) {
        unsafe { Wal_Close(self.ptr) }
    }
}

fn convert_to_rust_vec(c_array: *mut *mut uint8_t, length: c_size_t) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    for i in 0..length {
        let elem_ptr = unsafe { *c_array.add(i as usize) };
        let elem_len = unsafe { libc::strlen(elem_ptr as *const c_char) };
        let elem = unsafe { std::slice::from_raw_parts(elem_ptr, elem_len).to_vec() };
        result.push(elem);
    }
    unsafe { libc::free(c_array as *mut c_void) };
    result
}