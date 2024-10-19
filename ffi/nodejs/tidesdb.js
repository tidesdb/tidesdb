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

const ffi = require('ffi-napi');
const ref = require('ref-napi');

// Define types
const uint8_t = ref.types.uint8;
const size_t = ref.types.size_t;
const LSMT = ref.refType(ref.types.void);
const Wal = ref.refType(ref.types.void);
const Transaction = ref.refType(ref.types.void);

// Load the shared library
const libtidesdb = ffi.Library('libtidesdb', {
    'LSMT_New': [LSMT, ['string', 'int', 'int', 'int']],
    'LSMT_Delete': ['void', [LSMT]],
    'LSMT_Put': ['int', [LSMT, 'pointer', size_t, 'pointer', size_t]],
    'LSMT_Get': ['pointer', [LSMT, 'pointer', size_t, ref.refType(size_t)]],
    'LSMT_DeleteKey': ['int', [LSMT, 'pointer', size_t]],
    'LSMT_Close': ['void', [LSMT]],
    'LSMT_BeginTransaction': [Transaction, [LSMT]],
    'LSMT_CommitTransaction': ['int', [LSMT, Transaction]],
    'LSMT_RollbackTransaction': ['void', [LSMT, Transaction]],
    'LSMT_AddDelete': ['void', [Transaction, 'pointer', size_t, 'pointer', size_t]],
    'LSMT_AddPut': ['void', [Transaction, 'pointer', size_t, 'pointer', size_t]],
    'Wal_NewWithPath': [Wal, ['string']],
    'Wal_Recover': ['int', [Wal, LSMT]],
    'Wal_Close': ['void', [Wal]],
    'LSMT_NGet': ['pointer', [LSMT, 'pointer', size_t, ref.refType(size_t)]],
    'LSMT_LessThan': ['pointer', [LSMT, 'pointer', size_t, ref.refType(size_t)]],
    'LSMT_GreaterThan': ['pointer', [LSMT, 'pointer', size_t, ref.refType(size_t)]],
    'LSMT_Range': ['pointer', [LSMT, 'pointer', size_t, 'pointer', size_t, ref.refType(size_t)]],
    'LSMT_NRange': ['pointer', [LSMT, 'pointer', size_t, 'pointer', size_t, ref.refType(size_t)]],
    'LSMT_LessThanEq': ['pointer', [LSMT, 'pointer', size_t, ref.refType(size_t)]],
    'LSMT_GreaterThanEq': ['pointer', [LSMT, 'pointer', size_t, ref.refType(size_t)]]
});

// Helper function to convert C array to JavaScript array
function convertToJSArray(cArray, length) {
    const result = [];
    for (let i = 0; i < length; i++) {
        const elem = ref.readPointer(cArray, i * ref.sizeof.pointer, ref.sizeof.pointer);
        const elemLength = ref.readUInt32(elem);
        result.push(ref.reinterpret(elem, elemLength));
    }
    return result;
}

// Exported functions
module.exports = {
    NewLSMT: (directory, memtableFlushSize, compactionInterval, maxCompactionThreads) => {
        return libtidesdb.LSMT_New(directory, memtableFlushSize, compactionInterval, maxCompactionThreads);
    },
    DeleteLSMT: (lsmt) => {
        libtidesdb.LSMT_Delete(lsmt);
    },
    Put: (lsmt, key, value) => {
        return libtidesdb.LSMT_Put(lsmt, key, key.length, value, value.length);
    },
    Get: (lsmt, key) => {
        const valueLen = ref.alloc(size_t);
        const value = libtidesdb.LSMT_Get(lsmt, key, key.length, valueLen);
        return ref.reinterpret(value, valueLen.deref());
    },
    DeleteKey: (lsmt, key) => {
        return libtidesdb.LSMT_DeleteKey(lsmt, key, key.length);
    },
    CloseLSMT: (lsmt) => {
        libtidesdb.LSMT_Close(lsmt);
    },
    BeginTransaction: (lsmt) => {
        return libtidesdb.LSMT_BeginTransaction(lsmt);
    },
    CommitTransaction: (lsmt, tx) => {
        return libtidesdb.LSMT_CommitTransaction(lsmt, tx);
    },
    RollbackTransaction: (lsmt, tx) => {
        libtidesdb.LSMT_RollbackTransaction(lsmt, tx);
    },
    AddDelete: (tx, key, value) => {
        libtidesdb.LSMT_AddDelete(tx, key, key.length, value, value.length);
    },
    AddPut: (tx, key, value) => {
        libtidesdb.LSMT_AddPut(tx, key, key.length, value, value.length);
    },
    NewWalWithPath: (path) => {
        return libtidesdb.Wal_NewWithPath(path);
    },
    Recover: (wal, lsmt) => {
        return libtidesdb.Wal_Recover(wal, lsmt);
    },
    CloseWal: (wal) => {
        libtidesdb.Wal_Close(wal);
    },
    NGet: (lsmt, key) => {
        const resultLen = ref.alloc(size_t);
        const cArray = libtidesdb.LSMT_NGet(lsmt, key, key.length, resultLen);
        return convertToJSArray(cArray, resultLen.deref());
    },
    LessThan: (lsmt, key) => {
        const resultLen = ref.alloc(size_t);
        const cArray = libtidesdb.LSMT_LessThan(lsmt, key, key.length, resultLen);
        return convertToJSArray(cArray, resultLen.deref());
    },
    GreaterThan: (lsmt, key) => {
        const resultLen = ref.alloc(size_t);
        const cArray = libtidesdb.LSMT_GreaterThan(lsmt, key, key.length, resultLen);
        return convertToJSArray(cArray, resultLen.deref());
    },
    Range: (lsmt, start, end) => {
        const resultLen = ref.alloc(size_t);
        const cArray = libtidesdb.LSMT_Range(lsmt, start, start.length, end, end.length, resultLen);
        return convertToJSArray(cArray, resultLen.deref());
    },
    NRange: (lsmt, start, end) => {
        const resultLen = ref.alloc(size_t);
        const cArray = libtidesdb.LSMT_NRange(lsmt, start, start.length, end, end.length, resultLen);
        return convertToJSArray(cArray, resultLen.deref());
    },
    LessThanEq: (lsmt, key) => {
        const resultLen = ref.alloc(size_t);
        const cArray = libtidesdb.LSMT_LessThanEq(lsmt, key, key.length, resultLen);
        return convertToJSArray(cArray, resultLen.deref());
    },
    GreaterThanEq: (lsmt, key) => {
        const resultLen = ref.alloc(size_t);
        const cArray = libtidesdb.LSMT_GreaterThanEq(lsmt, key, key.length, resultLen);
        return convertToJSArray(cArray, resultLen.deref());
    }
};