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

local ffi = require("ffi")

ffi.cdef[[
typedef struct LSMT LSMT;
typedef struct Wal Wal;
typedef struct Transaction Transaction;

LSMT* LSMT_New(const char* directory, int memtableFlushSize, int compactionInterval, int maxCompactionThreads);
void LSMT_Delete(LSMT* lsmt);
int LSMT_Put(LSMT* lsmt, const uint8_t* key, size_t key_len, const uint8_t* value, size_t value_len);
uint8_t* LSMT_Get(LSMT* lsmt, const uint8_t* key, size_t key_len, size_t* value_len);
int LSMT_DeleteKey(LSMT* lsmt, const uint8_t* key, size_t key_len);
void LSMT_Close(LSMT* lsmt);
Transaction* LSMT_BeginTransaction(LSMT* lsmt);
int LSMT_CommitTransaction(LSMT* lsmt, Transaction* tx);
void LSMT_RollbackTransaction(LSMT* lsmt, Transaction* tx);
void LSMT_AddDelete(Transaction* tx, const uint8_t* key, size_t key_len, const uint8_t* value, size_t value_len);
void LSMT_AddPut(Transaction* tx, const uint8_t* key, size_t key_len, const uint8_t* value, size_t value_len);
Wal* Wal_NewWithPath(const char* path);
int Wal_Recover(Wal* wal, LSMT* lsmt);
void Wal_Close(Wal* wal);
uint8_t** LSMT_NGet(LSMT* lsmt, const uint8_t* key, size_t key_len, size_t* result_len);
uint8_t** LSMT_LessThan(LSMT* lsmt, const uint8_t* key, size_t key_len, size_t* result_len);
uint8_t** LSMT_GreaterThan(LSMT* lsmt, const uint8_t* key, size_t key_len, size_t* result_len);
uint8_t** LSMT_Range(LSMT* lsmt, const uint8_t* start, size_t start_len, const uint8_t* end, size_t end_len, size_t* result_len);
uint8_t** LSMT_NRange(LSMT* lsmt, const uint8_t* start, size_t start_len, const uint8_t* end, size_t end_len, size_t* result_len);
uint8_t** LSMT_LessThanEq(LSMT* lsmt, const uint8_t* key, size_t key_len, size_t* result_len);
uint8_t** LSMT_GreaterThanEq(LSMT* lsmt, const uint8_t* key, size_t key_len, size_t* result_len);
void free(void* ptr);
]]

local lib = ffi.load("libtidesdb.so")

local TidesDB = {}

function TidesDB.newLSMT(directory, memtableFlushSize, compactionInterval, maxCompactionThreads)
    local lsmt = lib.LSMT_New(directory, memtableFlushSize, compactionInterval, maxCompactionThreads)
    return ffi.gc(lsmt, lib.LSMT_Delete)
end

function TidesDB.put(lsmt, key, value)
    return lib.LSMT_Put(lsmt, key, #key, value, #value)
end

function TidesDB.get(lsmt, key)
    local value_len = ffi.new("size_t[1]")
    local value_ptr = lib.LSMT_Get(lsmt, key, #key, value_len)
    local value = ffi.string(value_ptr, value_len[0])
    lib.free(value_ptr)
    return value
end

function TidesDB.deleteKey(lsmt, key)
    return lib.LSMT_DeleteKey(lsmt, key, #key)
end

function TidesDB.close(lsmt)
    lib.LSMT_Close(lsmt)
end

function TidesDB.beginTransaction(lsmt)
    return lib.LSMT_BeginTransaction(lsmt)
end

function TidesDB.commitTransaction(lsmt, tx)
    return lib.LSMT_CommitTransaction(lsmt, tx)
end

function TidesDB.rollbackTransaction(lsmt, tx)
    lib.LSMT_RollbackTransaction(lsmt, tx)
end

function TidesDB.addDelete(tx, key, value)
    lib.LSMT_AddDelete(tx, key, #key, value, #value)
end

function TidesDB.addPut(tx, key, value)
    lib.LSMT_AddPut(tx, key, #key, value, #value)
end

function TidesDB.newWalWithPath(path)
    local wal = lib.Wal_NewWithPath(path)
    return ffi.gc(wal, lib.Wal_Close)
end

function TidesDB.recover(wal, lsmt)
    return lib.Wal_Recover(wal, lsmt)
end

function TidesDB.closeWal(wal)
    lib.Wal_Close(wal)
end

local function convertToLuaTable(c_array, length)
    local result = {}
    for i = 0, length - 1 do
        local elem_ptr = c_array[i]
        local elem_len = ffi.cast("int*", elem_ptr)[0]
        table.insert(result, ffi.string(elem_ptr, elem_len))
    end
    lib.free(c_array)
    return result
end

function TidesDB.nget(lsmt, key)
    local result_len = ffi.new("size_t[1]")
    local c_array = lib.LSMT_NGet(lsmt, key, #key, result_len)
    return convertToLuaTable(c_array, result_len[0])
end

function TidesDB.lessThan(lsmt, key)
    local result_len = ffi.new("size_t[1]")
    local c_array = lib.LSMT_LessThan(lsmt, key, #key, result_len)
    return convertToLuaTable(c_array, result_len[0])
end

function TidesDB.greaterThan(lsmt, key)
    local result_len = ffi.new("size_t[1]")
    local c_array = lib.LSMT_GreaterThan(lsmt, key, #key, result_len)
    return convertToLuaTable(c_array, result_len[0])
end

function TidesDB.range(lsmt, start, end_)
    local result_len = ffi.new("size_t[1]")
    local c_array = lib.LSMT_Range(lsmt, start, #start, end_, #end_, result_len)
    return convertToLuaTable(c_array, result_len[0])
end

function TidesDB.nrange(lsmt, start, end_)
    local result_len = ffi.new("size_t[1]")
    local c_array = lib.LSMT_NRange(lsmt, start, #start, end_, #end_, result_len)
    return convertToLuaTable(c_array, result_len[0])
end

function TidesDB.lessThanEq(lsmt, key)
    local result_len = ffi.new("size_t[1]")
    local c_array = lib.LSMT_LessThanEq(lsmt, key, #key, result_len)
    return convertToLuaTable(c_array, result_len[0])
end

function TidesDB.greaterThanEq(lsmt, key)
    local result_len = ffi.new("size_t[1]")
    local c_array = lib.LSMT_GreaterThanEq(lsmt, key, #key, result_len)
    return convertToLuaTable(c_array, result_len[0])
end

return TidesDB