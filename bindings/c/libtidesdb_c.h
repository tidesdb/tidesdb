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

#ifndef TIDESDB_C_H
#define TIDESDB_C_H

#include "../../libtidesdb.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Opaque pointer to LSMT instance
typedef struct LSMT LSMT;

// Opaque pointer to Wal instance
typedef struct Wal Wal;

struct Transaction {
    TidesDB::Transaction* instance;
};

// Function to create a new Wal instance with a path
Wal* Wal_NewWithPath(const char* path);

// Function to recover operations from the Wal
int Wal_Recover(Wal* wal, LSMT* lsmTree);

// Function to close the Wal
void Wal_Close(Wal* wal);

// Function to create a new LSMT instance
LSMT* LSMT_New(const char* directory, int memtableFlushSize, int compactionInterval,
               int maxCompactionThreads);

// Function to delete an LSMT instance
void LSMT_Delete(LSMT* lsmTree);

// Function to put a key-value pair into the LSMT
int LSMT_Put(LSMT* lsmTree, const uint8_t* key, size_t key_len, const uint8_t* value,
             size_t value_len);

// Function to get a value for a given key from the LSMT
uint8_t* LSMT_Get(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* value_len);

// Function to delete a key from the LSMT
int LSMT_DeleteKey(LSMT* lsmTree, const uint8_t* key, size_t key_len);

// Function to close the LSMT
void LSMT_Close(LSMT* lsmTree);

// Transaction functions
Transaction* LSMT_BeginTransaction(LSMT* lsmTree);
int LSMT_CommitTransaction(LSMT* lsmTree, Transaction* tx);
void LSMT_RollbackTransaction(LSMT* lsmTree, Transaction* tx);
void LSMT_AddDelete(Transaction* tx, const uint8_t* key, size_t key_len, const uint8_t* value,
                    size_t value_len);
void LSMT_AddPut(Transaction* tx, const uint8_t* key, size_t key_len, const uint8_t* value,
                 size_t value_len);

// Additional functions
uint8_t** LSMT_NGet(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* result_len);
uint8_t** LSMT_LessThan(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* result_len);
uint8_t** LSMT_GreaterThan(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* result_len);
uint8_t** LSMT_Range(LSMT* lsmTree, const uint8_t* start, size_t start_len, const uint8_t* end,
                     size_t end_len, size_t* result_len);
uint8_t** LSMT_NRange(LSMT* lsmTree, const uint8_t* start, size_t start_len, const uint8_t* end,
                      size_t end_len, size_t* result_len);
uint8_t** LSMT_LessThanEq(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* result_len);
uint8_t** LSMT_GreaterThanEq(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* result_len);

#ifdef __cplusplus
}
#endif

#endif  // TIDESDB_C_H