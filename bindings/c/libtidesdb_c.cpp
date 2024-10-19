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

#include "libtidesdb_c.h"
extern "C" {

struct LSMT {
    std::unique_ptr<TidesDB::LSMT> instance;
};

LSMT* LSMT_New(const char* directory, int memtableFlushSize, int compactionInterval,
               int maxCompactionThreads) {
    try {
        auto lsmTree =
            TidesDB::LSMT::New(directory, std::filesystem::perms::owner_all, memtableFlushSize,
                               compactionInterval, maxCompactionThreads);
        return new LSMT{std::move(lsmTree)};
    } catch (...) {
        return nullptr;
    }
}

void LSMT_Delete(LSMT* lsmTree) { delete lsmTree; }

int LSMT_Put(LSMT* lsmTree, const uint8_t* key, size_t key_len, const uint8_t* value,
             size_t value_len) {
    std::vector<uint8_t> keyVec(key, key + key_len);
    std::vector<uint8_t> valueVec(value, value + value_len);
    return lsmTree->instance->Put(keyVec, valueVec) ? 0 : -1;
}

uint8_t* LSMT_Get(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* value_len) {
    std::vector<uint8_t> keyVec(key, key + key_len);
    auto valueVec = lsmTree->instance->Get(keyVec);
    if (valueVec.empty()) {
        *value_len = 0;
        return nullptr;
    }
    *value_len = valueVec.size();
    uint8_t* value = (uint8_t*)malloc(*value_len);
    memcpy(value, valueVec.data(), *value_len);
    return value;
}

int LSMT_DeleteKey(LSMT* lsmTree, const uint8_t* key, size_t key_len) {
    std::vector<uint8_t> keyVec(key, key + key_len);
    return lsmTree->instance->Delete(keyVec) ? 0 : -1;
}

void LSMT_Close(LSMT* lsmTree) { lsmTree->instance->Close(); }

// Transaction functions
Transaction* LSMT_BeginTransaction(LSMT* lsmTree) {
    return new Transaction{lsmTree->instance->BeginTransaction()};
}

int LSMT_CommitTransaction(LSMT* lsmTree, Transaction* tx) {
    return lsmTree->instance->CommitTransaction(tx->instance) ? 0 : -1;
}

void LSMT_RollbackTransaction(LSMT* lsmTree, Transaction* tx) {
    lsmTree->instance->RollbackTransaction(tx->instance);
    delete tx;
}

void LSMT_AddDelete(Transaction* tx, const uint8_t* key, size_t key_len, const uint8_t* value,
                    size_t value_len) {
    std::vector<uint8_t> keyVec(key, key + key_len);
    std::vector<uint8_t> valueVec(value, value + value_len);
    TidesDB::LSMT::AddDelete(tx->instance, keyVec, valueVec);
}

void LSMT_AddPut(Transaction* tx, const uint8_t* key, size_t key_len, const uint8_t* value,
                 size_t value_len) {
    std::vector<uint8_t> keyVec(key, key + key_len);
    std::vector<uint8_t> valueVec(value, value + value_len);
    TidesDB::LSMT::AddPut(tx->instance, keyVec, valueVec);
}

// Helper function to convert vector of pairs to C array
uint8_t** convertToCArray(
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& vec,
    size_t* result_len) {
    *result_len = vec.size();
    uint8_t** result = (uint8_t**)malloc(vec.size() * sizeof(uint8_t*));
    for (size_t i = 0; i < vec.size(); ++i) {
        result[i] = (uint8_t*)malloc(vec[i].first.size() + vec[i].second.size());
        memcpy(result[i], vec[i].first.data(), vec[i].first.size());
        memcpy(result[i] + vec[i].first.size(), vec[i].second.data(), vec[i].second.size());
    }
    return result;
}

// Additional functions
uint8_t** LSMT_NGet(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* result_len) {
    std::vector<uint8_t> keyVec(key, key + key_len);
    auto result = lsmTree->instance->NGet(keyVec);
    return convertToCArray(result, result_len);
}

uint8_t** LSMT_LessThan(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* result_len) {
    std::vector<uint8_t> keyVec(key, key + key_len);
    auto result = lsmTree->instance->LessThan(keyVec);
    return convertToCArray(result, result_len);
}

uint8_t** LSMT_GreaterThan(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* result_len) {
    std::vector<uint8_t> keyVec(key, key + key_len);
    auto result = lsmTree->instance->GreaterThan(keyVec);
    return convertToCArray(result, result_len);
}

uint8_t** LSMT_Range(LSMT* lsmTree, const uint8_t* start, size_t start_len, const uint8_t* end,
                     size_t end_len, size_t* result_len) {
    std::vector<uint8_t> startVec(start, start + start_len);
    std::vector<uint8_t> endVec(end, end + end_len);
    auto result = lsmTree->instance->Range(startVec, endVec);
    return convertToCArray(result, result_len);
}

uint8_t** LSMT_NRange(LSMT* lsmTree, const uint8_t* start, size_t start_len, const uint8_t* end,
                      size_t end_len, size_t* result_len) {
    std::vector<uint8_t> startVec(start, start + start_len);
    std::vector<uint8_t> endVec(end, end + end_len);
    auto result = lsmTree->instance->NRange(startVec, endVec);
    return convertToCArray(result, result_len);
}

uint8_t** LSMT_LessThanEq(LSMT* lsmTree, const uint8_t* key, size_t key_len, size_t* result_len) {
    std::vector<uint8_t> keyVec(key, key + key_len);
    auto result = lsmTree->instance->LessThanEq(keyVec);
    return convertToCArray(result, result_len);
}

uint8_t** LSMT_GreaterThanEq(LSMT* lsmTree, const uint8_t* key, size_t key_len,
                             size_t* result_len) {
    std::vector<uint8_t> keyVec(key, key + key_len);
    auto result = lsmTree->instance->GreaterThanEq(keyVec);
    return convertToCArray(result, result_len);
}
}