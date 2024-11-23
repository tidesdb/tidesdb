/*
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SERIALIZEABLE_STRUCTURES_H
#define SERIALIZEABLE_STRUCTURES_H
#include <stdbool.h>
#include <time.h>

/*
 * OP_CODE
 * operation code enum
 * used for operation codes in TidesDB
 */
enum OP_CODE { OP_PUT, OP_DELETE };

/*
 * key_value_pair
 * key value pair struct
 * used for key value pairs in TidesDB
 */
typedef struct {
    uint8_t *key;
    uint32_t key_size;
    uint8_t *value;
    uint32_t value_size;
    int64_t ttl;
} key_value_pair;

/*
 * column_family_config
 * column family configuration struct
 * used for column family configuration in TidesDB
 */
typedef struct {
    char *name;
    int32_t flush_threshold;
    int32_t max_level;
    float probability;
    bool compressed;
} column_family_config;

typedef struct {
    enum OP_CODE op_code;  // the operation code
    key_value_pair *kv;    // the key-value pair
    char *column_family;   // the column family for the operation
} operation;

#endif  // SERIALIZEABLE_STRUCTURES_H