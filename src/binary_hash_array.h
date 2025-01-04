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
#ifndef __BINARY_HASH_ARRAY_H__
#define __BINARY_HASH_ARRAY_H__
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../external/xxhash.h"

/**
 * binary_hash_array_entry_t
 * binary hash array entry struct
 * @param key the key of the entry. Is fixed at 16 bytes and is a hash of the original key
 * @param value the value of the entry. Is fixed at 8 bytes
 */
typedef struct
{
    uint8_t key[16];
    int64_t value;
} binary_hash_array_entry_t;

/**
 * binary_hash_array_t
 * binary hash array struct
 * @param entries the entries in the array
 * @param size the size of the array
 * @param capacity the capacity of the array
 */
typedef struct
{
    binary_hash_array_entry_t *entries;
    size_t size;
    size_t capacity;
} binary_hash_array_t;

/**
 * hash_key
 * hashes a key
 * @param key the key to hash
 * @param key_len the length of the key
 * @param hash the hash of the key
 */
void binary_hash_array_hash_key(const uint8_t *key, size_t key_len, uint8_t *hash);

/**
 * binary_hash_array_new
 * creates a new binary hash array
 * @param size the size of the array
 * @return the new binary hash array
 */
binary_hash_array_t *binary_hash_array_new(size_t size);

/**
 * binary_hash_array_add
 * adds an entry to the binary hash array
 * @param bha the binary hash array to add to
 * @param key the key of the entry
 * @param key_len the length of the key
 * @param value the value of the entry
 */
void binary_hash_array_add(binary_hash_array_t *bha, uint8_t *key, size_t key_len, int64_t value);

/**
 * binary_hash_array_contains
 * checks if the binary hash array contains a key
 * @param bha the binary hash array to check
 * @param key the key to check for
 * @param key_len the length of the key
 * @return the value of the key if it exists, 0 if not
 */
int64_t binary_hash_array_contains(binary_hash_array_t *bha, uint8_t *key, size_t key_len);

/**
 * binary_hash_array_free
 * frees a binary hash array
 * @param bha the binary hash array to free
 */
void binary_hash_array_free(binary_hash_array_t *bha);

/**
 * compare
 * compares two entries
 * @param a the first entry
 * @param b the second entry
 * @return the comparison
 */
int binary_hash_array_compare(const void *a, const void *b);

/**
 * binary_hash_array_serialize
 * serializes the binary hash array.  Will sort the entries by key before serializing.
 * @param bha the binary hash array to serialize
 * @param out_size the size of the serialized array
 * @return the serialized array
 */
uint8_t *binary_hash_array_serialize(binary_hash_array_t *bha, size_t *out_size);

/**
 * binary_hash_array_deserialize
 * deserializes a binary hash array
 * @param data the data to deserialize
 * @param size the size of the data
 * @return the deserialized binary hash array
 */
binary_hash_array_t *binary_hash_array_deserialize(const uint8_t *data);

/**
 * binary_hash_array_resize
 * resizes the binary hash array
 * @param bha the binary hash array to resize
 * @param new_capacity the new capacity of the array
 */
void binary_hash_array_resize(binary_hash_array_t *bha, size_t new_capacity);

#endif /* __BINARY_HASH_ARRAY_H__ */