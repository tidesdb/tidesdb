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
#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../external/xxhash.h"
#include "endian.h"

/* we define the bloomfilter struct here so
 * we can use it in the struct definition for the next member */
typedef struct bloomfilter bloomfilter;

/* bloomfilter struct
 * @param size the size of the bloom filter (number of bits or slots)
 * @param count number of elements in the bloom filter
 * @param set array of integers representing the bloom filter's bitset
 * @param next pointer to the next bloomfilter (for chaining)
 */
struct bloomfilter
{
    uint32_t size;     /* Size of the bloom filter (number of bits or slots) */
    uint32_t count;    /* Number of elements in the bloom filter */
    uint8_t *set;      /* Array of integers representing the bloom filter's bitset */
    bloomfilter *next; /* Pointer to the next bloomfilter (for chaining) */
};

/* Bloom filter function prototypes */

/*
 * bloomfilter_create
 * create a new bloomfilter with an initial size
 * @param size the size of the bloomfilter
 */
bloomfilter *bloomfilter_create(unsigned int size);

/*
 * bloomfilter_destory
 * destroy a bloomfilter
 * @param bf the bloomfilter to destroy
 */
void bloomfilter_destroy(bloomfilter *bf);

/*
 * bloomfilter_is_full
 * check if the bloomfilter is full
 * @param bf the bloomfilter to check
 */
bool bloomfilter_is_full(bloomfilter *bf);

/*
 * bloomfilter_add
 * add data to the bloomfilter
 * @param bf the bloomfilter to add to
 * @param data the data to add
 * @param data_len the length of the data
 */
int bloomfilter_add(bloomfilter *bf, const unsigned char *data, unsigned int data_len);

/*
 * bloomfilter_check
 * check if data is in the bloomfilter
 * @param bf the bloomfilter to check
 * @param data the data to check
 * @param data_len the length of the data
 */
bool bloomfilter_check(bloomfilter *bf, const unsigned char *data, unsigned int data_len);

/*
 * hash1
 * hashes the data using xxhash
 * @param data the data to hash
 * @param data_len the length of the data
 */
unsigned int hash1(const unsigned char *data, unsigned int data_len);

/*
 * hash2
 * hashes the data using xxhash
 * @param data the data to hash
 * @param data_len the length of the data
 */
unsigned int hash2(const unsigned char *data, unsigned int data_len);

/*
 * bloomfilter_get_size
 * gets the size of the bloomfilter
 * @param bf the bloomfilter to get the size of
 */
unsigned int bloomfilter_get_size(bloomfilter *bf);

#endif /* BLOOMFILTER_H */