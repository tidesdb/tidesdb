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
#include "bloomfilter.h"
unsigned int hash1(const uint8_t *data, unsigned int data_len)
{
    return XXH32(data, data_len, 0); /* we hash using xxhash */
}

unsigned int hash2(const uint8_t *data, unsigned int data_len)
{
    return XXH32(data, data_len, 1); /* we hash using xxhash */
}

bloomfilter_t *bloomfilter_create(unsigned int size)
{
    /* we allocate memory for the bloom filter */
    bloomfilter_t *bf = malloc(sizeof(bloomfilter_t));
    if (bf == NULL) return NULL; /* we return NULL if we could not allocate memory */

    /* we set the size of the bloom filter */
    bf->size = size;

    bf->count = 0;
    /* we ensure partial bytes are rounded up */
    bf->set = calloc((size + 7) / 8, sizeof(uint8_t)); /* we allocate memory for the bitset */
    if (bf->set == NULL) /* we return NULL if we could not allocate memory */
    {
        free(bf); /* we free the bloom filter */
        return NULL;
    }

    bf->next = NULL; /* we set the next bloom filter to NULL */
    return bf;
}

void bloomfilter_destroy(bloomfilter_t *bf)
{
    /* we iteratively free the bloom filters */
    while (bf != NULL)
    {
        bloomfilter_t *next = bf->next;

        if (bf->set != NULL)
        {
            free(bf->set);
            bf->set = NULL;
        }

        free(bf);
        bf = next;
    }
}

int bloomfilter_check(bloomfilter_t *bf, const uint8_t *data, unsigned int data_len)
{
    /* we hash the data */
    unsigned int hash_value1 = hash1(data, data_len);
    unsigned int hash_value2 = hash2(data, data_len);

    /* we iterate through the bloom filters */
    while (bf != NULL)
    {
        /* we check if the data is in the bloom filter */
        if ((bf->set[(hash_value1 % bf->size) / 8] & (1 << (hash_value1 % 8))) &&
            (bf->set[(hash_value2 % bf->size) / 8] & (1 << (hash_value2 % 8))))
        {
            return 0; /* we return 0 if the data is in the bloom filter */
        }
        bf = bf->next; /* we move to the next bloom filter */
    }
    return -1; /* we return -1 if the data is not in the bloom filter */
}

int bloomfilter_is_full(bloomfilter_t *bf)
{
    for (unsigned int i = 0; i < (bf->size + 7) / 8; i++) /* we iterate through the bitset */
        if (bf->set[i] != 0xFF) return -1; /* we return false if the bitset is not full */

    return 0; /* we return 0 if the bitset is full */
}

int bloomfilter_add(bloomfilter_t *bf, const uint8_t *data, unsigned int data_len)
{
    /* we hash the data */
    unsigned int hash_value1 = hash1(data, data_len);
    unsigned int hash_value2 = hash2(data, data_len);

    /* we iterate through the bloom filters */
    bloomfilter_t *current = bf;
    while (current->next != NULL)
    {
        current = current->next; /* we move to the next bloom filter */
    }

    if (bloomfilter_is_full(current) != -1) /* we check if the bloom filter is full */
    {
        /* we create a new bloom filter */
        bloomfilter_t *new_bf = bloomfilter_create(current->size * 2);
        if (new_bf == NULL) return 1;

        current->next = new_bf; /* we set the next bloom filter */
        current = new_bf;
    }

    /* we add the data to the bloom filter */
    current->set[(hash_value1 % current->size) / 8] |= (1 << (hash_value1 % 8));
    current->set[(hash_value2 % current->size) / 8] |= (1 << (hash_value2 % 8));
    /* we increment the count */
    current->count++;

    return 0;
}