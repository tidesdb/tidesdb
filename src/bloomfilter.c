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

bloomfilter *bloomfilter_create(unsigned int size)
{
    /* we allocate memory for the bloom filter */
    bloomfilter *bf = malloc(sizeof(bloomfilter));
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

void bloomfilter_destroy(bloomfilter *bf)
{
    /* we iteratively free the bloom filters */
    while (bf != NULL)
    {
        bloomfilter *next = bf->next;

        if (bf->set != NULL)
        {
            free(bf->set);
            bf->set = NULL;
        }

        free(bf);
        bf = next;
    }
}

bool bloomfilter_check(bloomfilter *bf, const uint8_t *data, unsigned int data_len)
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
            return true; /* we return true if the data is in the bloom filter */
        }
        bf = bf->next; /* we move to the next bloom filter */
    }
    return false;
}

bool bloomfilter_is_full(bloomfilter *bf)
{
    for (unsigned int i = 0; i < (bf->size + 7) / 8; i++) /* we iterate through the bitset */
        if (bf->set[i] != 0xFF) return false; /* we return false if the bitset is not full */

    return true; /* we return true if the bitset is full */
}

int bloomfilter_add(bloomfilter *bf, const uint8_t *data, unsigned int data_len)
{
    /* we hash the data */
    unsigned int hash_value1 = hash1(data, data_len);
    unsigned int hash_value2 = hash2(data, data_len);

    /* we iterate through the bloom filters */
    bloomfilter *current = bf;
    while (current->next != NULL)
    {
        current = current->next; /* we move to the next bloom filter */
    }

    if (bloomfilter_is_full(current)) /* we check if the bloom filter is full */
    {
        /* we create a new bloom filter */
        bloomfilter *new_bf = bloomfilter_create(current->size * 2);
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