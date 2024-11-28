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

unsigned int hash1(const unsigned char *data, unsigned int data_len)
{
    return XXH32(data, data_len, 0);
}

unsigned int hash2(const unsigned char *data, unsigned int data_len)
{
    return XXH32(data, data_len, 1);
}

bloomfilter *bloomfilter_create(unsigned int size)
{
    bloomfilter *bf = malloc(sizeof(bloomfilter));
    if (bf == NULL) return NULL;

    bf->size = size;
    bf->count = 0;
    bf->set = calloc((size + 7) / 8, sizeof(uint8_t));
    if (bf->set == NULL)
    {
        free(bf);
        return NULL;
    }

    bf->next = NULL;
    return bf;
}

void bloomfilter_destroy(bloomfilter *bf)
{
    while (bf != NULL)
    {
        bloomfilter *next = bf->next;
        free(bf);
        bf = next;
    }

    bf = NULL;
}

bool bloomfilter_check(bloomfilter *bf, const unsigned char *data, unsigned int data_len)
{
    unsigned int hash_value1 = hash1(data, data_len);
    unsigned int hash_value2 = hash2(data, data_len);

    while (bf != NULL)
    {
        if ((bf->set[hash_value1 % bf->size / 8] & (1 << (hash_value1 % 8))) &&
            (bf->set[hash_value2 % bf->size / 8] & (1 << (hash_value2 % 8))))
        {
            return true;
        }
        bf = bf->next;
    }
    return false;
}

bool bloomfilter_is_full(bloomfilter *bf)
{
    for (unsigned int i = 0; i < (bf->size + 7) / 8; i++)
        if (bf->set[i] != 0xFF) return false;

    return true;
}

int bloomfilter_add(bloomfilter *bf, const unsigned char *data, unsigned int data_len)
{
    unsigned int hash_value1 = hash1(data, data_len);
    unsigned int hash_value2 = hash2(data, data_len);

    bloomfilter *current = bf;
    while (current->next != NULL)
    {
        current = current->next;
    }

    if (bloomfilter_is_full(current))
    {
        bloomfilter *new_bf = bloomfilter_create(current->size * 2);
        if (new_bf == NULL) return 1;

        current->next = new_bf;
        current = new_bf;
    }

    current->set[hash_value1 % current->size / 8] |= (1 << (hash_value1 % 8));
    current->set[hash_value2 % current->size / 8] |= (1 << (hash_value2 % 8));
    current->count++;

    return 0;
}