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
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/bloomfilter.h"
#include "test_macros.h"

/* we test bloom filter creation and destruction */
void test_bloomfilter_create()
{
    /* we create a bloom filter with size 1024 */
    bloomfilter *bf = bloomfilter_create(1024);

    /* we check if the bloom filter was created correctly */

    /* is not null */
    assert(bf != NULL);

    /* has the correct size */
    assert(bf->size == 1024);

    /* has the correct count */
    assert(bf->count == 0);

    /* has the correct set */
    assert(bf->set != NULL);

    /* let us destroy the bloom filter */
    bloomfilter_destroy(bf);

    printf(GREEN "test_bloomfilter_create passed\n" RESET);
}

/* we test bloom filter add and check
 * we add 1 data entry and check if it is in the bloom filter */
void test_bloomfilter_add_check()
{
    /* we create a bloom filter with size 1024 */
    bloomfilter *bf = bloomfilter_create(1024);

    const uint8_t data1[] = "test1"; /* the entry that will be in bf */
    const uint8_t data2[] = "test2"; /* the entry that will not be in bf */

    /* we add data1 to the bloom filter */
    assert(bloomfilter_add(bf, data1, strlen((const char *)data1)) == 0);

    /* we check if data1 is in the bloom filter, it should be */
    assert(bloomfilter_check(bf, data1, strlen((const char *)data1)) == true);

    /* we check if data2 is in the bloom filter, it should not be */
    assert(bloomfilter_check(bf, data2, strlen((const char *)data2)) == false);

    /* we destroy the bloom filter */
    bloomfilter_destroy(bf);

    printf(GREEN "test_bloomfilter_add_check passed\n" RESET);
}

/* we test if the bloom filter is full
 * we add 16 data entries to a bloom filter with size 8 */
void test_bloomfilter_is_full()
{
    bloomfilter *bf = bloomfilter_create(8); /* Small size for testing */

    for (int i = 0; i < 16; i++)
    {
        uint8_t data[2] = {(uint8_t)i, '\0'};
        bloomfilter_add(bf, data, 1);
    }

    assert(bloomfilter_is_full(bf) == true);

    bloomfilter_destroy(bf);

    printf(GREEN "test_bloomfilter_is_full passed\n" RESET);
}

void test_bloomfilter_chaining()
{
    bloomfilter *bf = bloomfilter_create(8); /* Small size for testing */
    const uint8_t data1[] = "test1";
    const uint8_t data2[] = "test2";

    for (int i = 0; i < 256; i++)
    {
        uint8_t data[256] = {(uint8_t)i, '\0'};
        bloomfilter_add(bf, data, 1);
    }

    assert(bf->next != NULL);
    assert(bloomfilter_add(bf, data2, strlen((const char *)data2)) == 0);
    assert(bloomfilter_check(bf, data2, strlen((const char *)data2)) == true);

    /* check if all the data is in the bloom filter */
    for (int i = 0; i < 256; i++)
    {
        uint8_t data[256] = {(uint8_t)i, '\0'};
        assert(bloomfilter_check(bf, data, 1) == true);
    }

    bloomfilter_destroy(bf);

    printf(GREEN "test_bloomfilter_chaining passed\n" RESET);
}

/** OR cc -g3 -fsanitize=address,undefined src/*.c external/*.c test/bloomfilter__tests.c -lzstd **/
int main(void)
{
    test_bloomfilter_create();
    test_bloomfilter_add_check();
    test_bloomfilter_is_full();
    test_bloomfilter_chaining();
    return 0;
}