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
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#include "../src/id_gen.h"
#include "test_macros.h"

void test_id_gen_init()
{
    id_gen* gen = id_gen_init(12345);
    assert(gen != NULL);
    assert(gen->state == 12345);
    id_gen_destroy(gen);

    printf(GREEN "test_id_gen_init passed\n" RESET);
}

void test_id_gen_new()
{
    id_gen* gen = id_gen_init(12345);
    uint64_t id1 = id_gen_new(gen);
    uint64_t id2 = id_gen_new(gen);
    assert(id1 != id2);
    id_gen_destroy(gen);

    printf(GREEN "test_id_gen_new passed\n" RESET);
}

/* helper */
void* generate_ids(void* arg)
{
    id_gen* gen = arg;
    for (int i = 0; i < 10; ++i)
    {
        uint64_t id = id_gen_new(gen);
        printf("Generated ID: %lu\n", id);
    }
    return NULL;
}

void test_id_gen_thread_safety()
{
    id_gen* gen = id_gen_init(12345);
    pthread_t threads[4];

    for (int i = 0; i < 4; ++i)
    {
        pthread_create(&threads[i], NULL, generate_ids, gen);
    }

    for (int i = 0; i < 4; ++i)
    {
        pthread_join(threads[i], NULL);
    }

    id_gen_destroy(gen);

    printf(GREEN "test_id_gen_thread_safety passed\n" RESET);
}

/** OR cc -g3 -fsanitize=address,undefined src/*.c external/*.c test/id_gen__tests.c -lzstd **/
int main(void)
{
    test_id_gen_init();
    test_id_gen_new();
    test_id_gen_thread_safety();
    return 0;
}