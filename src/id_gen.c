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
#include "id_gen.h"

#if defined(_WIN32) || defined(_WIN64)
id_gen* id_gen_init(uint64_t seed)
{
    id_gen* gen = malloc(sizeof(id_gen)); /* allocate memory for the id generator */
    /* check if successful */
    if (gen == NULL)
    {
        return NULL;
    }
    /* set the state of the id generator */
    gen->state = seed;

    /* initialize the lock for the id generator */
    InitializeCriticalSection(&gen->lock);
    return gen;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
id_gen_t* id_gen_init(uint64_t seed)
{
    id_gen_t* gen = malloc(sizeof(id_gen_t)); /* allocate memory for the id generator */
    /* check if successful */
    if (gen == NULL)
    {
        return NULL;
    }
    /* set the state of the id generator */
    gen->state = seed;

    /* initialize the lock for the id generator */
    pthread_mutex_init(&gen->lock, NULL);
    return gen;
}
#endif

#if defined(_WIN32) || defined(_WIN64)
uint64_t id_gen_new(id_gen* gen)
{
    uint64_t id; /* the new id */

    /* lock the id generator */
    EnterCriticalSection(&gen->lock);

    /* generate a new id using the LCG formula */
    gen->state = (A * gen->state + C) % M;
    id = gen->state;

    /* unlock the id generator */
    LeaveCriticalSection(&gen->lock);

    return id;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
uint64_t id_gen_new(id_gen_t* gen)
{
    uint64_t id; /* the new id */

    /* lock the id generator */
    pthread_mutex_lock(&gen->lock);

    /* generate a new id using the LCG formula */
    gen->state = (A * gen->state + C) % M;
    id = gen->state;

    /* unlock the id generator */
    pthread_mutex_unlock(&gen->lock);

    return id;
}
#endif

#if defined(_WIN32) || defined(_WIN64)
void id_gen_destroy(id_gen* gen)
{
    /* destroy the lock */
    DeleteCriticalSection(&gen->lock);
    /* free the memory allocated for the id generator */
    free(gen);

    gen = NULL;
}
#elif __linux__ || defined(__unix__) || defined(__APPLE__)
void id_gen_destroy(id_gen_t* gen)
{
    /* destroy the lock */
    pthread_mutex_destroy(&gen->lock);
    /* free the memory allocated for the id generator */
    free(gen);

    gen = NULL;
}
#endif