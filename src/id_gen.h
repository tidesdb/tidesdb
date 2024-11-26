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
#ifndef ID_GEN_H
#define ID_GEN_H

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* id_gen
 * generates unique ids
 * @param state the state of the id generator
 * @param lock the lock for the id generator
 */
typedef struct
{
    uint64_t state;
    pthread_mutex_t lock;
} id_gen;

/* id_gen_init
 * creates a new id generator
 * @param seed the seed for the id generator
 * @return the new id generator
 */
id_gen* id_gen_init(uint64_t seed);

/* id_gen_new
 * generates a new id
 * @param gen the id generator
 * @return the new id
 */
uint64_t id_gen_new(id_gen* gen);

/* id_gen_destroy
 * destroys the id generator
 * @param gen the id generator
 */
void id_gen_destroy(id_gen* gen);

#endif /* ID_GEN_H */