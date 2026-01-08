/**
 * Copyright 2024 Alex Gaetano Padula (TidesDB)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>

#include "benchmark.h"

extern const storage_engine_ops_t *get_tidesdb_ops(void);
extern const storage_engine_ops_t *get_rocksdb_ops(void);

const storage_engine_ops_t *get_engine_ops(const char *engine_name)
{
    if (strcmp(engine_name, "tidesdb") == 0)
    {
        return get_tidesdb_ops();
    }
    else if (strcmp(engine_name, "rocksdb") == 0)
    {
        const storage_engine_ops_t *ops = get_rocksdb_ops();
        if (!ops)
        {
            return NULL;
        }
        return ops;
    }

    return NULL;
}