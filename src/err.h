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
#ifndef TIDESDB_ERR_H
#define TIDESDB_ERR_H

#include <stdlib.h>

/*
 * tidesdb_err
 * the TidesDB error struct
 * used for error handling in TidesDB
 * @param code the error code
 * @param message the error message
 */
typedef struct
{
    int code;      /* the error code */
    char* message; /* the error message */
} tidesdb_err;

/*
 * tidesdb_err_new
 * create a new TidesDB error
 * @param code the error code
 * @param message the error message
 */
tidesdb_err* tidesdb_err_new(int code, char* message);

/*
 * tidesdb_err_free
 * free a TidesDB error
 * @param e the error to free
 */
void tidesdb_err_free(tidesdb_err* e);

#endif /* TIDESDB_ERR_H */