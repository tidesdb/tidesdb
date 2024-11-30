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
#include "err.h"

tidesdb_err_t* tidesdb_err_new(int code, char* message)
{
    /* we allocate memory for the error struct */
    tidesdb_err_t* e = malloc(sizeof(tidesdb_err_t));
    if (e == NULL) return NULL;

    /* We set the code and message */
    e->code = code;
    e->message = message;

    /* We return the error */
    return e;
}

void tidesdb_err_free(tidesdb_err_t* e)
{
    /* Check if e is NULL */
    if (e == NULL) return;

    /* we don't free the message has it shouldn't be dynamically allocated */
    /* we free the error */
    free(e);
    e = NULL;
}