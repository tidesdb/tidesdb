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

tidesdb_err_t *tidesdb_err_new(int code, char *message)
{
    /* we allocate memory for the error struct */
    tidesdb_err_t *e = malloc(sizeof(tidesdb_err_t));
    if (e == NULL) return NULL;

    /* we set the code and message */
    e->code = code;

    /* we check if the message is NULL */
    if (message == NULL)
    {
        e->message = NULL;
    }
    else
    {
        /* we allocate memory for the message */
        e->message = strdup(message);
        if (e->message == NULL)
        {
            /* we free the error struct if the message allocation fails */
            free(e);
            return NULL;
        }
    }

    /* we return the error */
    return e;
}

void tidesdb_err_free(tidesdb_err_t *e)
{
    /* check if err is NULL */
    if (e == NULL) return;

    if (e->message)
    {
        free(e->message);
        e->message = NULL;
    }

    /* free the error struct */
    free(e);
    e = NULL;
}

tidesdb_err_t *tidesdb_err_from_code(TIDESDB_ERR_CODE code, ...)
{
    char buffer[TDB_ERR_MAX_MESSAGE_SIZE];
    va_list args;
    va_start(args, code);

    if (tidesdb_err_messages[code].has_context)
    {
        const char *obj = va_arg(args, const char *);
        snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
    }
    else
    {
        snprintf(buffer, sizeof(buffer), "%s", tidesdb_err_messages[code].message);
    }

    va_end(args);

    tidesdb_err_t *err = tidesdb_err_new(tidesdb_err_messages[code].code, buffer);
    return err;
}