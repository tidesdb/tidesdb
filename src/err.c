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

    /* We return the error */
    return e;
}

void tidesdb_err_free(tidesdb_err_t* e)
{
    /* Check if e is NULL */
    if (e == NULL) return;

    /* Free the message if it was dynamically allocated */
    if (e->message)
    {
        free(e->message);
        e->message = NULL;
    }

    /* Free the error struct */
    free(e);
    e = NULL;
}

tidesdb_err_t* tidesdb_err_from_code(TIDESDB_ERR_CODE code, ...)
{
    char buffer[256];
    va_list args;
    va_start(args, code);

    switch (code)
    {
        case TIDESDB_ERR_MEMORY_ALLOC:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_MKDIR:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_INIT_LOCK:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_DESTROY_LOCK:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_INVALID_NAME:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_RM_FAILED:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_REALLOC_FAILED:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_RELEASE_LOCK:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        default:
            snprintf(buffer, sizeof(buffer), "%s", tidesdb_err_messages[code].message);
    }

    va_end(args);

    tidesdb_err_t* err = tidesdb_err_new(tidesdb_err_messages[code].code, buffer);
    return err;
}