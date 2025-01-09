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

tidesdb_err_t* tidesdb_err_from_code(TIDESDB_ERR_CODE code, ...)
{
    char buffer[TDB_ERR_MAX_MESSAGE_SIZE];
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
        case TIDESDB_ERR_PARTIAL_MERGE_ALREADY_STARTED:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_OPEN_DIRECTORY:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_OPEN_WAL:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_ADD_COLUMN_FAMILY:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_COLUMN_FAMILY_WAL_REPLAY:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_CLOSE_DIRECTORY:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_OPEN_SSTABLE:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_INIT_WAL_CURSOR:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_FLUSH:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_INIT_CURSOR_FOR_FLUSH:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_CREATE_SORTED_BINARY_HASH_ARR:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_SERIALIZE_KEY_VALUE_PAIR:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_CREATE_BLOCK_ON_FLUSH:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_WRITE_BLOCK_ON_FLUSH:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_SERIALIZE_BLOCK_INDICES:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_CREATE_BLOCK_FOR_INDICES:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_WRITE_BLOCK_FOR_INDICES:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_CLEAR_MEMTABLE:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_TRUNCATE_WAL:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_MERGE_SSTABLES:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }

        case TIDESDB_ERR_FAILED_TO_REMOVE_SSTABLES_ON_COMPACTION:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_GET_MERGED_SSTABLE_PATH:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_CLOSE_RENAME_MERGED_SSTABLE:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_MERGED_SSTABLE:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_ACQUIRE_LOCK_FOR_MERGE:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_OPEN_BLOCK_MANAGER_FOR_MERGE:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_MERGE_SORT_BLOCK_WRITE_FAILED:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_MERGE_SORT_BLOCK_CREATE_FAILED:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_MERGE_SORT_BHA_SERIALIZE_FAILED:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_INVALID_BLOCK_MANAGER:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_WRITE_BLOOM_BLOCK_ON_FLUSH:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_SERIALIZE_BLOOM:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_CREATE_BLOOM:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_CREATE_BLOOM_FILTER:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_SERIALIZE_BLOOM_FILTER:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_FAILED_TO_GET_SSTABLE_SIZE:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_INVALID_STAT:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_INVALID_NAME_LENGTH:
        {
            const char* obj = va_arg(args, const char*);
            snprintf(buffer, sizeof(buffer), tidesdb_err_messages[code].message, obj);
            break;
        }
        case TIDESDB_ERR_PATH_TOO_LONG:
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