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
#include "pager.h"

bool pager_open(const char* filename, pager** p) {
    // We check if the filename is NULL
    if (filename == NULL) {
        return false;
    }

    // We allocate memory for the pager
    *p = malloc(sizeof(pager));
    if (*p == NULL) {
        return false;
    }

    // We open the file
    (*p)->file = fopen(filename, "a+b");
    if ((*p)->file == NULL) {
        free(*p);
        return false;
    }

    // We copy over filename
    (*p)->filename = malloc(strlen(filename) + 1);
    if ((*p)->filename == NULL) {
        fclose((*p)->file);
        free(*p);
        return false;
    }
    strcpy((*p)->filename, filename);

    // We initialize the file lock
    if (pthread_rwlock_init(&(*p)->file_lock, NULL) != 0) {
        free((*p)->filename);
        fclose((*p)->file);
        free(*p);
        return false;
    }

    // We get amount of pages
    size_t page_count = 0;
    if (pager_pages_count(*p, &page_count) == false) {
        pthread_rwlock_destroy(&(*p)->file_lock);
        free((*p)->filename);
        fclose((*p)->file);
        free(*p);
        return false;
    }

    // Set the number of pages
    (*p)->num_pages = page_count;

    // Allocate memory for the page locks

    (*p)->page_locks = malloc(sizeof(pthread_rwlock_t) * page_count);
    if ((*p)->page_locks == NULL) {
        pthread_rwlock_destroy(&(*p)->file_lock);
        free((*p)->filename);
        fclose((*p)->file);
        free(*p);
        return false;
    }

    // Initialize the page locks
    for (unsigned int i = 0; i < page_count; i++) {
        if (pthread_rwlock_init(&(*p)->page_locks[i], NULL) != 0) {
            for (unsigned int j = 0; j < i; j++) {
                pthread_rwlock_destroy(&(*p)->page_locks[j]);
            }
            free((*p)->page_locks);
            pthread_rwlock_destroy(&(*p)->file_lock);
            free((*p)->filename);
            fclose((*p)->file);
            free(*p);
            return false;
        }
    }

    // Initialize the sync mutex
    if (pthread_mutex_init(&(*p)->sync_mutex, NULL) != 0) {
        for (unsigned int i = 0; i < page_count; i++) {
            pthread_rwlock_destroy(&(*p)->page_locks[i]);
        }
        free((*p)->page_locks);
        pthread_rwlock_destroy(&(*p)->file_lock);
        free((*p)->filename);
        fclose((*p)->file);
        free(*p);
        return false;
    }

    // Initialize the sync condition variable
    if (pthread_cond_init(&(*p)->sync_cond, NULL) != 0) {
        pthread_mutex_destroy(&(*p)->sync_mutex);
        for (unsigned int i = 0; i < page_count; i++) {
            pthread_rwlock_destroy(&(*p)->page_locks[i]);
        }
        free((*p)->page_locks);
        pthread_rwlock_destroy(&(*p)->file_lock);
        free((*p)->filename);
        fclose((*p)->file);
        free(*p);
        return false;
    }

    // Set the write count to 0
    (*p)->write_count = 0;

    // Set the stop sync thread flag to false
    (*p)->stop_sync_thread = false;

    // Start the sync thread
    if (pthread_create(&(*p)->sync_thread, NULL, pager_sync_thread, (void*)*p) != 0) {
        pthread_cond_destroy(&(*p)->sync_cond);
        pthread_mutex_destroy(&(*p)->sync_mutex);
        for (unsigned int i = 0; i < page_count; i++) {
            pthread_rwlock_destroy(&(*p)->page_locks[i]);
        }
        free((*p)->page_locks);
        pthread_rwlock_destroy(&(*p)->file_lock);
        free((*p)->filename);
        fclose((*p)->file);
        free(*p);
        return false;
    }

    return true;
}

bool pager_close(pager* p) {
    // We check if the pager is NULL
    if (p == NULL) {
        return false;
    }

    // We close the file
    if (fclose(p->file) != 0) {
        return false;
    }

    // We destroy the file lock
    if (pthread_rwlock_destroy(&p->file_lock) != 0) {
        return false;
    }

    // We destroy the page locks
    for (unsigned int i = 0; i < p->num_pages; i++) {
        if (pthread_rwlock_destroy(&p->page_locks[i]) != 0) {
            return false;
        }
    }

    // We free the page locks
    free(p->page_locks);

    // We set the stop sync thread flag to true
    p->stop_sync_thread = true;

    // We join the sync thread
    if (pthread_join(p->sync_thread, NULL) != 0) {
        return false;
    }

    // We destroy the sync mutex
    if (pthread_mutex_destroy(&p->sync_mutex) != 0) {
        printf("f\n");
        return false;
    }

    // We destroy the sync condition variable
    if (pthread_cond_destroy(&p->sync_cond) != 0) {
        return false;
    }

    // We free the pager
    free(p);

    return true;
}

bool pager_write(pager* p, uint8_t* data, size_t data_len, unsigned int* init_page_number) {
    if (!p || !p->file || !p->page_locks || !data || data_len == 0) {
        return false;
    }

    size_t pages_needed = (data_len + PAGE_BODY - 1) / PAGE_BODY;
    size_t remaining_data = data_len;
    uint8_t buffer[PAGE_SIZE];
    size_t offset = 0;

    long page_number = p->num_pages;  // Start from the current number of pages
    long initial_page_number = page_number;

    pthread_rwlock_wrlock(&p->file_lock);  // Lock the file for writing

    for (size_t i = 0; i < pages_needed; ++i) {
        if (page_number >= (long)p->num_pages) {
            // Allocate more locks if needed
            pthread_rwlock_t* new_locks = (pthread_rwlock_t*)realloc(
                p->page_locks, (p->num_pages + 1) * sizeof(pthread_rwlock_t));
            if (new_locks == NULL) {
                pthread_rwlock_unlock(&p->file_lock);
                return false;
            }
            p->page_locks = new_locks;
            if (pthread_rwlock_init(&p->page_locks[p->num_pages], NULL) != 0) {
                pthread_rwlock_unlock(&p->file_lock);

                return false;
            }
            p->num_pages++;
        }

        size_t chunk_size = remaining_data > PAGE_BODY ? PAGE_BODY : remaining_data;
        memset(buffer, 0, PAGE_SIZE);

        if (i < pages_needed - 1) {
            long next_page_number = page_number + 1;
            memcpy(buffer, &next_page_number, sizeof(next_page_number));
        } else {
            long no_overflow = -1;
            memcpy(buffer, &no_overflow, sizeof(no_overflow));
            // Include the actual data length in the last page header
            memcpy(buffer + sizeof(long), &data_len, sizeof(data_len));
        }

        // Pad the header to PAGE_HEADER size
        memset(buffer + sizeof(long) + sizeof(data_len), 0,
               PAGE_HEADER - sizeof(long) - sizeof(data_len));

        // Copy the data chunk to the body and pad if necessary
        memcpy(buffer + PAGE_HEADER, data + offset, chunk_size);
        if (chunk_size < PAGE_BODY) {
            memset(buffer + PAGE_HEADER + chunk_size, 0, PAGE_BODY - chunk_size);
        }

        offset += chunk_size;
        remaining_data -= chunk_size;

        pthread_rwlock_wrlock(&p->page_locks[page_number]);
        if (fseek(p->file, page_number * PAGE_SIZE, SEEK_SET) != 0 ||
            fwrite(buffer, 1, PAGE_SIZE, p->file) != PAGE_SIZE) {
            pthread_rwlock_unlock(&p->page_locks[page_number]);
            pthread_rwlock_unlock(&p->file_lock);

            return false;
        }
        pthread_rwlock_unlock(&p->page_locks[page_number]);

        page_number++;
    }

    pthread_mutex_lock(&p->sync_mutex);
    p->write_count++;
    if (p->write_count >= SYNC_INTERVAL) {
        pthread_cond_signal(&p->sync_cond);
    }
    pthread_mutex_unlock(&p->sync_mutex);

    pthread_rwlock_unlock(&p->file_lock);  // Unlock the file

    *init_page_number = initial_page_number;  // Set the initial page number

    return true;
}

bool pager_read(pager* p, unsigned int start_page_number, uint8_t** buffer, size_t* buffer_len) {
    if (!p || !p->file || !p->page_locks || !buffer || !buffer_len) {
        return false;
    }

    size_t offset = 0;
    uint8_t page_buffer[PAGE_SIZE];
    long page_number = start_page_number;
    size_t actual_data_len = 0;

    while (1) {
        pthread_rwlock_rdlock(&p->page_locks[page_number]);
        if (fseek(p->file, page_number * PAGE_SIZE, SEEK_SET) != 0) {
            pthread_rwlock_unlock(&p->page_locks[page_number]);
            return false;
        }

        if (fread(page_buffer, 1, PAGE_SIZE, p->file) != PAGE_SIZE) {
            pthread_rwlock_unlock(&p->page_locks[page_number]);
            return false;
        }
        pthread_rwlock_unlock(&p->page_locks[page_number]);

        long next_page_number;
        memcpy(&next_page_number, page_buffer, sizeof(next_page_number));

        size_t chunk_size = PAGE_SIZE - PAGE_HEADER;
        *buffer_len = offset + chunk_size;
        uint8_t* new_buffer = (uint8_t*)realloc(*buffer, *buffer_len);
        if (new_buffer == NULL) {
            free(*buffer);
            return false;
        }
        *buffer = new_buffer;

        memcpy(*buffer + offset, page_buffer + PAGE_HEADER, chunk_size);
        offset += chunk_size;

        if (next_page_number == -1) {
            // Retrieve the actual data length from the last page header
            memcpy(&actual_data_len, page_buffer + sizeof(long), sizeof(actual_data_len));
            break;
        }

        page_number = next_page_number;
    }

    // Adjust buffer length to the actual data length
    *buffer_len = actual_data_len;

    return true;
}

bool pager_cursor_init(pager* p, pager_cursor** cursor) {
    if (!p) {
        return false;
    }

    // Allocate memory for the cursor
    *cursor = (pager_cursor*)malloc(sizeof(pager_cursor));
    if (!cursor) {
        return false;
    }

    // Set the pager
    (*cursor)->pager = p;

    // Set the initial page number
    (*cursor)->page_number = 0;

    return true;
}

bool pager_cursor_next(pager_cursor* cursor) {
    if (!cursor || !cursor->pager) {
        return false;
    }

    while (cursor->page_number < (long)cursor->pager->num_pages - 1) {
        cursor->page_number++;
        uint8_t page_buffer[PAGE_SIZE];
        pthread_rwlock_rdlock(&cursor->pager->page_locks[cursor->page_number]);
        if (fseek(cursor->pager->file, cursor->page_number * PAGE_SIZE, SEEK_SET) != 0) {
            pthread_rwlock_unlock(&cursor->pager->page_locks[cursor->page_number]);
            return false;
        }
        if (fread(page_buffer, 1, PAGE_SIZE, cursor->pager->file) != PAGE_SIZE) {
            pthread_rwlock_unlock(&cursor->pager->page_locks[cursor->page_number]);
            return false;
        }
        pthread_rwlock_unlock(&cursor->pager->page_locks[cursor->page_number]);

        long next_page_number;
        memcpy(&next_page_number, page_buffer, sizeof(next_page_number));
        if (next_page_number == -1) {
            return true;  // Found a non-overflow page
        }
    }

    return false;
}

bool pager_cursor_prev(pager_cursor* cursor) {
    if (!cursor || !cursor->pager) {
        return false;
    }

    while (cursor->page_number > 0) {
        cursor->page_number--;
        uint8_t page_buffer[PAGE_SIZE];
        pthread_rwlock_rdlock(&cursor->pager->page_locks[cursor->page_number]);
        if (fseek(cursor->pager->file, cursor->page_number * PAGE_SIZE, SEEK_SET) != 0) {
            pthread_rwlock_unlock(&cursor->pager->page_locks[cursor->page_number]);
            return false;
        }
        if (fread(page_buffer, 1, PAGE_SIZE, cursor->pager->file) != PAGE_SIZE) {
            pthread_rwlock_unlock(&cursor->pager->page_locks[cursor->page_number]);
            return false;
        }
        pthread_rwlock_unlock(&cursor->pager->page_locks[cursor->page_number]);

        long next_page_number;
        memcpy(&next_page_number, page_buffer, sizeof(next_page_number));
        if (next_page_number == -1) {
            return true;  // Found a non-overflow page
        }
    }

    return false;
}

bool pager_cursor_get(pager_cursor* cursor, unsigned int* page_number) {
    if (!cursor || !cursor->pager || !page_number) {
        return false;
    }

    *page_number = cursor->page_number;

    return true;
}

time_t get_last_modified(const char* filename) {
    struct stat file_stat;
    if (stat(filename, &file_stat) != 0) {
        return -1;
    }

    return file_stat.st_mtime;
}

void pager_cursor_free(pager_cursor* cursor) {
    if (cursor) {
        free(cursor);
    }
}

bool pager_truncate(pager* p, size_t size) {
    if (!p || !p->file) {
        return false;
    }

    if (ftruncate(fileno(p->file), size) != 0) {
        return false;
    }

    return true;
}

bool pager_pages_count(pager* p, size_t* num_pages) {
    if (!p || !p->file || !num_pages) {
        return false;
    }

    struct stat file_stat;
    if (fstat(fileno(p->file), &file_stat) != 0) {
        return false;
    }

    *num_pages = (file_stat.st_size + PAGE_SIZE - 1) / PAGE_SIZE;

    return true;
}

bool pager_size(pager* p, size_t* size) {
    if (!p || !p->file || !size) {
        return false;
    }

    struct stat file_stat;
    if (fstat(fileno(p->file), &file_stat) != 0) {
        return false;
    }

    *size = file_stat.st_size;

    return true;
}

void* pager_sync_thread(void* arg) {
    pager* p = (pager*)arg;
    struct timespec ts;
    while (1) {
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            break;
        }
        ts.tv_sec += SYNC_ESCALATION;

        pthread_mutex_lock(&p->sync_mutex);
        while (p->write_count < SYNC_INTERVAL && !p->stop_sync_thread) {
            int wait_result = pthread_cond_timedwait(&p->sync_cond, &p->sync_mutex, &ts);
            if (wait_result == ETIMEDOUT) {
                break;
            }
        }
        if (p->stop_sync_thread) {
            pthread_mutex_unlock(&p->sync_mutex);
            break;
        }
        p->write_count = 0;
        pthread_mutex_unlock(&p->sync_mutex);

        fflush(p->file);
        fsync(fileno(p->file));
    }
    return NULL;
}