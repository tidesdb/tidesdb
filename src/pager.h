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
#ifndef PAGER_H
#define PAGER_H

#define PAGE_HEADER 16L  // The page header is used to store an overflow page number
#define PAGE_BODY 1024   // The page body is used to store the actual data
#define PAGE_SIZE (PAGE_HEADER + PAGE_BODY)  // The page size is the sum of the header and body
#define SYNC_INTERVAL 24576                  // Sync every 24576 writes
#define SYNC_ESCALATION 2  // We sync when we hit sync escalation or when we hit sync interval

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/*
 * pager
 * the pager struct is used to manage the file and pages
 */
typedef struct {
    FILE* file;                  // the file the pager is assigned
    char* filename;              // the filename of the paged file
    pthread_rwlock_t file_lock;  // lock for the file (only one thread can write to file at a time)
    pthread_rwlock_t* page_locks;  // page locks for each page
    size_t num_pages;              // number of pages in file currently
    pthread_t sync_thread;         // background sync thread
    pthread_mutex_t sync_mutex;    // mutex for sync thread
    pthread_cond_t sync_cond;      // condition variable for sync thread
    size_t write_count;            // number of writes since last sync
    bool stop_sync_thread;         // flag to stop the sync thread
} pager;

/*
 * pager_cursor
 * the cursor struct is used to navigate the pages of the file
 */
typedef struct {
    pager* pager;              // the pager the cursor is assigned
    unsigned int page_number;  // the page number the cursor is currently on
} pager_cursor;

/* Pager function prototypes */

/*
 * pager_open
 * opens new pager with the given filename
 * will reopen the file if it already exists
 * @param filename the filename of the file to open
 * @return bool true if the pager was opened successfully, false otherwise
 */
bool pager_open(const char* filename, pager** p);

/*
 * pager_close
 * closes the pager and frees the memory
 * @param p the pager to close
 * @return bool true if the pager was closed successfully, false otherwise
 */
bool pager_close(pager* p);

/*
 * pager_write
 * writes a new page to file
 * if the data exceeds page body size overflows into next page(s)
 * @param p the pager to write to
 * @param data the data to write
 * @param data_len the length of the data
 * @param init_page_number the page number of the page written
 * @return bool true if the write was successful, false otherwise
 */
bool pager_write(pager* p, uint8_t* data, size_t data_len, unsigned int* init_page_number);

/*
 * pager_read
 * reads a page from file will gather overflowed data from next page(s)
 * @param p the pager to read from
 * @param start_page_number the page number to start reading from
 * @param buffer the buffer to read into
 * @param buffer_len the length of the buffer
 * @return bool true if the read was successful, false otherwise
 */
bool pager_read(pager* p, unsigned int start_page_number, uint8_t** buffer, size_t* buffer_len);

/*
 * pager_cursor_init
 * initializes a new cursor for the pager
 * @param p the pager to create the cursor for
 * @param cursor the cursor to initialize
 * @return bool true if the cursor was initialized successfully, false otherwise
 */
bool pager_cursor_init(pager* p, pager_cursor** cursor);

/*
 * pager_cursor_next
 * moves the cursor to the next page
 * @param cursor the cursor to move
 * @return bool true if the cursor was moved successfully, false otherwise
 */
bool pager_cursor_next(pager_cursor* cursor);

/*
 * pager_cursor_prev
 * moves the cursor to the previous page
 * @param cursor the cursor to move
 * @return bool true if the cursor was moved successfully, false otherwise
 */
bool pager_cursor_prev(pager_cursor* cursor);

/*
 * pager_cursor_get
 * gets the current page number the cursor is on
 * @param cursor the cursor to get the page number from
 * @param page_number the page number the cursor is on
 * @return bool true if the page number was retrieved successfully, false otherwise
 */
bool pager_cursor_get(pager_cursor* cursor, unsigned int* page_number);

/*
 * get_last_modified
 * gets the last modified time of the file
 * @param filename the filename of the file
 * @return time_t the last modified time of the file
 */
time_t get_last_modified(const char* filename);

/*
 * pager_cursor_free
 * frees the memory for the cursor
 * @param cursor the cursor to free
 */
void pager_cursor_free(pager_cursor* cursor);

/*
 * pager_sync_thread
 * background thread to sync the file to disk
 * @param arg the pager to sync
 */
void* pager_sync_thread(void* arg);

/*
 * pager_truncate
 * truncates the file to the given size
 * @param p the pager to truncate
 * @param size the size to truncate the file to
 * @return bool true if the file was truncated successfully, false otherwise
 */
bool pager_truncate(pager* p, size_t size);

/*
 * pager_pages_count
 * returns the number of pages in the file
 * @param p the pager to get the number of pages from
 * @param num_pages the number of pages in the file
 * @return bool true if the number of pages was retrieved successfully, false otherwise
 */
bool pager_pages_count(pager* p, size_t* num_pages);

/*
 * pager_size
 * returns the size of the file
 * @param p the pager to get the size from
 * @param size the size of the file
 * @return bool true if the size was retrieved successfully, false otherwise
 */
bool pager_size(pager* p, size_t* size);

#endif  // PAGER_H
