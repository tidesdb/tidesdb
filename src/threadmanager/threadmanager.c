/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "threadmanager.h"

#include <stdlib.h>
#include <string.h>

/* initial process-array capacity, grown by doubling as more processes register */
#define THREADMANAGER_INITIAL_CAP 16

/**
 * threadmanager
 * an ordered set of labeled background processes the engine owns
 * @param procs dynamic array of registered processes in registration order
 * @param count number of registered processes
 * @param capacity allocated length of procs
 */
struct threadmanager
{
    threadmanager_proc_t *procs;
    int count;
    int capacity;
};

threadmanager_t *threadmanager_new(void)
{
    threadmanager_t *reg = calloc(1, sizeof(*reg));
    return reg;
}

/* reserve and return the next entry slot with its label filled in; the caller sets kind and handle
 * and bumps count. returns NULL on bad args or allocation failure. */
static threadmanager_proc_t *threadmanager_reserve(threadmanager_t *reg, const char *label)
{
    if (!reg || !label) return NULL;
    if (reg->count >= reg->capacity)
    {
        const int new_capacity = reg->capacity ? reg->capacity * 2 : THREADMANAGER_INITIAL_CAP;
        threadmanager_proc_t *grown = realloc(reg->procs, (size_t)new_capacity * sizeof(*grown));
        if (!grown) return NULL;
        reg->procs = grown;
        reg->capacity = new_capacity;
    }
    threadmanager_proc_t *entry = &reg->procs[reg->count];
    strncpy(entry->label, label, THREADMANAGER_LABEL_MAX - 1);
    entry->label[THREADMANAGER_LABEL_MAX - 1] = '\0';
    return entry;
}

int threadmanager_add_pool(threadmanager_t *reg, const char *label, bg_pool_t *pool)
{
    if (!pool) return -1;
    threadmanager_proc_t *entry = threadmanager_reserve(reg, label);
    if (!entry) return -1;
    entry->kind = THREADMANAGER_POOL;
    entry->handle.pool = pool;
    reg->count++;
    return 0;
}

int threadmanager_add_ticker(threadmanager_t *reg, const char *label, bg_ticker_t *ticker)
{
    if (!ticker) return -1;
    threadmanager_proc_t *entry = threadmanager_reserve(reg, label);
    if (!entry) return -1;
    entry->kind = THREADMANAGER_TICKER;
    entry->handle.ticker = ticker;
    reg->count++;
    return 0;
}

void threadmanager_wake(threadmanager_t *reg, const char *label)
{
    if (!reg || !label) return;
    for (int i = 0; i < reg->count; i++)
    {
        if (reg->procs[i].kind == THREADMANAGER_TICKER && strcmp(reg->procs[i].label, label) == 0)
            bg_ticker_wake(reg->procs[i].handle.ticker);
    }
}

int threadmanager_count(const threadmanager_t *reg)
{
    return reg ? reg->count : 0;
}

const threadmanager_proc_t *threadmanager_at(const threadmanager_t *reg, int index)
{
    if (!reg || index < 0 || index >= reg->count) return NULL;
    return &reg->procs[index];
}

int threadmanager_stop(threadmanager_t *reg, const char *label)
{
    if (!reg || !label) return -1;
    for (int i = 0; i < reg->count; i++)
    {
        if (strcmp(reg->procs[i].label, label) != 0) continue;
        if (reg->procs[i].kind == THREADMANAGER_POOL)
            bg_pool_stop(reg->procs[i].handle.pool);
        else
            bg_ticker_stop(reg->procs[i].handle.ticker);
        /* remove the entry so stop_all does not touch it again, preserving order for the rest */
        for (int j = i; j < reg->count - 1; j++) reg->procs[j] = reg->procs[j + 1];
        reg->count--;
        return 0;
    }
    return -1;
}

void threadmanager_stop_all(threadmanager_t *reg)
{
    if (!reg) return;
    /* stop in reverse registration order so later-started processes tear down before earlier ones
     */
    for (int i = reg->count - 1; i >= 0; i--)
    {
        if (reg->procs[i].kind == THREADMANAGER_POOL)
            bg_pool_stop(reg->procs[i].handle.pool);
        else
            bg_ticker_stop(reg->procs[i].handle.ticker);
    }
    free(reg->procs);
    free(reg);
}
