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
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/queue.h"
#include "test_macros.h"

void test_queue_new()
{
    queue *q = queue_new();
    assert(q != NULL);
    assert(q->head == NULL);
    assert(q->tail == NULL);
    assert(q->size == 0);
    queue_destroy(q);

    printf(GREEN "test_queue_new passed\n" RESET);
}

void test_queue_enqueue_dequeue()
{
    queue *q = queue_new();
    int data1 = 1, data2 = 2, data3 = 3;

    assert(queue_enqueue(q, &data1) == true);
    assert(queue_enqueue(q, &data2) == true);
    assert(queue_enqueue(q, &data3) == true);

    assert(queue_size(q) == 3);

    int *dequeued_data;
    dequeued_data = (int *)queue_dequeue(q);
    assert(dequeued_data != NULL && *dequeued_data == data1);

    dequeued_data = (int *)queue_dequeue(q);
    assert(dequeued_data != NULL && *dequeued_data == data2);

    dequeued_data = (int *)queue_dequeue(q);
    assert(dequeued_data != NULL && *dequeued_data == data3);

    assert(queue_size(q) == 0);

    queue_destroy(q);

    printf(GREEN "test_queue_enqueue_dequeue passed\n" RESET);
}

void test_queue_size()
{
    queue *q = queue_new();
    int data1 = 1, data2 = 2;

    assert(queue_size(q) == 0);

    queue_enqueue(q, &data1);
    assert(queue_size(q) == 1);

    queue_enqueue(q, &data2);
    assert(queue_size(q) == 2);

    queue_dequeue(q);
    assert(queue_size(q) == 1);

    queue_dequeue(q);
    assert(queue_size(q) == 0);

    queue_destroy(q);

    printf(GREEN "test_queue_size passed\n" RESET);
}

void test_queue_destroy()
{
    queue *q = queue_new();
    int data1 = 1, data2 = 2;

    queue_enqueue(q, &data1);
    queue_enqueue(q, &data2);

    queue_destroy(q);

    printf(GREEN "test_queue_destroy passed\n" RESET);
}

void test_dequeue_no_entries()
{
    queue *q = queue_new();
    assert(queue_dequeue(q) == NULL);
    queue_destroy(q);

    printf(GREEN "test_dequeue_no_entries passed\n" RESET);
}

/** OR cc -g3 -fsanitize=address,undefined src/*.c external/*.c test/queue__tests.c -lzstd **/
int main(void)
{
    test_queue_new();
    test_queue_enqueue_dequeue();
    test_queue_size();
    test_queue_destroy();
    test_dequeue_no_entries();
    return 0;
}