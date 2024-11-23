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

#include "../src/pager.h"
#include "test_macros.h"

void test_pager_open_close() {
    pager* p = NULL;

    assert(pager_open("test.db", &p) == true);

    assert(p != NULL);

    assert(pager_close(p) == true);

    remove("test.db");

    printf(GREEN "test_pager_open_close passed\n" RESET);
}

void test_pager_write_read() {
    pager* p = NULL;

    assert(pager_open("test.db", &p) == true);
    assert(p != NULL);

    unsigned char key[] = "key";
    unsigned int key_size = sizeof(key);
    unsigned int page_num = 0;

    assert(pager_write(p, key, key_size, &page_num) == true);

    unsigned char* read_key = NULL;
    size_t read_key_size = 0;

    assert(pager_read(p, page_num, &read_key, &read_key_size) == true);
    assert(memcmp(key, read_key, key_size) == 0);

    free(read_key);
    assert(pager_close(p) == true);

    remove("test.db");

    printf(GREEN "test_pager_write_read passed\n" RESET);
}

void test_pager_write_reopen_read() {
    pager* p = NULL;

    assert(pager_open("test.db", &p) == true);
    assert(p != NULL);

    unsigned char key[] = "key";
    unsigned int key_size = sizeof(key);
    unsigned int page_num = 0;

    assert(pager_write(p, key, key_size, &page_num) == true);

    unsigned char key2[] = "key2";
    unsigned int key_size2 = sizeof(key2);
    unsigned int page_num2 = 0;

    assert(pager_write(p, key2, key_size2, &page_num2) == true);

    unsigned char* read_key = NULL;
    size_t read_key_size = 0;

    assert(pager_read(p, page_num2, &read_key, &read_key_size) == true);
    assert(memcmp(key2, read_key, key_size2) == 0);

    free(read_key);
    assert(pager_close(p) == true);

    p = NULL;

    // reopen
    assert(pager_open("test.db", &p) == true);

    unsigned char* read_key2 = NULL;
    size_t read_key_size2 = 0;

    assert(pager_read(p, page_num2, &read_key2, &read_key_size2) == true);

    assert(memcmp(key2, read_key2, key_size2) == 0);

    // cleanup
    free(read_key2);
    assert(pager_close(p) == true);

    remove("test.db");

    printf(GREEN "test_pager_write_read passed\n" RESET);
}

void test_pager_overflowed_write_read() {
    pager* p = NULL;

    assert(pager_open("test.db", &p) == true);
    assert(p != NULL);

    unsigned char value[] =
        "In the realm of the dark, where silence reigns, A world unseen by eyes, where logic "
        "remains. A whispering hum in the wires and boards, Where every signal is a tale that "
        "accords. It starts with a flicker, a pulse, a shift, In the lowest of levels, a binary "
        "drift. Ones and zeroes, they twirl and they glide, In this microscopic world, they "
        "reside. They’re small, so small, they break all the rules, The tiniest dancers, the "
        "builders, the tools. A single bit, though small in its might, Holds the key to the "
        "cosmos, to day and to night. The ones are the fire, the truth, the light, The zeros are "
        "shadows, they hide out of sight. But together they balance, they form a great whole, A "
        "language of logic, they speak to the soul. In registers quiet, in memory deep, The bits "
        "lie in silence, they never do sleep. They shift and they shuffle, they weave and they "
        "turn, Through circuits and gates, they endlessly churn. The world of the low, where the "
        "bits take their stand, In every operation, they obey command. An adder or shifter, a "
        "logic gate’s call, It’s the bits that decide, they control it all. When two are combined, "
        "what wonders they make, A carry bit travels, decisions they stake. The one is the first, "
        "the zero is last, Together they form a binary blast. The most intricate dance of the "
        "smallest of parts, With zero and one, they play their own arts. To you, they are numbers, "
        "mere logic, or code, But to them, it’s a rhythm, an infinite road. Every byte a puzzle, "
        "every nibble a key, A perfect foundation of what you can see. They rise in alignment, in "
        "perfect display, A string of eight bits, they hold what you say. The float and the "
        "double, the sign and the scale, In the deep, silent dark, where no signal can fail. They "
        "float through the air, they dance on the breeze, The low-level bits are the ones with the "
        "keys. In assembler, in machine, they march with great pride, With registers ready, they "
        "never will hide. They multiply, they divide, they reach and they fall, In the land of the "
        "low bits, they answer the call. And as you type out a letter, a word, a phrase, Know the "
        "bits beneath it are silently ablaze. Each pixel a bit, each sound a byte, The low-level "
        "dancers make everything right. Oh, humble bits, in your tiny domain, You’re the pulse of "
        "the system, the force of the brain. In the dark, in the quiet, you toil and you strive, "
        "It’s in your small steps, the whole world’s alive. A flip, a jump, a pulse on the wire, "
        "In your silent march, you never tire. So here’s to the bits, the low and the small, In "
        "the depths of the system, they control it all.";
    unsigned int value_size = sizeof(value);
    unsigned int page_num = 0;

    assert(pager_write(p, value, value_size, &page_num) == true);

    unsigned char* read_value = NULL;
    size_t read_value_size = 0;

    assert(pager_read(p, page_num, &read_value, &read_value_size) == true);
    assert(memcmp(value, read_value, value_size) == 0);

    free(read_value);
    assert(pager_close(p) == true);

    remove("test.db");

    printf(GREEN "test_pager_overflowed_write_read passed\n" RESET);
}

void test_pager_cursor() {
    // we write an overflowed page and a normal page
    // the cursor skips overflow pages
    pager* p = NULL;

    assert(pager_open("test.db", &p) == true);
    assert(p != NULL);

    unsigned char value[] =
        "In the realm of the dark, where silence reigns, A world unseen by eyes, where logic "
        "remains. A whispering hum in the wires and boards, Where every signal is a tale that "
        "accords. It starts with a flicker, a pulse, a shift, In the lowest of levels, a binary "
        "drift. Ones and zeroes, they twirl and they glide, In this microscopic world, they "
        "reside. They’re small, so small, they break all the rules, The tiniest dancers, the "
        "builders, the tools. A single bit, though small in its might, Holds the key to the "
        "cosmos, to day and to night. The ones are the fire, the truth, the light, The zeros are "
        "shadows, they hide out of sight. But together they balance, they form a great whole, A "
        "language of logic, they speak to the soul. In registers quiet, in memory deep, The bits "
        "lie in silence, they never do sleep. They shift and they shuffle, they weave and they "
        "turn, Through circuits and gates, they endlessly churn. The world of the low, where the "
        "bits take their stand, In every operation, they obey command. An adder or shifter, a "
        "logic gate’s call, It’s the bits that decide, they control it all. When two are combined, "
        "what wonders they make, A carry bit travels, decisions they stake. The one is the first, "
        "the zero is last, Together they form a binary blast. The most intricate dance of the "
        "smallest of parts, With zero and one, they play their own arts. To you, they are numbers, "
        "mere logic, or code, But to them, it’s a rhythm, an infinite road. Every byte a puzzle, "
        "every nibble a key, A perfect foundation of what you can see. They rise in alignment, in "
        "perfect display, A string of eight bits, they hold what you say. The float and the "
        "double, the sign and the scale, In the deep, silent dark, where no signal can fail. They "
        "float through the air, they dance on the breeze, The low-level bits are the ones with the "
        "keys. In assembler, in machine, they march with great pride, With registers ready, they "
        "never will hide. They multiply, they divide, they reach and they fall, In the land of the "
        "low bits, they answer the call. And as you type out a letter, a word, a phrase, Know the "
        "bits beneath it are silently ablaze. Each pixel a bit, each sound a byte, The low-level "
        "dancers make everything right. Oh, humble bits, in your tiny domain, You’re the pulse of "
        "the system, the force of the brain. In the dark, in the quiet, you toil and you strive, "
        "It’s in your small steps, the whole world’s alive. A flip, a jump, a pulse on the wire, "
        "In your silent march, you never tire. So here’s to the bits, the low and the small, In "
        "the depths of the system, they control it all.";
    unsigned int value_size = sizeof(value);
    unsigned int page_num = 0;

    assert(pager_write(p, value, value_size, &page_num) == true);

    unsigned char value2[] = "value 2";
    unsigned int value_size2 = sizeof(value2);
    unsigned int page_num2 = 0;

    assert(pager_write(p, value2, value_size2, &page_num2) == true);

    pager_cursor* cursor = NULL;

    assert(pager_cursor_init(p, &cursor) == true);

    unsigned char* read_value = NULL;
    size_t read_value_size = 0;

    assert(pager_read(p, page_num, &read_value, &read_value_size) == true);

    assert(memcmp(value, read_value, value_size) == 0);

    free(read_value);
    read_value = NULL;
    read_value_size = 0;  // reset

    assert(pager_cursor_next(cursor) == true);

    assert(pager_read(p, page_num2, &read_value, &read_value_size) == true);

    assert(memcmp(value2, read_value, value_size2) == 0);

    free(read_value);

    pager_cursor_free(cursor);

    assert(pager_close(p) == true);

    remove("test.db");

    printf(GREEN "test_pager_cursor passed\n" RESET);
}

void test_pager_pages_count() {
    // we write many small values and count the pages
    pager* p = NULL;

    assert(pager_open("test.db", &p) == true);
    assert(p != NULL);

    for (int i = 0; i < 1000; i++) {
        unsigned char value[] = "value";
        unsigned int value_size = sizeof(value);
        unsigned int page_num = 0;

        assert(pager_write(p, value, value_size, &page_num) == true);
    }

    // we should have 999 pages
    size_t pages_count;

    assert(pager_pages_count(p, &pages_count) == true);

    assert(pages_count == 999);  // we should have 999 pages

    assert(pager_close(p) == true);

    remove("test.db");

    printf(GREEN "test_pager_pages_count passed\n" RESET);
}

void test_pager_pager_size() {
    // we write many small values and count the pages
    pager* p = NULL;

    assert(pager_open("test.db", &p) == true);
    assert(p != NULL);

    for (int i = 0; i < 1000; i++) {
        unsigned char value[] = "value";
        unsigned int value_size = sizeof(value);
        unsigned int page_num = 0;

        assert(pager_write(p, value, value_size, &page_num) == true);
    }

    // we should have PAGE_SIZE * 999
    size_t size;

    assert(pager_size(p, &size) == true);

    assert(size == PAGE_SIZE * 999);

    assert(pager_close(p) == true);

    remove("test.db");

    printf(GREEN "test_pager_pager_size passed\n" RESET);
}

void test_pager_truncate() {
    // we write many small values and count the pages
    pager* p = NULL;

    assert(pager_open("test.db", &p) == true);
    assert(p != NULL);

    for (int i = 0; i < 1000; i++) {
        unsigned char value[] = "value";
        unsigned int value_size = sizeof(value);
        unsigned int page_num = 0;

        assert(pager_write(p, value, value_size, &page_num) == true);
    }

    // we should have PAGE_SIZE * 999
    size_t size;

    assert(pager_size(p, &size) == true);

    assert(size == PAGE_SIZE * 999);

    // truncate to 0
    assert(pager_truncate(p, 0) == true);

    assert(pager_size(p, &size) == true);

    assert(size == 0);

    assert(pager_close(p) == true);

    remove("test.db");

    printf(GREEN "test_pager_truncate passed\n" RESET);
}

void test_get_last_modified() {
    const char* filename = "test_file.txt";
    FILE* file = fopen(filename, "w");
    assert(file != NULL);
    fclose(file);

    time_t mod_time = get_last_modified(filename);
    assert(mod_time != -1);

    struct stat file_stat;
    assert(stat(filename, &file_stat) == 0);
    assert(mod_time == file_stat.st_mtime);

    remove(filename);

    printf(GREEN "test_get_last_modified passed\n" RESET);
}

int main(void) {
    test_get_last_modified();
    test_pager_open_close();
    test_pager_write_read();
    test_pager_write_reopen_read();
    test_pager_overflowed_write_read();
    test_pager_cursor();
    test_pager_pages_count();
    test_pager_pager_size();
    test_pager_truncate();
    return 0;
}