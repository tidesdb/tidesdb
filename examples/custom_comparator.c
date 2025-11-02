/*
 * demonstrates how to create and register a custom comparator
 * that can be used with TidesDB column families.
 *
 * to use
 * 1. add this file to your tidesdb directory
 * 2. include it in your build
 * 3. register the comparator before creating column families
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * reverse order comparator
 * sorts keys in reverse order (largest to smallest)
 */
int reverse_comparator(const uint8_t *key1, size_t key1_size, const uint8_t *key2, size_t key2_size,
                       void *ctx)
{
    (void)ctx; /* unused */

    /* compare using memcmp but reverse the result */
    size_t min_size = key1_size < key2_size ? key1_size : key2_size;
    int result = memcmp(key1, key2, min_size);

    if (result != 0) return -result; /* reverse */

    /* if prefixes match, shorter key comes after longer key (reversed) */
    if (key1_size < key2_size) return 1;
    if (key1_size > key2_size) return -1;
    return 0;
}

/*
 * case-insensitive string comparator
 * compares strings ignoring case
 */
int case_insensitive_comparator(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                                size_t key2_size, void *ctx)
{
    (void)ctx; /* unused */

    size_t min_size = key1_size < key2_size ? key1_size : key2_size;

    for (size_t i = 0; i < min_size; i++)
    {
        unsigned char c1 = key1[i];
        unsigned char c2 = key2[i];

        /* convert to lowercase */
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;

        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
    }

    /* prefixes match, compare lengths */
    if (key1_size < key2_size) return -1;
    if (key1_size > key2_size) return 1;
    return 0;
}

/*
 * timestamp comparator (for uint64_t timestamps)
 * assumes keys are 8-byte big-endian timestamps
 */
int timestamp_comparator(const uint8_t *key1, size_t key1_size, const uint8_t *key2,
                         size_t key2_size, void *ctx)
{
    (void)ctx; /* unused */

    if (key1_size != 8 || key2_size != 8)
    {
        /* fall back to memcmp for invalid sizes */
        return memcmp(key1, key2, key1_size < key2_size ? key1_size : key2_size);
    }

    /* read as big-endian uint64_t */
    uint64_t ts1 = 0, ts2 = 0;
    for (int i = 0; i < 8; i++)
    {
        ts1 = (ts1 << 8) | key1[i];
        ts2 = (ts2 << 8) | key2[i];
    }

    if (ts1 < ts2) return -1;
    if (ts1 > ts2) return 1;
    return 0;
}

/*
 * example ****
 *
 * #include "tidesdb.h"
 *
 * // declare your comparator (from this file)
 * extern int reverse_comparator(const uint8_t*, size_t, const uint8_t*, size_t, void*);
 * extern int case_insensitive_comparator(const uint8_t*, size_t, const uint8_t*, size_t, void*);
 * extern int timestamp_comparator(const uint8_t*, size_t, const uint8_t*, size_t, void*);
 *
 * int main() {
 *     // register your custom comparators at startup
 *     tidesdb_register_comparator("reverse", reverse_comparator);
 *     tidesdb_register_comparator("case_insensitive", case_insensitive_comparator);
 *     tidesdb_register_comparator("timestamp", timestamp_comparator);
 *
 *     // open database
 *     tidesdb_config_t config = {.db_path = "./mydb"};
 *     tidesdb_t *db;
 *     tidesdb_open(&config, &db);
 *
 *     // create column family with custom comparator
 *     tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
 *     cf_config.comparator_name = "reverse";  // Use your registered comparator
 *     tidesdb_create_column_family(db, "my_cf", &cf_config);
 *
 *     // on reopen, just register the comparators again before opening
 *     // the column family will automatically use the registered comparator
 *
 *     return 0;
 * }
 */
