/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_SERIALIZATION_H__
#define __TIDESDB_BASE_SERIALIZATION_H__

#include "compat.h" /* fixed-width ints, memcpy, and decode_varint64_safe */

/* on-disk filename format for per-cf write-ahead logs, <id>.log */
#define TDB_WAL_EXT ".log"

/* the name a write-ahead log takes once its memtable has been flushed and the file is kept only
 * because an undecided prepare still lives in it. the data records in such a log are already
 * durable in L1, so a replay that applied them again would put versions a compaction may since
 * have retired back above the sstables, where every reader takes them as newer. the name is what
 * lets recovery tell that log apart from one a crash left behind, whose data is not durable
 * anywhere else and has to be replayed in full */
#define TDB_WAL_FLUSHED_EXT ".logf"

#define TDB_SSTABLE_KLOG_EXT ".klog"

/* the zero padding a key log name gives each of its two ids, chosen so the names of one database
 * sort in id order under an ordinary directory listing. the two widths differ because the two
 * cardinalities do -- a database holds families in the hundreds or thousands, while it draws a
 * fresh table id for every flush and every compaction output and never reuses one, so tables
 * accumulate for as long as it is written to. padding is presentation only. an id wider than its
 * field is written out in full and read back the same way, and loses nothing but its place in that
 * listing */
#define TDB_SSTABLE_CF_DIGITS 6
#define TDB_SSTABLE_ID_DIGITS 12

/* the widest any of these ids can be and still be a uint64_t, which bounds what a name may
 * present before it is decoded */
#define TDB_ID_MAX_DIGITS 20

/* upper bound on a key log name, taken against two ids at their full width rather than at their
 * padding, so it holds every name the format admits */
#define TDB_SSTABLE_KLOG_NAME_MAX 64

/* the suffix a btree leaf build stages under beside its key log; a file carrying it is one a
 * build was still writing, so it exists only where the process died mid-build */
#define TDB_SSTABLE_KLOG_STAGE_EXT ".lstmp"

/* size in bytes of the big-endian column-family index prepended to every memtable key */
#define TDB_CF_PREFIX_SIZE 4

/* the largest family id that prefix can carry. one shared memtable holds every family's keys and
 * the prefix is what separates them, so an id past this would be written truncated and land under
 * the prefix of whichever family it wrapped onto -- two families interleaved in one order, which no
 * later read could tell apart. family ids are drawn from a counter that never reuses one, so the
 * ceiling is on how many a database may ever create rather than on how many it holds */
#define TDB_CF_INDEX_MAX 0xFFFFFFFFull

/**
 * encode_varint
 * encode a uint64_t as a base-128 varint
 * @param buf output buffer, must have room for at least 10 bytes
 * @param value value to encode
 * @return number of bytes written
 */
static inline int encode_varint(uint8_t *buf, uint64_t value)
{
    int pos = 0;
    while (value >= 0x80)
    {
        buf[pos++] = (uint8_t)(value | 0x80);
        value >>= 7;
    }
    buf[pos++] = (uint8_t)value;
    return pos;
}

/**
 * decode_varint
 * decode a base-128 varint to a uint64_t within a byte bound
 * @param buf input buffer
 * @param value output value, always written (0 on failure)
 * @param max_bytes maximum bytes to read from buf
 * @return number of bytes read, or -1 on error
 */
static inline int decode_varint(const uint8_t *buf, uint64_t *value, const int max_bytes)
{
    /* thin adapter over the canonical bounded decoder in compat.h that keeps this call site's
     * byte-count bound and bytes-read return. the guard keeps buf + max_bytes well-defined. always
     * write *value (0 on failure) so a trusted caller that does not check the return -- the klog
     * block reads on data the engine itself wrote -- still reads a defined value, matching the
     * original decoder which wrote *value on every path. */
    *value = 0;
    if (TDB_UNLIKELY(max_bytes <= 0)) return -1;
    const uint8_t *next = decode_varint64_safe(buf, buf + max_bytes, value);
    return next ? (int)(next - buf) : -1;
}

/**
 * tdb_encode_be32
 * encode a uint32_t as four big-endian bytes
 * @param val value to encode
 * @param out output buffer, must have room for 4 bytes
 */
static inline void tdb_encode_be32(const uint32_t val, uint8_t *out)
{
    out[0] = (uint8_t)(val >> 24);
    out[1] = (uint8_t)(val >> 16);
    out[2] = (uint8_t)(val >> 8);
    out[3] = (uint8_t)(val);
}

/**
 * tdb_decode_be32
 * decode four big-endian bytes to a uint32_t
 * @param p input buffer, must hold at least 4 bytes
 * @return the decoded value
 */
static inline uint32_t tdb_decode_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/**
 * tdb_encode_be64
 * encode a uint64_t as eight big-endian bytes
 * @param val value to encode
 * @param out output buffer, must have room for 8 bytes
 */
static inline void tdb_encode_be64(const uint64_t val, uint8_t *out)
{
    out[0] = (uint8_t)(val >> 56);
    out[1] = (uint8_t)(val >> 48);
    out[2] = (uint8_t)(val >> 40);
    out[3] = (uint8_t)(val >> 32);
    out[4] = (uint8_t)(val >> 24);
    out[5] = (uint8_t)(val >> 16);
    out[6] = (uint8_t)(val >> 8);
    out[7] = (uint8_t)(val);
}

/**
 * tdb_decode_be64
 * decode eight big-endian bytes to a uint64_t
 * @param p input buffer, must hold at least 8 bytes
 * @return the decoded value
 */
static inline uint64_t tdb_decode_be64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

/**
 * tdb_build_prefixed_key
 * prepend the big-endian cf index to a key, producing a memtable key
 * @param cf_index column-family index to encode as the prefix
 * @param key source key bytes
 * @param key_size source key length
 * @param out output buffer, must have room for TDB_CF_PREFIX_SIZE + key_size bytes
 * @return total bytes written to out
 */
static inline size_t tdb_build_prefixed_key(const uint32_t cf_index, const uint8_t *key,
                                            const size_t key_size, uint8_t *out)
{
    tdb_encode_be32(cf_index, out);
    /* a bare family prefix is a legitimate key here -- it names where a family begins, which is
     * what an interval left open inside the family before it uses as its upper bound. memcpy
     * declares both pointers non-null whatever the length, so the copy is guarded rather than every
     * such caller made to pass a pointer it does not have */
    if (key_size) memcpy(out + TDB_CF_PREFIX_SIZE, key, key_size);
    return TDB_CF_PREFIX_SIZE + key_size;
}

#endif /* __TIDESDB_BASE_SERIALIZATION_H__ */
