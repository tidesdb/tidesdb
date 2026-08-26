/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_SERIALIZE_H__
#define __PLATFORM_SERIALIZE_H__

/* cross-platform little-endian serialization functions */
/*
 * encode_uint32_le_compat
 * encodes a uint32_t value in little-endian format
 * @param buf buffer to store encoded value
 * @param val value to encode
 */
static inline void encode_uint32_le_compat(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

/*
 * decode_uint32_le_compat
 * decodes a uint32_t value in little-endian format
 * @param buf buffer containing encoded value
 * @return decoded value
 */
static inline uint32_t decode_uint32_le_compat(const uint8_t *buf)
{
    return ((uint32_t)buf[0]) | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

/*
 * encode_uint64_le_compat
 * encodes a uint64_t value in little-endian format
 * @param buf buffer to store encoded value
 * @param val value to encode
 */
static inline void encode_uint64_le_compat(uint8_t *buf, uint64_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
    buf[4] = (uint8_t)((val >> 32) & 0xFF);
    buf[5] = (uint8_t)((val >> 40) & 0xFF);
    buf[6] = (uint8_t)((val >> 48) & 0xFF);
    buf[7] = (uint8_t)((val >> 56) & 0xFF);
}

/*
 * decode_uint64_le_compat
 * decodes a uint64_t value in little-endian format
 * @param buf buffer containing encoded value
 * @return decoded value
 */
static inline uint64_t decode_uint64_le_compat(const uint8_t *buf)
{
    return ((uint64_t)buf[0]) | ((uint64_t)buf[1] << 8) | ((uint64_t)buf[2] << 16) |
           ((uint64_t)buf[3] << 24) | ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
           ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
}

/**
 * encode_int64_le_compat
 * encodes a int64_t value in little-endian format
 * @param buf output buffer (must be at least 8 bytes)
 * @param val value to encode
 */
static inline void encode_int64_le_compat(uint8_t *buf, int64_t val)
{
    uint64_t uval = (uint64_t)val;
    buf[0] = (uint8_t)(uval);
    buf[1] = (uint8_t)(uval >> 8);
    buf[2] = (uint8_t)(uval >> 16);
    buf[3] = (uint8_t)(uval >> 24);
    buf[4] = (uint8_t)(uval >> 32);
    buf[5] = (uint8_t)(uval >> 40);
    buf[6] = (uint8_t)(uval >> 48);
    buf[7] = (uint8_t)(uval >> 56);
}

/**
 * decode_int64_le_compat
 * decodes a int64_t value in little-endian format
 * @param buf buffer containing encoded value
 * @return decoded value
 */
static inline int64_t decode_int64_le_compat(const uint8_t *buf)
{
    uint64_t uval = ((uint64_t)buf[0]) | ((uint64_t)buf[1] << 8) | ((uint64_t)buf[2] << 16) |
                    ((uint64_t)buf[3] << 24) | ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
                    ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
    return (int64_t)uval;
}
/* worst-case bytes for a LEB128 varint -- 7 data bits per byte, so ceil(64/7) = 10. this bounds
 * the parse loop in the bounded decoder below */
#define VARINT64_MAX_BYTES 10

/* bounded varint decoder -- reads at most the bytes a 64-bit value can occupy and never at or
 * past `end`. returns the pointer just past the decoded varint, or NULL on truncation (the buffer
 * ends mid-varint) or an overlong encoding with no terminator in the byte budget. this is the
 * canonical primitive for the parse-untrusted-bytes path, so a corrupt or truncated buffer cannot
 * drive an over-read */
static inline const uint8_t *decode_varint64_safe(const uint8_t *ptr, const uint8_t *end,
                                                  uint64_t *value)
{
    uint64_t result = 0;
    int shift = 0;
    for (int i = 0; i < VARINT64_MAX_BYTES; i++)
    {
        if (ptr >= end) return NULL;
        const uint8_t b = *ptr++;
        result |= (uint64_t)(b & 0x7Fu) << shift;
        if (!(b & 0x80u))
        {
            *value = result;
            return ptr;
        }
        shift += 7;
    }
    return NULL;
}

#endif /* __PLATFORM_SERIALIZE_H__ */
