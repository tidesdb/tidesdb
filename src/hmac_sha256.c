/**
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
#include "hmac_sha256.h"

/* zero a buffer so the compiler cannot elide the write as a dead store. writes through a volatile
 * lvalue are observable side effects the standard requires to happen, which is the portable way to
 * wipe secret material without depending on explicit_bzero (absent on macOS) or SecureZeroMemory.
 */
static void hmac_secure_zero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

void hmac_sha256(const void *key, const size_t key_len, const void *data, const size_t data_len,
                 uint8_t out[HMAC_SHA256_DIGEST_SIZE])
{
    uint8_t k_block[SHA256_BLOCK_SIZE];
    uint8_t ipad[SHA256_BLOCK_SIZE];
    uint8_t opad[SHA256_BLOCK_SIZE];
    uint8_t inner[SHA256_DIGEST_SIZE];
    sha256_ctx ctx;

    /* keys longer than the block size are replaced by their hash; shorter keys are zero-padded */
    memset(k_block, 0, sizeof(k_block));
    if (key_len > SHA256_BLOCK_SIZE)
        sha256_hash(key, key_len, k_block);
    else
        memcpy(k_block, key, key_len);

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        ipad[i] = (uint8_t)(k_block[i] ^ 0x36);
        opad[i] = (uint8_t)(k_block[i] ^ 0x5c);
    }

    /* inner = H(ipad || data) */
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, sizeof(ipad));
    sha256_update(&ctx, (const uint8_t *)data, data_len);
    sha256_final(&ctx, inner);

    /* out = H(opad || inner) */
    sha256_init(&ctx);
    sha256_update(&ctx, opad, sizeof(opad));
    sha256_update(&ctx, inner, sizeof(inner));
    sha256_final(&ctx, out);

    /* wipe the key-derived material from the stack -- k_block holds the (padded) secret key and the
     * pads hold it xored with a constant, so leaving them behind would expose the signing key to a
     * later stack read. out is the caller's result and is left intact. */
    hmac_secure_zero(k_block, sizeof(k_block));
    hmac_secure_zero(ipad, sizeof(ipad));
    hmac_secure_zero(opad, sizeof(opad));
}
