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

#include "../src/hmac_sha256.h"
#include "../src/sha256.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

static void to_hex(const uint8_t *d, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++)
    {
        out[i * 2] = h[d[i] >> 4];
        out[i * 2 + 1] = h[d[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

/* compute HMAC and assert its hex matches expected. cmp_len lets the truncated RFC case check a
 * prefix of the MAC. */
static void check_hmac(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                       const char *expect_hex, size_t cmp_bytes)
{
    uint8_t mac[HMAC_SHA256_DIGEST_SIZE];
    hmac_sha256(key, key_len, data, data_len, mac);
    char hex[HMAC_SHA256_DIGEST_SIZE * 2 + 1];
    to_hex(mac, cmp_bytes, hex);
    ASSERT_EQ(strncmp(hex, expect_hex, cmp_bytes * 2), 0);
}

/* RFC 4231 Test Case 1 */
static void test_hmac_rfc4231_case1(void)
{
    uint8_t key[20];
    memset(key, 0x0b, sizeof(key));
    check_hmac(key, sizeof(key), (const uint8_t *)"Hi There", 8,
               "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 32);
}

/* RFC 4231 Test Case 2 -- short ASCII key */
static void test_hmac_rfc4231_case2(void)
{
    check_hmac((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28,
               "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32);
}

/* RFC 4231 Test Case 3 -- 0xdd data */
static void test_hmac_rfc4231_case3(void)
{
    uint8_t key[20], data[50];
    memset(key, 0xaa, sizeof(key));
    memset(data, 0xdd, sizeof(data));
    check_hmac(key, sizeof(key), data, sizeof(data),
               "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", 32);
}

/* RFC 4231 Test Case 4 -- 0xcd data, 25-byte key */
static void test_hmac_rfc4231_case4(void)
{
    uint8_t key[25], data[50];
    for (int i = 0; i < 25; i++) key[i] = (uint8_t)(i + 1);
    memset(data, 0xcd, sizeof(data));
    check_hmac(key, sizeof(key), data, sizeof(data),
               "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", 32);
}

/* RFC 4231 Test Case 5 -- 128-bit truncation (compare first 16 bytes) */
static void test_hmac_rfc4231_case5_truncated(void)
{
    uint8_t key[20];
    memset(key, 0x0c, sizeof(key));
    check_hmac(key, sizeof(key), (const uint8_t *)"Test With Truncation", 20,
               "a3b6167473100ee06e0c796c2955552b", 16);
}

/* RFC 4231 Test Case 6 -- key longer than the block size (131 bytes, hashed first) */
static void test_hmac_rfc4231_case6_large_key(void)
{
    uint8_t key[131];
    memset(key, 0xaa, sizeof(key));
    const char *data = "Test Using Larger Than Block-Size Key - Hash Key First";
    check_hmac(key, sizeof(key), (const uint8_t *)data, strlen(data),
               "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", 32);
}

/* RFC 4231 Test Case 7 -- large key and large data */
static void test_hmac_rfc4231_case7_large_key_and_data(void)
{
    uint8_t key[131];
    memset(key, 0xaa, sizeof(key));
    const char *data =
        "This is a test using a larger than block-size key and a larger than block-size data. "
        "The key needs to be hashed before being used by the HMAC algorithm.";
    check_hmac(key, sizeof(key), (const uint8_t *)data, strlen(data),
               "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", 32);
}

/* integration -- the two additions (SHA-256 + HMAC-SHA-256) drive AWS SigV4 in the S3 connector.
 * reproduce the SigV4 signing-key chain (date -> region -> service -> aws4_request) and a final
 * signature exactly as src/objstore_s3.c does, and check against reference values computed with an
 * independent HMAC/SHA-256 (Python hmac+hashlib). */
static void test_sigv4_signing_key_and_signature(void)
{
    const char *secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const char *date = "20150830";
    const char *region = "us-east-1";

    char key_date[256];
    snprintf(key_date, sizeof(key_date), "AWS4%s", secret);

    uint8_t k1[32], k2[32], k3[32], signing_key[32];
    hmac_sha256(key_date, strlen(key_date), date, strlen(date), k1);
    hmac_sha256(k1, 32, region, strlen(region), k2);
    hmac_sha256(k2, 32, "s3", 2, k3);
    hmac_sha256(k3, 32, "aws4_request", 12, signing_key);

    char sk_hex[65];
    to_hex(signing_key, 32, sk_hex);
    ASSERT_EQ(strcmp(sk_hex, "61c08448a068b7aaaa3bd62d8e7b3c83b7982fcb0cae7650b7334230c1e715b6"),
              0);

    /* string-to-sign whose canonical-request hash is SHA-256("canonical-request-placeholder") */
    char canon_hash[SHA256_HEX_SIZE];
    sha256_hex("canonical-request-placeholder", strlen("canonical-request-placeholder"),
               canon_hash);

    char string_to_sign[512];
    snprintf(string_to_sign, sizeof(string_to_sign),
             "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/s3/aws4_request\n%s",
             canon_hash);

    uint8_t sig[32];
    hmac_sha256(signing_key, 32, string_to_sign, strlen(string_to_sign), sig);
    char sig_hex[65];
    to_hex(sig, 32, sig_hex);
    ASSERT_EQ(strcmp(sig_hex, "6a6d8dca01078fd01f6d1992a8b5ea1c5ccac50fa214db6b7af32d4a259c3599"),
              0);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);

    RUN_TEST(test_hmac_rfc4231_case1, tests_passed);
    RUN_TEST(test_hmac_rfc4231_case2, tests_passed);
    RUN_TEST(test_hmac_rfc4231_case3, tests_passed);
    RUN_TEST(test_hmac_rfc4231_case4, tests_passed);
    RUN_TEST(test_hmac_rfc4231_case5_truncated, tests_passed);
    RUN_TEST(test_hmac_rfc4231_case6_large_key, tests_passed);
    RUN_TEST(test_hmac_rfc4231_case7_large_key_and_data, tests_passed);
    RUN_TEST(test_sigv4_signing_key_and_signature, tests_passed);

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
