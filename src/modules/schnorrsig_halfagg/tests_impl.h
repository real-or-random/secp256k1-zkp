#ifndef SECP256K1_MODULE_SCHNORRSIG_HALFAGG_TESTS_H
#define SECP256K1_MODULE_SCHNORRSIG_HALFAGG_TESTS_H

#include "../../../include/secp256k1_schnorrsig_halfagg.h"

/* We test that hash initialized by secp256k1_schnorrsig_sha256_tagged_aggregate has the
 * expected state. */
void test_schnorrsig_sha256_tagged_aggregate(void) {
    unsigned char tag[18] = "HalfAgg/randomizer";
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_optimized;

    secp256k1_sha256_initialize_tagged(&sha, (unsigned char *) tag, sizeof(tag));
    secp256k1_schnorrsig_sha256_tagged_aggregation(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);
}

/* In this test we create a bunch of Schnorr signatures,
*  aggregate N_INITIAL of them in one shot, and then
*  aggregate N_NEW of them incrementally to the already aggregated ones
*  the aggregate signature should verify after both steps
*/
#define N_INITIAL 3
#define N_NEW 5
#define N (N_INITIAL+N_NEW)
void test_schnorrsig_aggregate(void) {
    int i;
    secp256k1_xonly_pubkey pubkeys[N];
    unsigned char msgs32[N*32];
    unsigned char sigs64[N*64];
    unsigned char aggsig[32*(N + 1)];
    size_t aggsig_len = 32*(N + 1);

    /* create N many Schnorr keys and sigs for random messages */
    for (i = 0; i < N; ++i) {
        unsigned char sk[32];
        secp256k1_keypair keypair;
        secp256k1_testrand256(sk);
        secp256k1_testrand256(&msgs32[i*32]);

        CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
        CHECK(secp256k1_keypair_xonly_pub(CTX, &pubkeys[i], NULL, &keypair));
        CHECK(secp256k1_schnorrsig_sign(CTX, &sigs64[i*64], &msgs32[i*32], &keypair, NULL));
    }

    /* aggregate the first N_INITIAL of them */
    CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, N_INITIAL));
    /* make sure that the aggregate signature verifies */
    CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N_INITIAL, aggsig, aggsig_len));
    /* aggregate the remaining N_NEW many signatures to the already existing ones */
    aggsig_len = 32*(N + 1);
    secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[N_INITIAL*64], N_INITIAL, N_NEW);
    /* make sure that the aggregate signature verifies */
    CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N, aggsig, aggsig_len));
}

/* this tests the test vectors from
https://github.com/BlockstreamResearch/cross-input-aggregation/blob/master/hacspec-halfagg/tests/tests.rs#L78
*/
void test_schnorrsig_aggregate_spec_vectors(void) {
    /* Test vector 0 */
    {
        int n = 0;
        int aggsig_len = 32;
        /* ugly trick: setting size to 1, because C     */
        /* complains about zero-size arrays             */
        const unsigned char pubkeys_ser[32] = {
            0x1b, 0x84, 0xc5, 0x56, 0x7b, 0x12, 0x64, 0x40,
            0x99, 0x5d, 0x3e, 0xd5, 0xaa, 0xba, 0x05, 0x65,
            0xd7, 0x1e, 0x18, 0x34, 0x60, 0x48, 0x19, 0xff,
            0x9c, 0x17, 0xf5, 0xe9, 0xd5, 0xdd, 0x07, 0x8f
        };
        secp256k1_xonly_pubkey pubkeys[1];
        const unsigned char msgs32[1] = { 0x00 };
        const unsigned char aggsig[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        CHECK(secp256k1_xonly_pubkey_parse(CTX, &pubkeys[0], &pubkeys_ser[0]));
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len));
    }
    /* Test vector 1 */
    {
        int n = 1;
        int aggsig_len = 32+32;
        const unsigned char pubkeys_ser[32] = {
            0x1b, 0x84, 0xc5, 0x56, 0x7b, 0x12, 0x64, 0x40,
            0x99, 0x5d, 0x3e, 0xd5, 0xaa, 0xba, 0x05, 0x65,
            0xd7, 0x1e, 0x18, 0x34, 0x60, 0x48, 0x19, 0xff,
            0x9c, 0x17, 0xf5, 0xe9, 0xd5, 0xdd, 0x07, 0x8f
        };
        const unsigned char msgs32[32] = {
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
        };
        const unsigned char aggsig[32+32] = {
            0xb0, 0x70, 0xaa, 0xfc, 0xea, 0x43, 0x9a, 0x4f,
            0x6f, 0x1b, 0xbf, 0xc2, 0xeb, 0x66, 0xd2, 0x9d,
            0x24, 0xb0, 0xca, 0xb7, 0x4d, 0x6b, 0x74, 0x5c,
            0x3c, 0xfb, 0x00, 0x9c, 0xc8, 0xfe, 0x4a, 0xa8,
            0x10, 0x8f, 0x33, 0x90, 0x76, 0x12, 0xfb, 0x74,
            0x84, 0x19, 0xeb, 0xc4, 0x00, 0x4b, 0x31, 0x69,
            0xe1, 0x6e, 0x35, 0xd5, 0xf1, 0x2b, 0x69, 0x3b,
            0x6b, 0xbc, 0x3d, 0x4a, 0x69, 0x82, 0xf2, 0xf6,
        };
        secp256k1_xonly_pubkey pubkeys[1];
        int i;
        for (i = 0; i < n; ++i) {
            CHECK(secp256k1_xonly_pubkey_parse(CTX, &pubkeys[i], &pubkeys_ser[i*32]));
        }
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len));
    }
    /* Test vector 2 */
    {
        int n = 2;
        int aggsig_len = 2*32+32;
        const unsigned char pubkeys_ser[2*32] = {
            0x1b, 0x84, 0xc5, 0x56, 0x7b, 0x12, 0x64, 0x40,
            0x99, 0x5d, 0x3e, 0xd5, 0xaa, 0xba, 0x05, 0x65,
            0xd7, 0x1e, 0x18, 0x34, 0x60, 0x48, 0x19, 0xff,
            0x9c, 0x17, 0xf5, 0xe9, 0xd5, 0xdd, 0x07, 0x8f,

            0x46, 0x27, 0x79, 0xad, 0x4a, 0xad, 0x39, 0x51,
            0x46, 0x14, 0x75, 0x1a, 0x71, 0x08, 0x5f, 0x2f,
            0x10, 0xe1, 0xc7, 0xa5, 0x93, 0xe4, 0xe0, 0x30,
            0xef, 0xb5, 0xb8, 0x72, 0x1c, 0xe5, 0x5b, 0x0b,
        };
        const unsigned char msgs32[2*32] = {
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,

            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        };
        const unsigned char aggsig[2*32+32] = {
            0xb0, 0x70, 0xaa, 0xfc, 0xea, 0x43, 0x9a, 0x4f,
            0x6f, 0x1b, 0xbf, 0xc2, 0xeb, 0x66, 0xd2, 0x9d,
            0x24, 0xb0, 0xca, 0xb7, 0x4d, 0x6b, 0x74, 0x5c,
            0x3c, 0xfb, 0x00, 0x9c, 0xc8, 0xfe, 0x4a, 0xa8,
            0xa3, 0xaf, 0xbd, 0xb4, 0x5a, 0x6a, 0x34, 0xbf,
            0x7c, 0x8c, 0x00, 0xf1, 0xb6, 0xd7, 0xe7, 0xd3,
            0x75, 0xb5, 0x45, 0x40, 0xf1, 0x37, 0x16, 0xc8,
            0x7b, 0x62, 0xe5, 0x1e, 0x2f, 0x4f, 0x22, 0xff,
            0xc2, 0x11, 0xdb, 0x48, 0x47, 0x9c, 0x2f, 0x54,
            0x6d, 0x52, 0xb0, 0x79, 0x55, 0xe7, 0x64, 0xeb,
            0x6a, 0x14, 0x2d, 0x57, 0x72, 0x45, 0xf4, 0x0a,
            0x44, 0xf5, 0xde, 0xe4, 0x68, 0xda, 0x42, 0x44,
        };
        secp256k1_xonly_pubkey pubkeys[2];
        int i;
        for (i = 0; i < n; ++i) {
            CHECK(secp256k1_xonly_pubkey_parse(CTX, &pubkeys[i], &pubkeys_ser[i*32]));
        }
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len));
    }
}

static void test_schnorrsig_aggregate_api(void) {
    /* Test preparation. Need N key, messages, signatures */
    secp256k1_xonly_pubkey pubkeys[N];
    unsigned char msgs32[N*32];
    unsigned char sigs64[N*64];
    unsigned char aggsig[32*(N + 1)];
    size_t aggsig_len = 32*(N + 1);
    size_t size_max = (size_t) - 1;
    int i;
    for (i = 0; i < N; ++i) {
        unsigned char sk[32];
        secp256k1_keypair keypair;
        secp256k1_testrand256(sk);
        secp256k1_testrand256(&msgs32[i*32]);

        CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
        CHECK(secp256k1_keypair_xonly_pub(CTX, &pubkeys[i], NULL, &keypair));
        CHECK(secp256k1_schnorrsig_sign(CTX, &sigs64[i*64], &msgs32[i*32], &keypair, NULL));
    }

    /* Test body 1: Check API of function aggregate  */
    /* Should not accept NULL for any pointer input  */
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggregate(CTX, NULL, &aggsig_len, pubkeys, msgs32, sigs64, N_INITIAL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggregate(CTX, aggsig, NULL, pubkeys, msgs32, sigs64, N_INITIAL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, NULL, msgs32, sigs64, N_INITIAL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, NULL, sigs64, N_INITIAL));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, NULL, N_INITIAL));

    /* Test body 2: Check API of function inc_aggregate */
    /* Should not accept NULL for any pointer input     */
    /* Should not accept overflowing number of sigs     */
    /* Should reject if aggsig_len is too small        */
    CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, N_INITIAL));
    aggsig_len = 32*(N + 1);
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, NULL, &aggsig_len, pubkeys, msgs32, &sigs64[N_INITIAL*64], N_INITIAL, N_NEW));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, NULL, pubkeys, msgs32, &sigs64[N_INITIAL*64], N_INITIAL, N_NEW));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, NULL, msgs32, &sigs64[N_INITIAL*64], N_INITIAL, N_NEW));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, NULL, &sigs64[N_INITIAL*64], N_INITIAL, N_NEW));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, NULL, N_INITIAL, N_NEW));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[N_INITIAL*64], size_max, size_max));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[N_INITIAL*64], N_INITIAL, size_max));
    aggsig_len = 32*N;
    CHECK(secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[N_INITIAL*64], N_INITIAL, N_NEW) == 0);
    aggsig_len = 32*(N+1)-1;
    CHECK(secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[N_INITIAL*64], N_INITIAL, N_NEW) == 0);

    /* Test body 3: Check API of function aggverify */
    /* Should not accept NULL for any pointer input */
    /* Should reject for invalid aggsig_len        */
    aggsig_len = 32*(N + 1);
    CHECK(secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[N_INITIAL*64], N_INITIAL, N_NEW));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggverify(CTX, NULL, msgs32, N, aggsig, aggsig_len));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggverify(CTX, pubkeys, NULL, N, aggsig, aggsig_len));
    CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N, NULL, aggsig_len));
    CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N, aggsig, aggsig_len + 1) == 0);
    CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N, aggsig, aggsig_len - 1) == 0);
    CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N, aggsig, aggsig_len + 32) == 0);
    CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N, aggsig, aggsig_len - 32) == 0);
}


/*
In this test, we make sure that trivial attempts to break
the security of verification do not work.
*/
static void test_schnorrsig_aggregate_unforge(void) {
    /* Test 1: We fix a set of N messages and compute
       a random aggsig for them. This should not verify. */
    {
        int i;
        secp256k1_xonly_pubkey pubkeys[N];
        unsigned char msgs32[N*32];
        unsigned char aggsig[32*(N + 1)];
        size_t aggsig_len = 32*(N + 1);
        /* create N many Schnorr keys and random messages */
        for (i = 0; i < N; ++i) {
            unsigned char sk[32];
            secp256k1_keypair keypair;
            secp256k1_testrand256(sk);
            secp256k1_testrand256(&msgs32[i*32]);

            CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
            CHECK(secp256k1_keypair_xonly_pub(CTX, &pubkeys[i], NULL, &keypair));
        }
        /* sample aggsig randomly */
        for (i = 0; i < N + 1; ++i) {
            secp256k1_testrand256(&aggsig[i*32]);
        }
        /* Make sure that it does not verify */
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N, aggsig, aggsig_len) == 0);
    }
    /* Test 2: We fix a set of N messages and compute valid
       signatures for all but one. For this final one, we sample
       a random signature. The resulting aggregate signature
       should not verify. */
    {
        int i;
        secp256k1_xonly_pubkey pubkeys[N];
        unsigned char msgs32[N*32];
        unsigned char sigs64[N*64];
        unsigned char aggsig[32*(N + 1)];
        size_t aggsig_len = 32*(N + 1);

        /* create N many Schnorr keys and sigs for random messages */
        for (i = 0; i < N; ++i) {
            unsigned char sk[32];
            secp256k1_keypair keypair;
            secp256k1_testrand256(sk);
            secp256k1_testrand256(&msgs32[i*32]);

            CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
            CHECK(secp256k1_keypair_xonly_pub(CTX, &pubkeys[i], NULL, &keypair));
            CHECK(secp256k1_schnorrsig_sign(CTX, &sigs64[i*64], &msgs32[i*32], &keypair, NULL));
        }
        /* For the last message, we replace the actual sig with a random one */
        secp256k1_testrand256(&sigs64[(N-1)*64]);
        secp256k1_testrand256(&sigs64[(N-1)*64+32]);
        /* Aggregate the N signatures */
        CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, N));
        /* Make sure it does not verify */
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N, aggsig, aggsig_len) == 0);
    }
    /* Test 3: We generate a valid aggregate signature and then
       change one of the messages. This should not verify. */
    {
        int i;
        secp256k1_xonly_pubkey pubkeys[N];
        unsigned char msgs32[N*32];
        unsigned char sigs64[N*64];
        unsigned char aggsig[32*(N + 1)];
        size_t aggsig_len = 32*(N + 1);

        /* create N many Schnorr keys and sigs for random messages */
        for (i = 0; i < N; ++i) {
            unsigned char sk[32];
            secp256k1_keypair keypair;
            secp256k1_testrand256(sk);
            secp256k1_testrand256(&msgs32[i*32]);

            CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
            CHECK(secp256k1_keypair_xonly_pub(CTX, &pubkeys[i], NULL, &keypair));
            CHECK(secp256k1_schnorrsig_sign(CTX, &sigs64[i*64], &msgs32[i*32], &keypair, NULL));
        }
        /* Aggregate the N signatures */
        CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, N));
        /* Change one of the messages */
        msgs32[1] = msgs32[1]^0xff;
        /* Make sure it does not verify */
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N, aggsig, aggsig_len) == 0);
    }
}

/*
In this test, we make sure that the algorithms properly reject
for overflowing and non parseable values.
*/
static void test_schnorrsig_aggregate_overflow(void) {
    /* Test 1: We check that aggregation            */
    /* returns 0 if s overflows                     */
    {
        int i;
        secp256k1_xonly_pubkey pubkeys[N];
        unsigned char msgs32[N*32];
        unsigned char sigs64[N*64];
        unsigned char aggsig[32*(N + 1)];
        size_t aggsig_len = 32*(N + 1);

        /* create N many Schnorr keys and sigs for random messages */
        for (i = 0; i < N; ++i) {
            unsigned char sk[32];
            secp256k1_keypair keypair;
            secp256k1_testrand256(sk);
            secp256k1_testrand256(&msgs32[i*32]);
            CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
            CHECK(secp256k1_keypair_xonly_pub(CTX, &pubkeys[i], NULL, &keypair));
            CHECK(secp256k1_schnorrsig_sign(CTX, &sigs64[i*64], &msgs32[i*32], &keypair, NULL));
        }
        /* make one s (say the first one) overflow */
        memset(&sigs64[32], 0xFF, 32);
        /* check that aggregating fails */
        CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, N) == 0);
    }
    /* Test 2: We check that verification returns 0 */
    /* if s overflows                               */
    {
        int i;
        secp256k1_xonly_pubkey pubkeys[N];
        unsigned char msgs32[N*32];
        unsigned char sigs64[N*64];
        unsigned char aggsig[32*(N + 1)];
        size_t aggsig_len = 32*(N + 1);

        /* create N many Schnorr keys and sigs for random messages */
        for (i = 0; i < N; ++i) {
            unsigned char sk[32];
            secp256k1_keypair keypair;
            secp256k1_testrand256(sk);
            secp256k1_testrand256(&msgs32[i*32]);
            CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
            CHECK(secp256k1_keypair_xonly_pub(CTX, &pubkeys[i], NULL, &keypair));
            CHECK(secp256k1_schnorrsig_sign(CTX, &sigs64[i*64], &msgs32[i*32], &keypair, NULL));
        }
        /* aggregate */
        CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, N));
        /* make s in the aggsig overflow */
        memset(&aggsig[N*32], 0xFF, 32);
        /* should not verify */
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, N, aggsig, aggsig_len) == 0);
    }
}

static void run_schnorrsig_halfagg_tests(void) {
    test_schnorrsig_sha256_tagged_aggregate();
    test_schnorrsig_aggregate_spec_vectors();
    test_schnorrsig_aggregate();
    test_schnorrsig_aggregate_api();
    test_schnorrsig_aggregate_unforge();
    test_schnorrsig_aggregate_overflow();
}

#endif
