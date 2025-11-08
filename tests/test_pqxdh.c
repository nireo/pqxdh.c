// test_pqxdh.c
#include "pqxdh/pqxdh.h"
#include "utils.h"

#include <sodium.h>
#include <string.h>

static int bytes_all_zero(const uint8_t* p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= p[i];
    return acc == 0;
}

static int bytes_equal(const uint8_t* a, const uint8_t* b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static void flip_one_bit(uint8_t* p, size_t n)
{
    if (n == 0)
        return;
    p[n / 2] ^= 0x01;
}

static const char* test_init(void)
{
    pqxdh_state s = { 0 };
    int ret = init_pqxdh_state(&s);
    mu_assert("init_pqxdh_state failed", ret == 0);
    unsigned long long dummy = 0;
    (void)dummy;
    int v1 = crypto_sign_verify_detached(s.prekey_sig,
        s.prekey_pk, crypto_box_PUBLICKEYBYTES,
        s.ident_pk);
    mu_assert("prekey_sig verify failed", v1 == 0);

    int v2 = crypto_sign_verify_detached(s.mlkem_pk_sig,
        s.mlkem_pk, OQS_KEM_ml_kem_1024_length_public_key,
        s.ident_pk);
    mu_assert("mlkem_pk_sig verify failed", v2 == 0);
    return 0;
}

static const char* test_handshake_success(void)
{
    pqxdh_state alice = { 0 };
    pqxdh_state bob = { 0 };
    mu_assert("alice init failed", init_pqxdh_state(&alice) == 0);
    mu_assert("bob init failed", init_pqxdh_state(&bob) == 0);

    pqxdh_key_bundle bob_bundle = { 0 };
    make_bundle_from_state(&bob, &bob_bundle);

    pqxdh_init_output init_out = { 0 };
    mu_assert("init_key_exchange failed",
        init_key_exchange(&alice, &bob_bundle, &init_out) == 0);

    uint8_t bob_ss[32] = { 0 };
    mu_assert("complete_key_exchange failed",
        complete_key_exchange(&bob, &init_out.msg, bob_ss) == 0);

    mu_assert("shared secrets mismatch",
        bytes_equal(init_out.shared_secret, bob_ss, 32));
    mu_assert("shared secret is all zeros",
        !bytes_all_zero(bob_ss, 32));

    mu_assert("unexpected one_time_prekey usage flag",
        init_out.msg.used_one_time_prekey == 0);
    mu_assert("ephemeral public key is all zeros",
        !bytes_all_zero(init_out.msg.eph_pk, sizeof init_out.msg.eph_pk));
    mu_assert("peer_ident_pk (echoed) is all zeros",
        !bytes_all_zero(init_out.msg.peer_ident_pk, sizeof init_out.msg.peer_ident_pk));
    return 0;
}

static const char* test_bad_prekey_signature_rejected(void)
{
    pqxdh_state alice = { 0 };
    pqxdh_state bob = { 0 };
    mu_assert("alice init failed", init_pqxdh_state(&alice) == 0);
    mu_assert("bob init failed", init_pqxdh_state(&bob) == 0);

    pqxdh_key_bundle bad = { 0 };
    make_bundle_from_state(&bob, &bad);
    flip_one_bit(bad.prekey_sig, sizeof bad.prekey_sig);

    pqxdh_init_output tmp = { 0 };
    int r = init_key_exchange(&alice, &bad, &tmp);
    mu_assert("init_key_exchange should have failed on bad prekey_sig", r != 0);
    return 0;
}

static const char* test_bad_mlkem_signature_rejected(void)
{
    pqxdh_state alice = { 0 };
    pqxdh_state bob = { 0 };
    mu_assert("alice init failed", init_pqxdh_state(&alice) == 0);
    mu_assert("bob init failed", init_pqxdh_state(&bob) == 0);

    pqxdh_key_bundle bad = { 0 };
    make_bundle_from_state(&bob, &bad);
    flip_one_bit(bad.mlkem_pk_sig, sizeof bad.mlkem_pk_sig);

    pqxdh_init_output tmp = { 0 };
    int r = init_key_exchange(&alice, &bad, &tmp);
    mu_assert("init_key_exchange should have failed on bad mlkem_pk_sig", r != 0);
    return 0;
}

static const char* all_tests(void)
{
    mu_run_test(test_init);
    mu_run_test(test_handshake_success);
    mu_run_test(test_bad_prekey_signature_rejected);
    mu_run_test(test_bad_mlkem_signature_rejected);
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 2;
    }

    tests_run = 0;
    const char* result = all_tests();
    if (result) {
        printf("FAIL: %s\n", result);
        return 1;
    }
    printf("OK (%d tests)\n", tests_run);
    return 0;
}
