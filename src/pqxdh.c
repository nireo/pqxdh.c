#include "pqxdh/pqxdh.h"
#include "oqs/common.h"
#include "oqs/kem.h"
#include "oqs/kem_ml_kem.h"
#include <assert.h>
#include <sodium.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/utils.h>
#include <string.h>

static void kdf_blake2b_32(
    const byte dh1[32],
    const byte dh2[32],
    const byte dh3[32],
    const byte ss[32],
    byte out32[32])
{
    unsigned char FF[32];
    for (size_t i = 0; i < 32; i++)
        FF[i] = 0xFF;

    static const char INFO[] = "PQXDH_CURVE25519_BLAKE2B_ML-KEM-1024";

    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, FF, 32);
    crypto_generichash_update(&st, dh1, 32);
    crypto_generichash_update(&st, dh2, 32);
    crypto_generichash_update(&st, dh3, 32);
    crypto_generichash_update(&st, ss, 32);
    crypto_generichash_update(&st, (const unsigned char*)INFO, sizeof(INFO) - 1);
    crypto_generichash_final(&st, out32, 32);
}

int init_pqxdh_state(pqxdh_state* state)
{
    if (crypto_sign_keypair(state->ident_pk, state->ident_sk) != 0)
        return -1;

    if (crypto_box_keypair(state->prekey_pk, state->prekey_sk) != 0)
        return -1;

    unsigned long long slen = 0;
    if (crypto_sign_detached(state->prekey_sig, &slen, state->prekey_pk, crypto_scalarmult_BYTES, state->ident_pk) != 0)
        return -1;
    assert(slen == crypto_sign_BYTES);

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem)
        return -1;

    int ret = OQS_KEM_keypair(kem, state->mlkem_pk, state->mlkem_sk) == OQS_SUCCESS;
    if (ret) {
        if (crypto_sign_detached(state->mlkem_pk_sig, &slen, state->mlkem_sk, crypto_scalarmult_BYTES, state->ident_pk) != 0)
            ret = -1;
        else
            ret = 0;
        assert(slen == crypto_sign_BYTES);
    }
    OQS_KEM_free(kem);

    return 0;
}

int init_key_exchange(const pqxdh_state* self,
    const pqxdh_key_bundle* other,
    pqxdh_init_output* out)
{
    memset(out, 0, sizeof *out);

    // verify the bundle signatures from Bob
    if (crypto_sign_verify_detached(other->prekey_sig,
            other->prekey_pk, crypto_box_PUBLICKEYBYTES,
            other->ident_pk)
        != 0)
        return -1;

    if (crypto_sign_verify_detached(other->mlkem_pk_sig,
            other->mlkem_pk, OQS_KEM_ml_kem_1024_length_public_key,
            other->ident_pk)
        != 0)
        return -1;

    // generate ephemeral X25519 for this session
    unsigned char eph_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char eph_sk[crypto_box_SECRETKEYBYTES];
    if (crypto_box_keypair(eph_pk, eph_sk) != 0)
        return -1;

    // ML-KEM encapsulate to Bob’s KEM public key
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        sodium_memzero(eph_sk, sizeof eph_sk);
        return -1;
    }

    unsigned char ss[OQS_KEM_ml_kem_1024_length_shared_secret];
    if (OQS_KEM_encaps(kem, out->msg.ciphertext, ss, other->mlkem_pk) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        sodium_memzero(eph_sk, sizeof eph_sk);
        return -1;
    }

    unsigned char self_ident_sk_x25519[32];
    unsigned char other_ident_pk_x25519[32];

    if (crypto_sign_ed25519_sk_to_curve25519(self_ident_sk_x25519, self->ident_sk) != 0) {
        OQS_KEM_free(kem);
        sodium_memzero(eph_sk, sizeof eph_sk);
        return -1;
    }

    if (crypto_sign_ed25519_pk_to_curve25519(other_ident_pk_x25519, other->ident_pk) != 0) {
        OQS_KEM_free(kem);
        sodium_memzero(eph_sk, sizeof eph_sk);
        return -1;
    }

    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];

    // DH1 = DH(IKA, SPKB)
    if (crypto_scalarmult(dh1, self_ident_sk_x25519, other->prekey_pk) != 0) {
        OQS_KEM_free(kem);
        sodium_memzero(eph_sk, sizeof eph_sk);
        return -1;
    }
    // DH2 = DH(EKA, IKB)
    if (crypto_scalarmult(dh2, eph_sk, other_ident_pk_x25519) != 0) {
        OQS_KEM_free(kem);
        sodium_memzero(eph_sk, sizeof eph_sk);
        return -1;
    }
    // DH3 = DH(EKA, SPKB)
    if (crypto_scalarmult(dh3, eph_sk, other->prekey_pk) != 0) {
        OQS_KEM_free(kem);
        sodium_memzero(eph_sk, sizeof eph_sk);
        return -1;
    }

    kdf_blake2b_32(dh1, dh2, dh3, ss, out->shared_secret);

    // TODO: add support for one-time prekeys
    memcpy(out->msg.peer_ident_pk, self->ident_pk, crypto_sign_PUBLICKEYBYTES);
    memcpy(out->msg.eph_pk, eph_pk, crypto_box_PUBLICKEYBYTES);
    memset(out->msg.one_time_prekey, 0, sizeof out->msg.one_time_prekey);
    out->msg.used_one_time_prekey = 0;

    sodium_memzero(eph_sk, sizeof eph_sk);
    OQS_KEM_free(kem);
    return 0;
}

int complete_key_exchange(const pqxdh_state* self,
    const pqxdh_initial_message* msg,
    byte out_shared_secret[32])
{
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem)
        return -1;

    unsigned char ss[OQS_KEM_ml_kem_1024_length_shared_secret];
    if (OQS_KEM_decaps(kem, ss, msg->ciphertext, self->mlkem_sk) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return -1;
    }

    unsigned char peer_ident_pk_x25519[32];
    unsigned char self_ident_sk_x25519[32];

    if (crypto_sign_ed25519_pk_to_curve25519(peer_ident_pk_x25519, msg->peer_ident_pk) != 0) {
        OQS_KEM_free(kem);
        return -1;
    }
    if (crypto_sign_ed25519_sk_to_curve25519(self_ident_sk_x25519, self->ident_sk) != 0) {
        OQS_KEM_free(kem);
        return -1;
    }

    byte dh1[crypto_scalarmult_BYTES];
    byte dh2[crypto_scalarmult_BYTES];
    byte dh3[crypto_scalarmult_BYTES];

    // DH1 = DH(IKA, SPKB)
    if (crypto_scalarmult(dh1, self->prekey_sk, peer_ident_pk_x25519) != 0) {
        OQS_KEM_free(kem);
        return -1;
    }
    // DH2 = DH(EKA, IKB)
    if (crypto_scalarmult(dh2, self_ident_sk_x25519, msg->eph_pk) != 0) {
        OQS_KEM_free(kem);
        return -1;
    }
    // DH3 = DH(EKA, SPKB)
    if (crypto_scalarmult(dh3, self->prekey_sk, msg->eph_pk) != 0) {
        OQS_KEM_free(kem);
        return -1;
    }

    kdf_blake2b_32(dh1, dh2, dh3, ss, out_shared_secret);

    OQS_KEM_free(kem);
    return 0;
}
