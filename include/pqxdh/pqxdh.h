#ifndef __PQXDH_H__
#define __PQXDH_H__

#include "oqs/kem_ml_kem.h"
#include <sodium/crypto_box.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign.h>
#include <stdint.h>

typedef uint8_t byte;

typedef struct pqxdh_state {
    byte ident_sk[crypto_sign_SECRETKEYBYTES];
    byte ident_pk[crypto_sign_PUBLICKEYBYTES];

    byte prekey_sk[crypto_scalarmult_curve25519_BYTES];
    byte prekey_pk[crypto_scalarmult_curve25519_BYTES];
    byte prekey_sig[crypto_sign_BYTES];

    byte mlkem_pk[OQS_KEM_ml_kem_1024_length_public_key];
    byte mlkem_sk[OQS_KEM_ml_kem_1024_length_secret_key];
    byte mlkem_pk_sig[crypto_sign_BYTES];
} pqxdh_state;

typedef struct {
    byte ident_pk[crypto_sign_PUBLICKEYBYTES];
    byte prekey_pk[crypto_scalarmult_curve25519_BYTES];
    byte prekey_sig[crypto_sign_BYTES];

    byte mlkem_pk[OQS_KEM_ml_kem_1024_length_public_key];
    byte mlkem_pk_sig[crypto_sign_BYTES];
} pqxdh_key_bundle;

typedef struct pqxdh_initial_message {
    byte peer_ident_pk[crypto_scalarmult_curve25519_BYTES];
    byte eph_pk[crypto_scalarmult_curve25519_BYTES];
    byte one_time_prekey[crypto_scalarmult_curve25519_BYTES];

    size_t ct_len;
    byte* ct;
} pqxdh_initial_message;

typedef struct {
    byte shared_secret[32];
    pqxdh_initial_message msg;
} pqxdh_init_output;

int init_pqxdh_state(pqxdh_state* state);

#endif
