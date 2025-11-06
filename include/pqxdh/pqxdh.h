#ifndef __PQXDH_H__
#define __PQXDH_H__

#include <sodium/crypto_box.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign.h>
#include <stdint.h>

typedef uint8_t byte;

typedef struct pqxdh_state {
    byte ident_priv[crypto_scalarmult_curve25519_BYTES];
    byte ident_pub[crypto_scalarmult_curve25519_BYTES];

    byte ephemeral_priv[crypto_scalarmult_curve25519_BYTES];
    byte ephemeral_pub[crypto_scalarmult_curve25519_BYTES];

    byte one_time_prekey[crypto_scalarmult_curve25519_BYTES];
    byte one_time_prekey_pub[crypto_scalarmult_curve25519_BYTES];

    byte signed_prekey[crypto_scalarmult_curve25519_BYTES];
    byte signed_prekey_pub[crypto_scalarmult_curve25519_BYTES];

    byte signing_public_key[crypto_sign_PUBLICKEYBYTES];
    byte signing_private_key[crypto_sign_SECRETKEYBYTES];

    char username[64];
} pqxdh_state;

typedef struct pqxdh_initial_message {
    byte ident_pub[crypto_scalarmult_curve25519_BYTES];
    byte ephemral_pub[crypto_scalarmult_curve25519_BYTES];
    byte one_time_prekey[crypto_scalarmult_curve25519_BYTES];

    int used_prekey;
} pqxdh_initial_message;

typedef struct pqxdh_prekey_bundle {
    byte ident_pub[crypto_scalarmult_curve25519_BYTES];
    byte ephemral_pub[crypto_scalarmult_curve25519_BYTES];
    byte one_time_prekey[crypto_scalarmult_curve25519_BYTES];
    byte signature[crypto_sign_BYTES];
} pqxdh_prekey_bundle;

int init_pqxdh_state(pqxdh_state* state);

#endif
