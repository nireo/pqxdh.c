#include <sodium.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign.h>
#include <stdio.h>

typedef uint8_t byte;

// pqxdh_state represents the state of a user in the Post-Quantum Extended Triple Diffie
// Hellman key exhange. the user state is not thread safe so the caller is responsible for
// handling concurrency correctly.
struct pqxdh_state {
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
};

struct pqxdh_initial_message {
    byte ident_pub[crypto_scalarmult_curve25519_BYTES];
    byte ephemral_pub[crypto_scalarmult_curve25519_BYTES];
    byte one_time_prekey[crypto_scalarmult_curve25519_BYTES];

    int used_prekey;
};

struct pqxdh_prekey_bundle {
    byte ident_pub[crypto_scalarmult_curve25519_BYTES];
    byte ephemral_pub[crypto_scalarmult_curve25519_BYTES];
    byte one_time_prekey[crypto_scalarmult_curve25519_BYTES];
    byte signature[crypto_sign_BYTES];
};

int pqxdh_init_state(struct pqxdh_state* state)
{
    // generate the user's identity key
    crypto_box_keypair(state->ident_pub, state->ident_priv);

    return 0;
}

int main(void)
{
    printf("hello world");
    return 0;
}
