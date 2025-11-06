#include "pqxdh/pqxdh.h"
#include "oqs/common.h"
#include "oqs/kem.h"
#include <assert.h>
#include <sodium.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign.h>
#include <string.h>

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

int init_key_exchange(const pqxdh_state* state, const pqxdh_key_bundle* other, pqxdh_init_output* out)
{
    memset(out, 0, sizeof *out);

    // verify other person's keys
    if (crypto_sign_verify_detached(other->prekey_sig, other->prekey_pk, crypto_scalarmult_BYTES, other->ident_pk) != 0) {
        return -1;
    }

    if (crypto_sign_verify_detached(other->mlkem_pk_sig, other->mlkem_pk, crypto_scalarmult_BYTES, other->ident_pk) != 0) {
        return -1;
    }

    // generate ephemeral key pair that should only be used for this
    byte eph_sk[crypto_sign_SECRETKEYBYTES];
    byte eph_pk[crypto_sign_PUBLICKEYBYTES];
    if (crypto_box_keypair(eph_pk, eph_sk) != 0) {
        return -1;
    }

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem)
        return -1;

    OQS_KEM_free(kem);
    return 0;
}
