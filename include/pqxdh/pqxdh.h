#ifndef __PQXDH_H__
#define __PQXDH_H__

#include "oqs/kem_ml_kem.h"
#include <sodium/crypto_auth.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_OTPKS 64

typedef uint8_t byte;

typedef struct {
    byte otp_sk[crypto_sign_SECRETKEYBYTES];
    byte otp_pk[crypto_sign_PUBLICKEYBYTES];
    int used;
} one_time_prekey;

typedef struct {
    byte mlkem_pk[OQS_KEM_ml_kem_1024_length_public_key];
    byte mlkem_sk[OQS_KEM_ml_kem_1024_length_secret_key];
} mlkem_key;

#define QUEUE(name, type, CAP)                                                     \
    typedef struct name {                                                          \
        type buf[(CAP)];                                                           \
        size_t front;                                                              \
        size_t count;                                                              \
    } name;                                                                        \
                                                                                   \
    static inline void name##_init(name* q)                                        \
    {                                                                              \
        q->front = 0u;                                                             \
        q->count = 0u;                                                             \
    }                                                                              \
    static inline bool name##_is_empty(const name* q) { return q->count == 0u; }   \
    static inline bool name##_is_full(const name* q) { return q->count == (CAP); } \
    static inline size_t name##_size(const name* q) { return q->count; }           \
    static inline void name##_clear(name* q)                                       \
    {                                                                              \
        q->front = 0u;                                                             \
        q->count = 0u;                                                             \
    }                                                                              \
                                                                                   \
    static inline bool name##_enqueue(name* q, type value)                         \
    {                                                                              \
        if (q->count == (CAP))                                                     \
            return false;                                                          \
        size_t rear = (q->front + q->count) % (CAP);                               \
        q->buf[rear] = value;                                                      \
        q->count++;                                                                \
        return true;                                                               \
    }                                                                              \
                                                                                   \
    static inline bool name##_dequeue(name* q, type* out)                          \
    {                                                                              \
        if (q->count == 0u)                                                        \
            return false;                                                          \
        if (out)                                                                   \
            *out = q->buf[q->front];                                               \
        q->front = (q->front + 1u) % (CAP);                                        \
        q->count--;                                                                \
        return true;                                                               \
    }                                                                              \
                                                                                   \
    static inline bool name##_front(const name* q, type* out)                      \
    {                                                                              \
        if (q->count == 0u)                                                        \
            return false;                                                          \
        if (out)                                                                   \
            *out = q->buf[q->front];                                               \
        return true;                                                               \
    }

QUEUE(otpk_queue, one_time_prekey, 64)
QUEUE(mlkem_queue, mlkem_key, 64)

typedef struct pqxdh_state {
    byte ident_sk[crypto_sign_SECRETKEYBYTES];
    byte ident_pk[crypto_sign_PUBLICKEYBYTES];

    byte prekey_sk[crypto_scalarmult_curve25519_BYTES];
    byte prekey_pk[crypto_scalarmult_curve25519_BYTES];
    byte prekey_sig[crypto_sign_BYTES];

    byte mlkem_pk[OQS_KEM_ml_kem_1024_length_public_key];
    byte mlkem_sk[OQS_KEM_ml_kem_1024_length_secret_key];
    byte mlkem_pk_sig[crypto_sign_BYTES];

    one_time_prekey otps[MAX_OTPKS];

    otpk_queue otpks;
    mlkem_queue mlkem_keys;
} pqxdh_state;

typedef struct {
    byte ident_pk[crypto_sign_PUBLICKEYBYTES];
    byte prekey_pk[crypto_scalarmult_curve25519_BYTES];
    byte prekey_sig[crypto_sign_BYTES];

    byte mlkem_pk[OQS_KEM_ml_kem_1024_length_public_key];
    byte mlkem_pk_sig[crypto_sign_BYTES];

    byte one_time_prekey[crypto_sign_PUBLICKEYBYTES];
    int has_one_time_prekey;
} pqxdh_key_bundle;

typedef struct pqxdh_initial_message {
    byte peer_ident_pk[crypto_scalarmult_curve25519_BYTES];
    byte eph_pk[crypto_scalarmult_curve25519_BYTES];
    byte one_time_prekey[crypto_scalarmult_curve25519_BYTES];
    byte ciphertext[OQS_KEM_ml_kem_1024_length_ciphertext];
    byte tag[crypto_auth_BYTES];
    int used_one_time_prekey;
} pqxdh_initial_message;

typedef struct {
    byte shared_secret[32];
    pqxdh_initial_message msg;
} pqxdh_init_output;

int init_pqxdh_state(pqxdh_state* state);
int init_otpks(pqxdh_state* state);
int replace_old_used_otpks(pqxdh_state* state);
int init_key_exchange(const pqxdh_state* self, const pqxdh_key_bundle* other, pqxdh_init_output* out);
int complete_key_exchange(pqxdh_state* self, const pqxdh_initial_message* msg, byte out_shared_secret[32]);

#endif
