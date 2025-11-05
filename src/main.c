#include <oqs/oqs.h>
#include <sodium.h>
#include <stdio.h>

typedef unsigned char byte;

int main(void)
{
    // Initialize libsodium
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    printf("libsodium initialized successfully\n");
    printf("libsodium version: %s\n", sodium_version_string());

    // Test liboqs
    printf("\nliboqs version: %s\n", OQS_VERSION_TEXT);
    printf("ML-KEM-1024 enabled: %s\n",
        OQS_KEM_alg_is_enabled("ML-KEM-1024") ? "YES" : "NO");

    // Generate Ed25519 keypair
    byte ed25519_pk[crypto_sign_PUBLICKEYBYTES];
    byte ed25519_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(ed25519_pk, ed25519_sk);
    printf("\nGenerated Ed25519 keypair\n");

    // Generate ML-KEM-1024 keypair
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (kem == NULL) {
        fprintf(stderr, "Failed to create ML-KEM-1024 instance\n");
        return 1;
    }

    byte* kem_pk = malloc(kem->length_public_key);
    byte* kem_sk = malloc(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, kem_pk, kem_sk) != OQS_SUCCESS) {
        fprintf(stderr, "Failed to generate ML-KEM-1024 keypair\n");
        free(kem_pk);
        free(kem_sk);
        OQS_KEM_free(kem);
        return 1;
    }

    printf("Generated ML-KEM-1024 keypair\n");
    printf("  Public key size: %zu bytes\n", kem->length_public_key);
    printf("  Secret key size: %zu bytes\n", kem->length_secret_key);

    // Cleanup
    free(kem_pk);
    free(kem_sk);
    OQS_KEM_free(kem);

    printf("\n✓ All tests passed!\n");
    return 0;
}
