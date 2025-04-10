#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

#define DILITHIUM_ALG OQS_SIG_alg_dilithium_5

int main() {
    if (OQS_SIG_alg_is_enabled(DILITHIUM_ALG) != 1) {
        fprintf(stderr, "ERROR: Dilithium5 is not enabled in liboqs.\n");
        return EXIT_FAILURE;
    }

    OQS_SIG *sig = OQS_SIG_new(DILITHIUM_ALG);
    if (!sig) {
        fprintf(stderr, "ERROR: Failed to initialize signature scheme.\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *private_key = malloc(sig->length_secret_key);

    if (!public_key || !private_key) {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        return EXIT_FAILURE;
    }

    if (OQS_SIG_keypair(sig, public_key, private_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Keypair generation failed.\n");
        return EXIT_FAILURE;
    }

    // Save keys to disk
    FILE *pub = fopen("public_key.bin", "wb");
    FILE *priv = fopen("private_key.bin", "wb");
    fwrite(public_key, 1, sig->length_public_key, pub);
    fwrite(private_key, 1, sig->length_secret_key, priv);
    fclose(pub);
    fclose(priv);

    printf("Keypair generated.\n");

    free(public_key);
    free(private_key);
    OQS_SIG_free(sig);
    return EXIT_SUCCESS;
}
