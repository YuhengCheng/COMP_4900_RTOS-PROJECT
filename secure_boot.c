#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h> // Open Quantum Safe library
#include <time.h>    // For timing

#define DILITHIUM_ALG OQS_SIG_alg_dilithium_5 // Use Dilithium5
#define NUM_ITERATIONS 100 // Number of iterations for averaging times

// Function to free resources securely
void cleanup(uint8_t *public_key, uint8_t *secret_key, uint8_t *signature, OQS_SIG *sig) {
    if (sig != NULL) {
        OQS_MEM_secure_free(secret_key, sig->length_secret_key);
    }
    OQS_MEM_insecure_free(public_key);
    OQS_MEM_insecure_free(signature);
    OQS_SIG_free(sig);
}

// Generate Dilithium key pair
int generate_keypair(OQS_SIG *sig, uint8_t **public_key, uint8_t **secret_key) {
    *public_key = OQS_MEM_malloc(sig->length_public_key);
    *secret_key = OQS_MEM_malloc(sig->length_secret_key);
    if (*public_key == NULL || *secret_key == NULL) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        return -1;
    }

    if (OQS_SIG_keypair(sig, *public_key, *secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Key pair generation failed\n");
        return -1;
    }
    return 0;
}

// Sign the boot image
int sign_boot_image(OQS_SIG *sig, const uint8_t *message, size_t message_len,
                    const uint8_t *secret_key, uint8_t **signature, size_t *sig_len) {
    *signature = OQS_MEM_malloc(sig->length_signature);
    if (*signature == NULL) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        return -1;
    }

    if (OQS_SIG_sign(sig, *signature, sig_len, message, message_len, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Signing failed\n");
        return -1;
    }
    return 0;
}

// Verify the boot image signature
int verify_boot_image(OQS_SIG *sig, const uint8_t *message, size_t message_len,
                      const uint8_t *public_key, const uint8_t *signature, size_t sig_len) {
    return (OQS_SIG_verify(sig, message, message_len, signature, sig_len, public_key) == OQS_SUCCESS) ? 0 : -1;
}

int main() {
    OQS_init(); // Initialize OQS library

    OQS_SIG *sig = OQS_SIG_new(DILITHIUM_ALG);
    if (sig == NULL) {
        fprintf(stderr, "ERROR: Dilithium5 not supported\n");
        OQS_destroy();
        return EXIT_FAILURE;
    }

    uint8_t *public_key = NULL, *secret_key = NULL, *signature = NULL;
    size_t sig_len;

    // Example boot image
    const uint8_t boot_image[] = "This is a sample boot image.";
    size_t message_len = sizeof(boot_image) - 1;

    // Variables for time measurement
    clock_t start_time, end_time;
    double total_time_gen = 0, total_time_sign = 0, total_time_verify = 0;

    // Loop through the operations and time each step
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        // Time key generation
        start_time = clock();
        if (generate_keypair(sig, &public_key, &secret_key) != 0) {
            cleanup(public_key, secret_key, signature, sig);
            OQS_destroy();
            return EXIT_FAILURE;
        }
        end_time = clock();
        total_time_gen += ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

        // Time signing the boot image
        start_time = clock();
        if (sign_boot_image(sig, boot_image, message_len, secret_key, &signature, &sig_len) != 0) {
            cleanup(public_key, secret_key, signature, sig);
            OQS_destroy();
            return EXIT_FAILURE;
        }
        end_time = clock();
        total_time_sign += ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

        // Time verifying the boot image
        start_time = clock();
        if (verify_boot_image(sig, boot_image, message_len, public_key, signature, sig_len) != 0) {
            cleanup(public_key, secret_key, signature, sig);
            OQS_destroy();
            return EXIT_FAILURE;
        }
        end_time = clock();
        total_time_verify += ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    }

    // Print the average times
    printf("Total time for 100 iterations:%.6f seconds\n",total_time_gen+total_time_sign+total_time_verify);
    printf("Average time for key generation: %.6f seconds\n", total_time_gen / NUM_ITERATIONS);
    printf("Average time for signing: %.6f seconds\n", total_time_sign / NUM_ITERATIONS);
    printf("Average time for verification: %.6f seconds\n", total_time_verify / NUM_ITERATIONS);

    // Cleanup after all iterations
    cleanup(public_key, secret_key, signature, sig);

    // Destroy OQS library
    OQS_destroy();
    return EXIT_SUCCESS;
}
