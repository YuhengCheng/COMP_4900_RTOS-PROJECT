#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <time.h>
#define KEY_SIZE 2048  // RSA key size in bits

// Global context variables for efficiency (to avoid reinitializing each time)
static EVP_PKEY_CTX *keygen_ctx = NULL;
static EVP_MD_CTX *sign_ctx = NULL;
static EVP_MD_CTX *verify_ctx = NULL;

// Function to generate an RSA key pair
int generate_rsa_key(EVP_PKEY **key) {
    if (!keygen_ctx) {
        keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!keygen_ctx) {
            printf("Error creating context\n");
            return -1;
        }
    }

    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(keygen_ctx, KEY_SIZE) <= 0) {
        printf("Error initializing keygen\n");
        return -1;
    }

    if (EVP_PKEY_keygen(keygen_ctx, key) <= 0) {
        printf("Key generation failed\n");
        return -1;
    }

    return 0;
}

// Function to sign the boot image
int sign_boot_image(const unsigned char *image, size_t image_len, 
    EVP_PKEY *key, unsigned char **signature, size_t *sig_len) {
    size_t req_len = 0;

    if (!sign_ctx) {
        sign_ctx = EVP_MD_CTX_new();
        if (!sign_ctx) {
            printf("Failed to create context\n");
            return -1;
        }
    }

    // Initialize signing operation
    if (!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, key) ||
        !EVP_DigestSignUpdate(sign_ctx, image, image_len)) {
        printf("Signing setup failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // First call to get signature length
    if (!EVP_DigestSignFinal(sign_ctx, NULL, &req_len)) {
        printf("Failed to get signature length: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // Reuse allocated memory buffer instead of reallocating each time
    *signature = malloc(req_len);
    if (!*signature) {
        printf("Memory allocation failed\n");
        return -1;
    }

    // Second call to actually generate signature
    if (!EVP_DigestSignFinal(sign_ctx, *signature, &req_len)) {
        printf("Signing failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(*signature);
        return -1;
    }

    *sig_len = req_len;
    return 0;
}

// Function to verify the boot image signature
int verify_boot_image(const unsigned char *image, size_t image_len,
                     EVP_PKEY *key, const unsigned char *signature, size_t sig_len) {
    int rc = -1;

    if (!verify_ctx) {
        verify_ctx = EVP_MD_CTX_new();
        if (!verify_ctx) {
            printf("Failed to create context\n");
            return -1;
        }
    }

    if (EVP_DigestVerifyInit(verify_ctx, NULL, EVP_sha256(), NULL, key) &&
        EVP_DigestVerifyUpdate(verify_ctx, image, image_len) &&
        EVP_DigestVerifyFinal(verify_ctx, signature, sig_len)) {
        rc = 0;
    } else {
        printf("Verification failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }

    return rc;
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    double totalTime = 0;
    double genTotal = 0;
    double signTotal = 0;
    double verifyTotal = 0;
    
    unsigned char boot_image[] = "This is a sample boot image.";
    size_t image_len = strlen((char *)boot_image);

    for (int i = 0; i < 100; i++) {
        EVP_PKEY *key = NULL;
        unsigned char *signature = NULL;
        size_t sig_len;

        // Generate RSA key pair
        clock_t genStart = clock();
        if (generate_rsa_key(&key) != 0) {
            EVP_cleanup();
            return -1;
        }
        double genElapsedTime = (double)(clock() - genStart) / CLOCKS_PER_SEC;
        genTotal += genElapsedTime;

        // Sign the boot image
        clock_t signStart = clock();
        if (sign_boot_image(boot_image, image_len, key, &signature, &sig_len) != 0) {
            EVP_PKEY_free(key);
            EVP_cleanup();
            return -1;
        }
        double signElapsedTime = (double)(clock() - signStart) / CLOCKS_PER_SEC;
        signTotal += signElapsedTime;

        // Verify the signature
        clock_t verifyStart = clock();
        if (verify_boot_image(boot_image, image_len, key, signature, sig_len) != 0) {
            printf("Boot image verification failed!\n");
        } else {
            printf("Boot image verification successful.\n");
        }
        double verifyElapsedTime = (double)(clock() - verifyStart) / CLOCKS_PER_SEC;
        verifyTotal += verifyElapsedTime;

        // Cleanup
        totalTime += genElapsedTime + signElapsedTime + verifyElapsedTime;
        EVP_PKEY_free(key);
        free(signature);
        
        
    }
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    printf("\nAverage key generation time: %f seconds\n", genTotal / 100);
    printf("Average signing time: %f seconds\n", signTotal / 100);
    printf("Average verification time: %f seconds\n", verifyTotal / 100);
    printf("Total time for all operations: %f seconds\n", totalTime);
    
    return 0;
}
