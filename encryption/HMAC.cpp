#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <stdexcept>

std::vector<unsigned char> hmac_sha256(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& message)
{
    // OpenSSL 3.0+ uses EVP_MAC
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        throw std::runtime_error("Failed to fetch HMAC");
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        EVP_MAC_free(mac);
        throw std::runtime_error("Failed to create MAC context");
    }

    // Initialize with the key
    if (EVP_MAC_init(ctx, key.data(), key.size(), params) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw std::runtime_error("Failed to init MAC");
    }

    // Update with message
    if (EVP_MAC_update(ctx, message.data(), message.size()) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw std::runtime_error("Failed to update MAC");
    }

    // Finalize
    unsigned char result[EVP_MAX_MD_SIZE];
    size_t result_len = 0;
    if (EVP_MAC_final(ctx, result, &result_len, sizeof(result)) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw std::runtime_error("Failed to finalize MAC");
    }

    // Cleanup
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return std::vector<unsigned char>(result, result + result_len);
}