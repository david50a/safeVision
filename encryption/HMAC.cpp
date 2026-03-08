#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <vector>
#include <stdexcept>
#include <memory>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h> 

namespace py = pybind11;

struct OpenSSLDeleter {
    void operator()(EVP_MAC* ptr) const { EVP_MAC_free(ptr); }
    void operator()(EVP_MAC_CTX* ptr) const { EVP_MAC_CTX_free(ptr); }
};

std::vector<unsigned char> hmac_sha256(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& message) 
{
    // 1. Fetch the MAC algorithm
    std::unique_ptr<EVP_MAC, OpenSSLDeleter> mac(EVP_MAC_fetch(NULL, "HMAC", NULL));
    if (!mac) throw std::runtime_error("Failed to fetch HMAC");

    // 2. Set the digest parameter (SHA256)
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    // 3. Create and initialize the context
    std::unique_ptr<EVP_MAC_CTX, OpenSSLDeleter> ctx(EVP_MAC_CTX_new(mac.get()));
    if (!ctx) throw std::runtime_error("Failed to create MAC context");

    if (EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1) {
        throw std::runtime_error("Failed to init MAC");
    }

    // 4. Update with message data
    if (EVP_MAC_update(ctx.get(), message.data(), message.size()) != 1) {
        throw std::runtime_error("Failed to update MAC");
    }

    // 5. Finalize
    unsigned char result[EVP_MAX_MD_SIZE];
    size_t result_len = 0;
    if (EVP_MAC_final(ctx.get(), result, &result_len, sizeof(result)) != 1) {
        throw std::runtime_error("Failed to finalize MAC");
    }

    return std::vector<unsigned char>(result, result + result_len);
}

PYBIND11_MODULE(hmac_lib, m) { 
    m.def("hmac_sha256", &hmac_sha256, "Compute HMAC-SHA256",
          py::arg("key"), py::arg("message"));
}