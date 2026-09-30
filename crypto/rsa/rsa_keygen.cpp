#include "crypto_api.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <memory>
#include <stdexcept>

namespace hybrid_pki {

std::string opensslError(const char* context);
std::string rsaPublicFingerprint(void* opaque_key);

RSAKeyPair generateRSAKeyPair() {
    EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (raw_context == nullptr) {
        throw std::runtime_error(opensslError("RSA key-generation context"));
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(raw_context,
                                                                          EVP_PKEY_CTX_free);
    if (EVP_PKEY_keygen_init(context.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 4096) <= 0) {
        throw std::runtime_error(opensslError("RSA-4096 key-generation setup"));
    }

    EVP_PKEY* raw_key = nullptr;
    if (EVP_PKEY_generate(context.get(), &raw_key) <= 0 || raw_key == nullptr) {
        throw std::runtime_error(opensslError("RSA-4096 key generation"));
    }

    std::shared_ptr<void> private_key(raw_key, [](void* value) {
        EVP_PKEY_free(static_cast<EVP_PKEY*>(value));
    });
    if (EVP_PKEY_up_ref(raw_key) != 1) {
        throw std::runtime_error(opensslError("RSA public-key reference"));
    }
    std::shared_ptr<void> public_key(raw_key, [](void* value) {
        EVP_PKEY_free(static_cast<EVP_PKEY*>(value));
    });

    RSAKeyPair result;
    result.private_handle = std::move(private_key);
    result.public_handle = std::move(public_key);
    result.public_fingerprint = rsaPublicFingerprint(result.public_handle.get());
    return result;
}

}  // namespace hybrid_pki
