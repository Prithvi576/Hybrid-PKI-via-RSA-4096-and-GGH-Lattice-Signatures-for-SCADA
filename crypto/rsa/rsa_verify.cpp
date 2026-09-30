#include "crypto_api.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <memory>

namespace hybrid_pki {

bool verifyRSA(const std::string& message, const std::vector<unsigned char>& signature,
               const RSAKeyPair& key_pair) noexcept {
    if (message.empty() || signature.empty()) {
        return false;
    }
    auto* key = static_cast<EVP_PKEY*>(key_pair.public_handle.get());
    if (key == nullptr) {
        return false;
    }

    EVP_MD_CTX* raw_context = EVP_MD_CTX_new();
    if (raw_context == nullptr) {
        return false;
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(raw_context, EVP_MD_CTX_free);
    EVP_PKEY_CTX* key_context = nullptr;
    if (EVP_DigestVerifyInit(context.get(), &key_context, EVP_sha256(), nullptr, key) != 1 ||
        key_context == nullptr ||
        EVP_PKEY_CTX_set_rsa_padding(key_context, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(key_context, RSA_PSS_SALTLEN_DIGEST) <= 0 ||
        EVP_DigestVerifyUpdate(context.get(), message.data(), message.size()) != 1) {
        return false;
    }
    return EVP_DigestVerifyFinal(context.get(), signature.data(), signature.size()) == 1;
}

}  // namespace hybrid_pki
