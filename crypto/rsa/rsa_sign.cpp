#include "crypto_api.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <memory>
#include <stdexcept>

namespace hybrid_pki {

std::string opensslError(const char* context);

std::vector<unsigned char> signRSA(const std::string& message, const RSAKeyPair& key_pair) {
    if (message.empty()) {
        throw std::invalid_argument("RSA refuses an empty canonical message");
    }
    auto* key = static_cast<EVP_PKEY*>(key_pair.private_handle.get());
    if (key == nullptr) {
        throw std::invalid_argument("RSA private key is unavailable");
    }

    EVP_MD_CTX* raw_context = EVP_MD_CTX_new();
    if (raw_context == nullptr) {
        throw std::runtime_error(opensslError("RSA signing context"));
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(raw_context, EVP_MD_CTX_free);
    EVP_PKEY_CTX* key_context = nullptr;
    if (EVP_DigestSignInit(context.get(), &key_context, EVP_sha256(), nullptr, key) != 1 ||
        key_context == nullptr ||
        EVP_PKEY_CTX_set_rsa_padding(key_context, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(key_context, RSA_PSS_SALTLEN_DIGEST) <= 0 ||
        EVP_DigestSignUpdate(context.get(), message.data(), message.size()) != 1) {
        throw std::runtime_error(opensslError("RSA-PSS signing setup"));
    }

    std::size_t signature_length = 0;
    if (EVP_DigestSignFinal(context.get(), nullptr, &signature_length) != 1 || signature_length == 0) {
        throw std::runtime_error(opensslError("RSA-PSS signature sizing"));
    }
    std::vector<unsigned char> signature(signature_length);
    if (EVP_DigestSignFinal(context.get(), signature.data(), &signature_length) != 1) {
        throw std::runtime_error(opensslError("RSA-PSS signing"));
    }
    signature.resize(signature_length);
    return signature;
}

}  // namespace hybrid_pki
