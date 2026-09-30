#include "crypto_api.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace hybrid_pki {

bool RSAKeyPair::has_private_key() const noexcept { return static_cast<bool>(private_handle); }
bool RSAKeyPair::has_public_key() const noexcept { return static_cast<bool>(public_handle); }

std::string opensslError(const char* context) {
    const unsigned long code = ERR_get_error();
    std::array<char, 256> text{};
    if (code != 0) {
        ERR_error_string_n(code, text.data(), text.size());
    }
    return std::string(context) + (code == 0 ? " failed" : ": " + std::string(text.data()));
}

std::string rsaPublicFingerprint(void* opaque_key) {
    auto* key = static_cast<EVP_PKEY*>(opaque_key);
    if (key == nullptr) {
        throw std::invalid_argument("RSA public key is missing");
    }

    unsigned char* der = nullptr;
    const int der_length = i2d_PUBKEY(key, &der);
    if (der_length <= 0 || der == nullptr) {
        throw std::runtime_error(opensslError("RSA public key encoding"));
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_length = 0;
    const int digest_ok = EVP_Digest(der, static_cast<std::size_t>(der_length), digest.data(),
                                     &digest_length, EVP_sha256(), nullptr);
    OPENSSL_free(der);
    if (digest_ok != 1) {
        throw std::runtime_error(opensslError("RSA fingerprint"));
    }

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < 10 && index < digest_length; ++index) {
        output << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }
    return output.str();
}

}  // namespace hybrid_pki
