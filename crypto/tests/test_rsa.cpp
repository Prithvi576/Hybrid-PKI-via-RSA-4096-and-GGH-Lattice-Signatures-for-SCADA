#include "crypto_api.hpp"

#include <exception>
#include <iostream>
#include <stdexcept>

namespace {
void require(const bool condition, const char* detail) {
    if (!condition) {
        throw std::runtime_error(detail);
    }
}
}  // namespace

int main() {
    try {
        const auto key_pair = hybrid_pki::generateRSAKeyPair();
        require(key_pair.has_private_key() && key_pair.has_public_key(), "RSA key generation failed");
        require(!key_pair.public_fingerprint.empty(), "RSA fingerprint missing");

        const std::string message = "COMMAND=OPEN_VALVE\nTIMESTAMP=2026-09-28T00:00:00Z\nSEQUENCE=1\n";
        const auto signature = hybrid_pki::signRSA(message, key_pair);
        require(signature.size() == 512, "RSA-4096 signature size is not 512 bytes");
        require(hybrid_pki::verifyRSA(message, signature, key_pair), "RSA verification failed");
        require(!hybrid_pki::verifyRSA(message + "X", signature, key_pair),
                "RSA accepted a modified message");

        const auto other_key_pair = hybrid_pki::generateRSAKeyPair();
        require(!hybrid_pki::verifyRSA(message, signature, other_key_pair),
                "RSA accepted a wrong public key");
        require(!hybrid_pki::verifyRSA(message, {0x01, 0x02, 0x03}, key_pair),
                "RSA accepted a malformed signature");
        bool empty_rejected = false;
        try {
            static_cast<void>(hybrid_pki::signRSA("", key_pair));
        } catch (const std::exception&) {
            empty_rejected = true;
        }
        require(empty_rejected, "RSA accepted empty input");
        std::cout << "RSA tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "RSA test failure: " << error.what() << '\n';
        return 1;
    }
}
