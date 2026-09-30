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
        const auto key_pair = hybrid_pki::generateGGHKeyPair();
        require(key_pair.has_private_key() && key_pair.has_public_key(), "GGH key generation failed");
        require(!key_pair.public_fingerprint.empty(), "GGH fingerprint missing");

        const std::string message = "COMMAND=OPEN_VALVE\nTIMESTAMP=2026-09-28T00:00:00Z\nSEQUENCE=1\n";
        const auto signature = hybrid_pki::signGGH(message, key_pair);
        require(hybrid_pki::gghSignatureSize(signature) == 128, "unexpected GGH signature size");
        require(hybrid_pki::verifyGGH(message, signature, key_pair), "GGH verification failed");
        require(!hybrid_pki::verifyGGH(message + "X", signature, key_pair),
                "GGH accepted a modified message");

        auto corrupted = signature;
        corrupted.lattice_point[0] += 1;
        require(!hybrid_pki::verifyGGH(message, corrupted, key_pair),
                "GGH accepted a corrupted signature");
        const auto other_key_pair = hybrid_pki::generateGGHKeyPair();
        require(!hybrid_pki::verifyGGH(message, signature, other_key_pair),
                "GGH accepted a wrong public key");
        require(!hybrid_pki::verifyGGH(message, {}, key_pair), "GGH accepted a malformed signature");
        bool empty_rejected = false;
        try {
            static_cast<void>(hybrid_pki::signGGH("", key_pair));
        } catch (const std::exception&) {
            empty_rejected = true;
        }
        require(empty_rejected, "GGH accepted empty input");
        std::cout << "GGH tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "GGH test failure: " << error.what() << '\n';
        return 1;
    }
}
