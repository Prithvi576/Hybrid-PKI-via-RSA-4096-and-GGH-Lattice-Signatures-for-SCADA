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
        const auto rsa_key_pair = hybrid_pki::generateRSAKeyPair();
        const auto ggh_key_pair = hybrid_pki::generateGGHKeyPair();
        const hybrid_pki::CommandEnvelope original{"OPEN_VALVE", "2026-09-28T00:00:00Z", 105};
        auto result = hybrid_pki::hybridSign(original, rsa_key_pair, ggh_key_pair);
        auto verification = hybrid_pki::hybridVerify(result.signed_command, rsa_key_pair, ggh_key_pair);
        require(verification.rsa_valid && verification.ggh_valid && verification.overall_valid,
                "hybrid verification failed");

        auto altered = result.signed_command;
        altered.envelope.command = "CLOSE_VALVE";
        verification = hybrid_pki::hybridVerify(altered, rsa_key_pair, ggh_key_pair);
        require(!verification.rsa_valid && !verification.ggh_valid && !verification.overall_valid,
                "hybrid accepted a modified command");
        altered = result.signed_command;
        altered.envelope.timestamp_utc = "2026-09-28T00:00:01Z";
        require(!hybrid_pki::hybridVerify(altered, rsa_key_pair, ggh_key_pair).overall_valid,
                "hybrid accepted a modified timestamp");
        altered = result.signed_command;
        ++altered.envelope.sequence;
        require(!hybrid_pki::hybridVerify(altered, rsa_key_pair, ggh_key_pair).overall_valid,
                "hybrid accepted a modified sequence");
        altered = result.signed_command;
        altered.rsa_signature[0] ^= 0x01;
        verification = hybrid_pki::hybridVerify(altered, rsa_key_pair, ggh_key_pair);
        require(!verification.rsa_valid && verification.ggh_valid && !verification.overall_valid,
                "hybrid did not detect a corrupted RSA signature");
        altered = result.signed_command;
        altered.ggh_signature.lattice_point[0] += 1;
        verification = hybrid_pki::hybridVerify(altered, rsa_key_pair, ggh_key_pair);
        require(verification.rsa_valid && !verification.ggh_valid && !verification.overall_valid,
                "hybrid did not detect a corrupted GGH signature");
        std::cout << "Hybrid tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Hybrid test failure: " << error.what() << '\n';
        return 1;
    }
}
