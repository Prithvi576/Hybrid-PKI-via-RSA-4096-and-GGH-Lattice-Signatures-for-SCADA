#include "crypto_api.hpp"

#include <chrono>

namespace hybrid_pki {

HybridVerificationResult hybridVerify(const HybridSignedCommand& command,
                                      const RSAKeyPair& rsa_key_pair,
                                      const GGHKeyPair& ggh_key_pair) noexcept {
    HybridVerificationResult result;
    try {
        const auto hybrid_start = std::chrono::steady_clock::now();
        const std::string message = canonicalize(command.envelope);
        const auto rsa_start = std::chrono::steady_clock::now();
        result.rsa_valid = verifyRSA(message, command.rsa_signature, rsa_key_pair);
        const auto rsa_end = std::chrono::steady_clock::now();
        const auto ggh_start = std::chrono::steady_clock::now();
        result.ggh_valid = verifyGGH(message, command.ggh_signature, ggh_key_pair);
        const auto ggh_end = std::chrono::steady_clock::now();
        result.overall_valid = result.rsa_valid && result.ggh_valid;
        result.measurements.rsa =
            std::chrono::duration_cast<std::chrono::nanoseconds>(rsa_end - rsa_start);
        result.measurements.ggh =
            std::chrono::duration_cast<std::chrono::nanoseconds>(ggh_end - ggh_start);
        result.measurements.hybrid =
            std::chrono::duration_cast<std::chrono::nanoseconds>(ggh_end - hybrid_start);
    } catch (...) {
        result = {};
    }
    return result;
}

}  // namespace hybrid_pki
