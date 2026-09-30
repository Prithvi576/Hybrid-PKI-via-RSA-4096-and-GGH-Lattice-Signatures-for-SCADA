#include "crypto_api.hpp"

#include <chrono>
#include <stdexcept>

namespace hybrid_pki {

namespace {
void validateField(const std::string& value, const char* name, const std::size_t maximum_length) {
    if (value.empty() || value.size() > maximum_length || value.find_first_of("\r\n") != std::string::npos) {
        throw std::invalid_argument(std::string("invalid ") + name);
    }
}
}  // namespace

std::string canonicalize(const CommandEnvelope& envelope) {
    validateField(envelope.command, "command", 128);
    validateField(envelope.timestamp_utc, "timestamp", 64);
    return "COMMAND_LENGTH=" + std::to_string(envelope.command.size()) + "\nCOMMAND=" +
           envelope.command + "\nTIMESTAMP_LENGTH=" + std::to_string(envelope.timestamp_utc.size()) +
           "\nTIMESTAMP=" + envelope.timestamp_utc + "\nSEQUENCE=" +
           std::to_string(envelope.sequence) + "\n";
}

HybridSigningResult hybridSign(const CommandEnvelope& envelope, const RSAKeyPair& rsa_key_pair,
                               const GGHKeyPair& ggh_key_pair) {
    const std::string message = canonicalize(envelope);
    const auto hybrid_start = std::chrono::steady_clock::now();
    const auto rsa_start = std::chrono::steady_clock::now();
    auto rsa_signature = signRSA(message, rsa_key_pair);
    const auto rsa_end = std::chrono::steady_clock::now();
    const auto ggh_start = std::chrono::steady_clock::now();
    auto ggh_signature = signGGH(message, ggh_key_pair);
    const auto ggh_end = std::chrono::steady_clock::now();

    HybridSigningResult result;
    result.signed_command = {envelope, std::move(rsa_signature), std::move(ggh_signature)};
    result.measurements.rsa = std::chrono::duration_cast<std::chrono::nanoseconds>(rsa_end - rsa_start);
    result.measurements.ggh = std::chrono::duration_cast<std::chrono::nanoseconds>(ggh_end - ggh_start);
    result.measurements.hybrid =
        std::chrono::duration_cast<std::chrono::nanoseconds>(ggh_end - hybrid_start);
    return result;
}

}  // namespace hybrid_pki
