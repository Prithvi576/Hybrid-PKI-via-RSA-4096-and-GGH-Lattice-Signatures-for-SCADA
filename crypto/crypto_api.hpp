#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hybrid_pki {

struct GGHKeyPair;
struct GGHSignature;

struct GGHPrivateKey {
private:
    std::vector<std::int64_t> short_basis;
    std::size_t dimension{};

    friend GGHKeyPair generateGGHKeyPair();
    friend GGHSignature signGGH(const std::string&, const GGHKeyPair&);
};

struct GGHPublicKey {
private:
    std::vector<std::int64_t> bad_basis;
    std::size_t dimension{};
    long double maximum_distance_squared{};

    friend GGHKeyPair generateGGHKeyPair();
    friend bool verifyGGH(const std::string&, const GGHSignature&, const GGHKeyPair&) noexcept;
};

struct RSAKeyPair {
    // OpenSSL-owned handles are intentionally opaque to callers.
    std::shared_ptr<void> private_handle;
    std::shared_ptr<void> public_handle;
    std::string public_fingerprint;

    [[nodiscard]] bool has_private_key() const noexcept;
    [[nodiscard]] bool has_public_key() const noexcept;
};

struct GGHKeyPair {
    // The private basis stays inside the implementation; callers cannot inspect it.
    std::shared_ptr<GGHPrivateKey> private_key;
    std::shared_ptr<GGHPublicKey> public_key;
    std::string public_fingerprint;

    [[nodiscard]] bool has_private_key() const noexcept;
    [[nodiscard]] bool has_public_key() const noexcept;
};

struct GGHSignature {
    std::vector<std::int64_t> lattice_point;
};

struct CommandEnvelope {
    std::string command;
    std::string timestamp_utc;
    std::uint64_t sequence{};
};

struct HybridSignedCommand {
    CommandEnvelope envelope;
    std::vector<unsigned char> rsa_signature;
    GGHSignature ggh_signature;
};

struct OperationMeasurements {
    std::chrono::nanoseconds rsa{};
    std::chrono::nanoseconds ggh{};
    std::chrono::nanoseconds hybrid{};
};

struct HybridSigningResult {
    HybridSignedCommand signed_command;
    OperationMeasurements measurements;
};

struct HybridVerificationResult {
    bool rsa_valid{};
    bool ggh_valid{};
    bool overall_valid{};
    OperationMeasurements measurements;
};

// RSA-PSS/SHA-256. The implementation generates exactly 4096-bit RSA keys.
RSAKeyPair generateRSAKeyPair();
std::vector<unsigned char> signRSA(const std::string& message, const RSAKeyPair& key_pair);
bool verifyRSA(const std::string& message, const std::vector<unsigned char>& signature,
               const RSAKeyPair& key_pair) noexcept;

// Educational GGH hash-and-sign implementation. It is deliberately not presented as
// a modern or production-secure post-quantum signature scheme.
GGHKeyPair generateGGHKeyPair();
GGHSignature signGGH(const std::string& message, const GGHKeyPair& key_pair);
bool verifyGGH(const std::string& message, const GGHSignature& signature,
               const GGHKeyPair& key_pair) noexcept;
std::size_t gghSignatureSize(const GGHSignature& signature) noexcept;
std::string gghConfiguration();

std::string canonicalize(const CommandEnvelope& envelope);
HybridSigningResult hybridSign(const CommandEnvelope& envelope, const RSAKeyPair& rsa_key_pair,
                               const GGHKeyPair& ggh_key_pair);
HybridVerificationResult hybridVerify(const HybridSignedCommand& command,
                                      const RSAKeyPair& rsa_key_pair,
                                      const GGHKeyPair& ggh_key_pair) noexcept;

}  // namespace hybrid_pki
