#include "crypto_api.hpp"

#include <cmath>

namespace hybrid_pki {

std::vector<std::int64_t> gghHashTarget(const std::string& message, std::size_t dimension);
bool gghIsPublicLatticePoint(const std::vector<std::int64_t>& point,
                             const std::vector<std::int64_t>& bad_basis,
                             std::size_t dimension) noexcept;
long double gghDistanceSquared(const std::vector<std::int64_t>& left,
                               const std::vector<std::int64_t>& right) noexcept;

bool verifyGGH(const std::string& message, const GGHSignature& signature,
               const GGHKeyPair& key_pair) noexcept {
    try {
        if (message.empty() || !key_pair.public_key ||
            signature.lattice_point.size() != key_pair.public_key->dimension) {
            return false;
        }
        const auto target = gghHashTarget(message, key_pair.public_key->dimension);
        return gghIsPublicLatticePoint(signature.lattice_point, key_pair.public_key->bad_basis,
                                       key_pair.public_key->dimension) &&
               gghDistanceSquared(signature.lattice_point, target) <=
                   key_pair.public_key->maximum_distance_squared;
    } catch (...) {
        return false;
    }
}

}  // namespace hybrid_pki
