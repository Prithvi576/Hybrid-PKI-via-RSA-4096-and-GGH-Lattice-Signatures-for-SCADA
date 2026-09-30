#include "crypto_api.hpp"

#include <stdexcept>

namespace hybrid_pki {

std::vector<std::int64_t> gghHashTarget(const std::string& message, std::size_t dimension);
std::vector<std::int64_t> gghRoundToLattice(const std::vector<std::int64_t>& target,
                                            const std::vector<std::int64_t>& short_basis,
                                            std::size_t dimension);

GGHSignature signGGH(const std::string& message, const GGHKeyPair& key_pair) {
    if (!key_pair.private_key || key_pair.private_key->dimension == 0) {
        throw std::invalid_argument("GGH private key is unavailable");
    }
    const auto target = gghHashTarget(message, key_pair.private_key->dimension);
    return {gghRoundToLattice(target, key_pair.private_key->short_basis,
                              key_pair.private_key->dimension)};
}

}  // namespace hybrid_pki
