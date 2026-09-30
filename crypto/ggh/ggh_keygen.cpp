#include "crypto_api.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace hybrid_pki {

namespace {
constexpr std::size_t kDimension = 16;

std::int64_t secureInteger(const std::int64_t minimum, const std::int64_t maximum) {
    const auto span = static_cast<std::uint64_t>(maximum - minimum + 1);
    const auto limit = std::numeric_limits<std::uint64_t>::max() -
                       (std::numeric_limits<std::uint64_t>::max() % span);
    std::uint64_t value = 0;
    do {
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
            throw std::runtime_error("OpenSSL secure random generation failed for GGH");
        }
    } while (value >= limit);
    return minimum + static_cast<std::int64_t>(value % span);
}

std::vector<std::int64_t> multiply(const std::vector<std::int64_t>& left,
                                   const std::vector<std::int64_t>& right) {
    std::vector<std::int64_t> result(kDimension * kDimension, 0);
    for (std::size_t row = 0; row < kDimension; ++row) {
        for (std::size_t column = 0; column < kDimension; ++column) {
            long double value = 0.0L;
            for (std::size_t index = 0; index < kDimension; ++index) {
                value += static_cast<long double>(left[row * kDimension + index]) *
                         static_cast<long double>(right[index * kDimension + column]);
            }
            if (value > std::numeric_limits<std::int64_t>::max() ||
                value < std::numeric_limits<std::int64_t>::min()) {
                throw std::overflow_error("GGH public-basis generation overflow");
            }
            result[row * kDimension + column] = static_cast<std::int64_t>(std::llround(value));
        }
    }
    return result;
}
}  // namespace

GGHKeyPair generateGGHKeyPair() {
    auto private_key = std::make_shared<GGHPrivateKey>();
    private_key->dimension = kDimension;
    private_key->short_basis.assign(kDimension * kDimension, 0);
    for (std::size_t row = 0; row < kDimension; ++row) {
        for (std::size_t column = 0; column < kDimension; ++column) {
            private_key->short_basis[row * kDimension + column] =
                row == column ? 59 : secureInteger(-3, 3);
        }
    }

    std::vector<std::int64_t> unimodular(kDimension * kDimension, 0);
    for (std::size_t index = 0; index < kDimension; ++index) {
        unimodular[index * kDimension + index] = 1;
    }
    // Elementary row additions preserve determinant ±1 and therefore the lattice.
    for (std::size_t operation = 0; operation < kDimension * 8; ++operation) {
        const auto destination = static_cast<std::size_t>(secureInteger(0, kDimension - 1));
        std::size_t source = static_cast<std::size_t>(secureInteger(0, kDimension - 1));
        while (source == destination) {
            source = static_cast<std::size_t>(secureInteger(0, kDimension - 1));
        }
        const auto multiplier = secureInteger(-2, 2);
        if (multiplier == 0) {
            continue;
        }
        for (std::size_t column = 0; column < kDimension; ++column) {
            const long double value =
                static_cast<long double>(unimodular[destination * kDimension + column]) +
                static_cast<long double>(multiplier) *
                    static_cast<long double>(unimodular[source * kDimension + column]);
            if (value > std::numeric_limits<std::int64_t>::max() ||
                value < std::numeric_limits<std::int64_t>::min()) {
                throw std::overflow_error("GGH unimodular transform overflow");
            }
            unimodular[destination * kDimension + column] = static_cast<std::int64_t>(std::llround(value));
        }
    }

    auto public_key = std::make_shared<GGHPublicKey>();
    public_key->dimension = kDimension;
    public_key->bad_basis = multiply(unimodular, private_key->short_basis);
    public_key->maximum_distance_squared = 0.0L;
    for (std::size_t column = 0; column < kDimension; ++column) {
        long double coordinate_bound = 0.0L;
        for (std::size_t row = 0; row < kDimension; ++row) {
            coordinate_bound += std::fabs(static_cast<long double>(
                private_key->short_basis[row * kDimension + column]));
        }
        public_key->maximum_distance_squared +=
            (coordinate_bound * 0.5L) * (coordinate_bound * 0.5L);
    }
    public_key->maximum_distance_squared += 1e-6L;

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_length = 0;
    if (EVP_Digest(public_key->bad_basis.data(),
                   public_key->bad_basis.size() * sizeof(std::int64_t), digest.data(), &digest_length,
                   EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("GGH public-key fingerprinting failed");
    }
    std::ostringstream fingerprint;
    fingerprint << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < 10 && index < digest_length; ++index) {
        fingerprint << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }

    GGHKeyPair result;
    result.private_key = std::move(private_key);
    result.public_key = std::move(public_key);
    result.public_fingerprint = fingerprint.str();
    return result;
}

}  // namespace hybrid_pki
