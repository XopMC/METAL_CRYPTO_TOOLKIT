#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace bls12_381 {

using SecretKey = std::array<std::uint8_t, 32>;
using PublicKey = std::array<std::uint8_t, 48>;
using PublicKeyUncompressed = std::array<std::uint8_t, 96>;

bool valid_secret_key(const SecretKey& secret);

bool keygen(
    const std::uint8_t* ikm,
    std::size_t ikm_size,
    const std::uint8_t* info,
    std::size_t info_size,
    SecretKey& secret,
    std::string& error);

bool eip2333_master(
    const std::uint8_t* seed,
    std::size_t seed_size,
    SecretKey& secret,
    std::string& error);

bool eip2333_child(
    const SecretKey& parent,
    std::uint32_t child_index,
    SecretKey& child,
    std::string& error);

bool scalar_add_mod(
    const SecretKey& lhs,
    const SecretKey& rhs,
    SecretKey& result);

bool scalar_multiply_mod(
    const SecretKey& lhs,
    const SecretKey& rhs,
    SecretKey& result);

bool public_key_compressed(
    const SecretKey& secret,
    PublicKey& public_key,
    std::string& error);

bool public_key_uncompressed(
    const SecretKey& secret,
    PublicKeyUncompressed& public_key,
    std::string& error);

bool public_keys_compressed(
    const SecretKey* secrets,
    std::size_t count,
    PublicKey* public_keys,
    std::string& error);

void clear_secret(SecretKey& secret);

}  // namespace bls12_381
