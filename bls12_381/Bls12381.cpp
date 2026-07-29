#include "Bls12381.h"

#include "third_party/blst/bindings/blst.h"
#include "third_party/blst/bindings/blst_aux.h"

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>

#include <algorithm>
#include <vector>

namespace bls12_381 {
namespace {

bool scalar_from_secret(const SecretKey& bytes, blst_scalar& scalar) {
    blst_scalar_from_bendian(&scalar, bytes.data());
    std::array<std::uint8_t, 32> canonical{};
    blst_bendian_from_scalar(canonical.data(), &scalar);
    unsigned int difference = 0u;
    for (std::size_t index = 0; index < canonical.size(); ++index) {
        difference |=
            static_cast<unsigned int>(canonical[index] ^ bytes[index]);
    }
    return difference == 0u && blst_sk_check(&scalar);
}

void scalar_to_secret(const blst_scalar& scalar, SecretKey& bytes) {
    blst_bendian_from_scalar(bytes.data(), &scalar);
}

bool validate_seed(
    const std::uint8_t* seed,
    std::size_t seed_size,
    const char* label,
    std::string& error) {
    if (seed == nullptr) {
        error = std::string(label) + " pointer is null";
        return false;
    }
    if (seed_size < 32u) {
        error = std::string(label) + " must contain at least 32 bytes";
        return false;
    }
    return true;
}

void hmac_sha256(
    const std::uint8_t* key,
    std::size_t key_size,
    const std::uint8_t* data,
    std::size_t data_size,
    std::uint8_t output[32]) {
    CCHmac(
        kCCHmacAlgSHA256,
        key,
        key_size,
        data,
        data_size,
        output);
}

void chia_legacy_hkdf_expand(
    const std::uint8_t ikm[32],
    const std::uint8_t salt[4],
    std::array<std::uint8_t, 255u * 32u>& output) {
    std::array<std::uint8_t, 32> prk{};
    hmac_sha256(
        salt, 4u, ikm, 32u, prk.data());
    std::array<std::uint8_t, 33> block_input{};
    std::array<std::uint8_t, 32> block{};
    for (std::size_t index = 0u; index < 255u; ++index) {
        std::size_t input_size = 1u;
        if (index != 0u) {
            std::copy(
                block.begin(), block.end(),
                block_input.begin());
            input_size += block.size();
        }
        block_input[input_size - 1u] =
            static_cast<std::uint8_t>(index + 1u);
        hmac_sha256(
            prk.data(),
            prk.size(),
            block_input.data(),
            input_size,
            block.data());
        std::copy(
            block.begin(), block.end(),
            output.begin() +
                static_cast<std::ptrdiff_t>(
                    index * block.size()));
    }
    std::fill(prk.begin(), prk.end(), 0u);
    std::fill(block.begin(), block.end(), 0u);
    std::fill(block_input.begin(), block_input.end(), 0u);
}

}  // namespace

bool valid_secret_key(const SecretKey& secret) {
    blst_scalar scalar{};
    return scalar_from_secret(secret, scalar);
}

bool keygen(
    const std::uint8_t* ikm,
    std::size_t ikm_size,
    const std::uint8_t* info,
    std::size_t info_size,
    SecretKey& secret,
    std::string& error) {
    if (!validate_seed(ikm, ikm_size, "IKM", error)) return false;
    if (info_size != 0u && info == nullptr) {
        error = "key-info pointer is null";
        return false;
    }
    blst_scalar scalar{};
    blst_keygen(&scalar, ikm, ikm_size, info, info_size);
    if (!blst_sk_check(&scalar)) {
        error = "BLS KeyGen produced an invalid scalar";
        return false;
    }
    scalar_to_secret(scalar, secret);
    error.clear();
    return true;
}

bool eip2333_master(
    const std::uint8_t* seed,
    std::size_t seed_size,
    SecretKey& secret,
    std::string& error) {
    if (!validate_seed(seed, seed_size, "EIP-2333 seed", error)) {
        return false;
    }
    blst_scalar scalar{};
    blst_derive_master_eip2333(&scalar, seed, seed_size);
    if (!blst_sk_check(&scalar)) {
        error = "EIP-2333 master derivation produced an invalid scalar";
        return false;
    }
    scalar_to_secret(scalar, secret);
    error.clear();
    return true;
}

bool eip2333_child(
    const SecretKey& parent,
    std::uint32_t child_index,
    SecretKey& child,
    std::string& error) {
    blst_scalar parent_scalar{};
    if (!scalar_from_secret(parent, parent_scalar)) {
        error = "EIP-2333 parent scalar is invalid";
        return false;
    }
    blst_scalar child_scalar{};
    blst_derive_child_eip2333(
        &child_scalar, &parent_scalar, child_index);
    if (!blst_sk_check(&child_scalar)) {
        error = "EIP-2333 child derivation produced an invalid scalar";
        return false;
    }
    scalar_to_secret(child_scalar, child);
    error.clear();
    return true;
}

bool chia_legacy_master(
    const std::uint8_t* seed,
    std::size_t seed_size,
    SecretKey& secret,
    std::string& error) {
    if (!validate_seed(seed, seed_size, "Chia BLS seed", error)) {
        return false;
    }
    blst_scalar scalar{};
    blst_keygen_v3(
        &scalar, seed, seed_size, nullptr, 0u);
    if (!blst_sk_check(&scalar)) {
        error = "Chia BLS master derivation produced an invalid scalar";
        return false;
    }
    scalar_to_secret(scalar, secret);
    error.clear();
    return true;
}

bool chia_legacy_child(
    const SecretKey& parent,
    std::uint32_t child_index,
    SecretKey& child,
    std::string& error) {
    if (!valid_secret_key(parent)) {
        error = "Chia BLS parent scalar is invalid";
        return false;
    }
    const std::array<std::uint8_t, 4> salt = {
        static_cast<std::uint8_t>(child_index >> 24u),
        static_cast<std::uint8_t>(child_index >> 16u),
        static_cast<std::uint8_t>(child_index >> 8u),
        static_cast<std::uint8_t>(child_index),
    };
    std::array<std::uint8_t, 32> inverted_parent{};
    for (std::size_t index = 0u;
         index < inverted_parent.size(); ++index) {
        inverted_parent[index] =
            static_cast<std::uint8_t>(parent[index] ^ 0xffu);
    }
    std::array<std::uint8_t, 255u * 32u> lamport_zero{};
    std::array<std::uint8_t, 255u * 32u> lamport_one{};
    chia_legacy_hkdf_expand(
        parent.data(), salt.data(), lamport_zero);
    chia_legacy_hkdf_expand(
        inverted_parent.data(), salt.data(), lamport_one);

    std::vector<std::uint8_t> lamport_public_key(
        2u * 255u * 32u);
    for (std::size_t index = 0u; index < 255u; ++index) {
        CC_SHA256(
            lamport_zero.data() + index * 32u,
            32u,
            lamport_public_key.data() + index * 32u);
        CC_SHA256(
            lamport_one.data() + index * 32u,
            32u,
            lamport_public_key.data() +
                (index + 255u) * 32u);
    }
    std::array<std::uint8_t, 32> lamport_digest{};
    CC_SHA256(
        lamport_public_key.data(),
        static_cast<CC_LONG>(lamport_public_key.size()),
        lamport_digest.data());
    const bool result = chia_legacy_master(
        lamport_digest.data(),
        lamport_digest.size(),
        child,
        error);
    std::fill(
        inverted_parent.begin(), inverted_parent.end(), 0u);
    std::fill(
        lamport_zero.begin(), lamport_zero.end(), 0u);
    std::fill(
        lamport_one.begin(), lamport_one.end(), 0u);
    std::fill(
        lamport_public_key.begin(),
        lamport_public_key.end(),
        0u);
    std::fill(
        lamport_digest.begin(), lamport_digest.end(), 0u);
    return result;
}

bool scalar_add_mod(
    const SecretKey& lhs,
    const SecretKey& rhs,
    SecretKey& result) {
    blst_scalar lhs_scalar{};
    blst_scalar rhs_scalar{};
    if (!scalar_from_secret(lhs, lhs_scalar) ||
        !scalar_from_secret(rhs, rhs_scalar)) {
        return false;
    }
    blst_fr lhs_fr{};
    blst_fr rhs_fr{};
    blst_fr sum{};
    blst_fr_from_scalar(&lhs_fr, &lhs_scalar);
    blst_fr_from_scalar(&rhs_fr, &rhs_scalar);
    blst_fr_add(&sum, &lhs_fr, &rhs_fr);
    blst_scalar output{};
    blst_scalar_from_fr(&output, &sum);
    scalar_to_secret(output, result);
    return true;
}

bool scalar_add_bytes_mod(
    const SecretKey& lhs,
    const std::uint8_t* rhs,
    std::size_t rhs_size,
    SecretKey& result,
    std::string& error) {
    if (rhs == nullptr || rhs_size == 0u) {
        error = "BLS scalar addend is empty";
        return false;
    }
    blst_scalar lhs_scalar{};
    if (!scalar_from_secret(lhs, lhs_scalar)) {
        error = "BLS scalar add parent is invalid";
        return false;
    }
    blst_scalar rhs_scalar{};
    if (!blst_scalar_from_be_bytes(
            &rhs_scalar, rhs, rhs_size)) {
        error = "BLS scalar addend reduction failed";
        return false;
    }
    blst_scalar output{};
    if (!blst_sk_add_n_check(
            &output, &lhs_scalar, &rhs_scalar)) {
        error = "BLS scalar addition produced zero";
        return false;
    }
    scalar_to_secret(output, result);
    error.clear();
    return true;
}

bool scalar_multiply_mod(
    const SecretKey& lhs,
    const SecretKey& rhs,
    SecretKey& result) {
    blst_scalar lhs_scalar{};
    blst_scalar rhs_scalar{};
    if (!scalar_from_secret(lhs, lhs_scalar) ||
        !scalar_from_secret(rhs, rhs_scalar)) {
        return false;
    }
    blst_fr lhs_fr{};
    blst_fr rhs_fr{};
    blst_fr product{};
    blst_fr_from_scalar(&lhs_fr, &lhs_scalar);
    blst_fr_from_scalar(&rhs_fr, &rhs_scalar);
    blst_fr_mul(&product, &lhs_fr, &rhs_fr);
    blst_scalar output{};
    blst_scalar_from_fr(&output, &product);
    scalar_to_secret(output, result);
    return true;
}

bool public_key_compressed(
    const SecretKey& secret,
    PublicKey& public_key,
    std::string& error) {
    blst_scalar scalar{};
    if (!scalar_from_secret(secret, scalar)) {
        error = "BLS secret scalar is invalid";
        return false;
    }
    std::array<std::uint8_t, 96> serialized{};
    blst_sk_to_pk2_in_g1(serialized.data(), nullptr, &scalar);
    serialized[0] |= 0x80u;
    std::copy_n(serialized.begin(), public_key.size(), public_key.begin());
    error.clear();
    return true;
}

bool valid_public_key_compressed(
    const PublicKey& public_key) {
    blst_p1_affine point{};
    if (blst_p1_uncompress(
            &point, public_key.data()) != BLST_SUCCESS ||
        blst_p1_affine_is_inf(&point)) {
        return false;
    }

    // The min-pk build intentionally omits map_to_g1.c, including its
    // convenience subgroup predicate. Check subgroup membership directly:
    // a valid G1 public key is annihilated by the BLS12-381 scalar order.
    static constexpr std::array<std::uint8_t, 32> scalar_order_le = {
        0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
        0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
        0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
    };
    blst_p1 projective{};
    blst_p1 order_multiple{};
    blst_p1_from_affine(&projective, &point);
    blst_p1_mult(
        &order_multiple,
        &projective,
        scalar_order_le.data(),
        255u);
    return blst_p1_is_inf(&order_multiple);
}

bool public_key_uncompressed(
    const SecretKey& secret,
    PublicKeyUncompressed& public_key,
    std::string& error) {
    blst_scalar scalar{};
    if (!scalar_from_secret(secret, scalar)) {
        error = "BLS secret scalar is invalid";
        return false;
    }
    blst_p1 point{};
    blst_sk_to_pk_in_g1(&point, &scalar);
    blst_p1_serialize(public_key.data(), &point);
    error.clear();
    return true;
}

bool public_keys_compressed(
    const SecretKey* secrets,
    std::size_t count,
    PublicKey* public_keys,
    std::string& error) {
    if (count != 0u && (secrets == nullptr || public_keys == nullptr)) {
        error = "BLS batch buffers are null";
        return false;
    }
    for (std::size_t index = 0; index < count; ++index) {
        if (!public_key_compressed(
                secrets[index], public_keys[index], error)) {
            error += " at batch index " + std::to_string(index);
            return false;
        }
    }
    error.clear();
    return true;
}

void clear_secret(SecretKey& secret) {
    volatile std::uint8_t* bytes = secret.data();
    for (std::size_t index = 0; index < secret.size(); ++index) {
        bytes[index] = 0u;
    }
}

}  // namespace bls12_381
