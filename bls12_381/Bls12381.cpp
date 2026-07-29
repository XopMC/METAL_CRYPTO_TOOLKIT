#include "Bls12381.h"

#include "third_party/blst/bindings/blst.h"
#include "third_party/blst/bindings/blst_aux.h"

#include <algorithm>

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
