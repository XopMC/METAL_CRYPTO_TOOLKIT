#include "bls12_381/Bls12381.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef BLS_TEST_BACKEND
#define BLS_TEST_BACKEND "unknown"
#endif

namespace {

std::uint8_t hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<std::uint8_t>(value - 'A' + 10);
    }
    throw std::runtime_error("invalid hex digit");
}

std::vector<std::uint8_t> hex_bytes(std::string value) {
    if (value.rfind("0x", 0u) == 0u ||
        value.rfind("0X", 0u) == 0u) {
        value.erase(0u, 2u);
    }
    if ((value.size() & 1u) != 0u) value.insert(value.begin(), '0');
    std::vector<std::uint8_t> output(value.size() / 2u);
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = static_cast<std::uint8_t>(
            (hex_nibble(value[index * 2u]) << 4u) |
            hex_nibble(value[index * 2u + 1u]));
    }
    return output;
}

template <std::size_t Size>
std::array<std::uint8_t, Size> fixed_hex(const std::string& value) {
    const std::vector<std::uint8_t> parsed = hex_bytes(value);
    if (parsed.size() > Size) throw std::runtime_error("hex value is too large");
    std::array<std::uint8_t, Size> output{};
    std::copy(
        parsed.begin(), parsed.end(),
        output.begin() + static_cast<std::ptrdiff_t>(Size - parsed.size()));
    return output;
}

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void check_eip2333(
    const std::string& seed_hex,
    const std::string& master_hex,
    const std::string& child_hex,
    std::uint32_t child_index) {
    const std::vector<std::uint8_t> seed = hex_bytes(seed_hex);
    bls12_381::SecretKey master{};
    bls12_381::SecretKey child{};
    std::string error;
    require(
        bls12_381::eip2333_master(
            seed.data(), seed.size(), master, error),
        "EIP-2333 master derivation failed");
    require(master == fixed_hex<32>(master_hex), "EIP-2333 master mismatch");
    require(
        bls12_381::eip2333_child(
            master, child_index, child, error),
        "EIP-2333 child derivation failed");
    require(child == fixed_hex<32>(child_hex), "EIP-2333 child mismatch");
}

void run_vectors() {
    check_eip2333(
        "3141592653589793238462643383279502884197169399375105820974944592",
        "41c9e07822b092a93fd6797396338c3ada4170cc81829fdfce6b5d34bd5e7ec7",
        "384843fad5f3d777ea39de3e47a8f999ae91f89e42bffa993d91d9782d152a0f",
        3141592653u);
    check_eip2333(
        "0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
        "3cfa341ab3910a7d00d933d8f7c4fe87c91798a0397421d6b19fd5b815132e80",
        "40e86285582f35b28821340f6a53b448588efa575bc4d88c32ef8567b8d9479b",
        4294967295u);
    check_eip2333(
        "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
        "2a0e28ffa5fbbe2f8e7aad4ed94f745d6bf755c51182e119bb1694fe61d3afca",
        "455c0dc9fccb3395825d92a60d2672d69416be1c2578a87a7a3d3ced11ebb88d",
        42u);
    check_eip2333(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f"
        "09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        "0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070",
        "2d18bd6c14e6d15bf8b5085c9b74f3daae3b03cc2014770a599d8c1539e50f8e",
        0u);

    const bls12_381::SecretKey one = fixed_hex<32>("01");
    bls12_381::PublicKey generator{};
    std::string error;
    require(
        bls12_381::public_key_compressed(one, generator, error),
        "G1 generator derivation failed");
    require(
        generator == fixed_hex<48>(
            "97f1d3a73197d7942695638c4fa9ac0f"
            "c3688c4f9774b905a14e3a3f171bac58"
            "6c55e83ff97a1aeffb3af00adb22c6bb"),
        "compressed G1 generator mismatch");

    const bls12_381::SecretKey two = fixed_hex<32>("02");
    const bls12_381::SecretKey three = fixed_hex<32>("03");
    bls12_381::SecretKey result{};
    require(
        bls12_381::scalar_add_mod(two, three, result) &&
        result == fixed_hex<32>("05"),
        "scalar addition mismatch");
    require(
        bls12_381::scalar_multiply_mod(two, three, result) &&
        result == fixed_hex<32>("06"),
        "scalar multiplication mismatch");
    require(
        !bls12_381::valid_secret_key(bls12_381::SecretKey{}),
        "zero scalar was accepted");
    require(
        !bls12_381::valid_secret_key(fixed_hex<32>(
            "73eda753299d7d483339d80809a1d805"
            "53bda402fffe5bfeffffffff00000001")),
        "scalar modulus was accepted");

    std::array<std::uint8_t, 31> short_seed{};
    require(
        !bls12_381::keygen(
            short_seed.data(), short_seed.size(),
            nullptr, 0u, result, error),
        "short KeyGen IKM was accepted");
}

void run_benchmark(std::size_t count) {
    std::vector<bls12_381::SecretKey> secrets(count);
    std::vector<bls12_381::PublicKey> public_keys(count);
    for (std::size_t index = 0; index < count; ++index) {
        const std::uint64_t value =
            static_cast<std::uint64_t>(index + 1u);
        for (unsigned int byte = 0; byte < 8u; ++byte) {
            secrets[index][31u - byte] =
                static_cast<std::uint8_t>(value >> (byte * 8u));
        }
    }
    std::string error;
    const auto start = std::chrono::steady_clock::now();
    require(
        bls12_381::public_keys_compressed(
            secrets.data(), count, public_keys.data(), error),
        "batch public-key derivation failed");
    const auto stop = std::chrono::steady_clock::now();
    std::uint64_t checksum = 0u;
    for (const auto& public_key : public_keys) {
        for (std::uint8_t value : public_key) {
            checksum = (checksum * 0x100000001b3ULL) ^ value;
        }
    }
    const auto nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            stop - start).count();
    std::cout
        << "backend=" << BLS_TEST_BACKEND
        << " operations=" << count
        << " nanoseconds=" << nanoseconds
        << " checksum=" << checksum << "\n";
}

void write_vector_receipt(const std::string& path) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "cannot open vector receipt");
    output
        << "backend=" << BLS_TEST_BACKEND
        << " eip2333=ok keygen=ok scalar=ok g1=ok\n";
    require(output.good(), "cannot write vector receipt");
}

}  // namespace

int main(int argc, char** argv) {
    try {
        run_vectors();
        if (argc == 3 && std::string(argv[1]) == "--bench") {
            const std::size_t count =
                static_cast<std::size_t>(std::stoull(argv[2]));
            require(count != 0u, "benchmark count must be nonzero");
            run_benchmark(count);
        } else if (argc == 3 && std::string(argv[1]) == "--output") {
            write_vector_receipt(argv[2]);
            std::cout
                << "bls12_381 vectors ok backend="
                << BLS_TEST_BACKEND << "\n";
        } else {
            require(
                argc == 1,
                "usage: bls12_381_vectors [--bench N|--output FILE]");
            std::cout
                << "bls12_381 vectors ok backend="
                << BLS_TEST_BACKEND << "\n";
        }
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "bls12_381 test failed: "
                  << exception.what() << "\n";
        return 1;
    }
}
