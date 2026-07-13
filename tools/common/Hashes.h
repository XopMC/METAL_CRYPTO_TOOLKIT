#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace address_tools {

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t size);
std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data);
std::array<uint8_t, 32> sha256d(const uint8_t* data, size_t size);
std::array<uint8_t, 32> sha512_256(const uint8_t* data, size_t size);
std::array<uint8_t, 20> ripemd160(const uint8_t* data, size_t size);
std::vector<uint8_t> blake2b(const uint8_t* data, size_t size, size_t output_size);
uint16_t crc16_xmodem(const uint8_t* data, size_t size);
uint32_t crc32_ieee(const uint8_t* data, size_t size);
bool bytes_equal(const uint8_t* lhs, const uint8_t* rhs, size_t size);

}  // namespace address_tools
