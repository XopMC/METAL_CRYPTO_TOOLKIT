#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace address_tools {

bool decode_cardano(std::string_view input, std::vector<uint8_t>& output);
bool decode_algorand(std::string_view input, std::vector<uint8_t>& output);
bool decode_multicoin_base58_bech32(std::string_view input, std::vector<uint8_t>& output);
bool decode_base64_raw(std::string_view input, std::vector<uint8_t>& output);
bool decode_cosmos(std::string_view input, std::vector<uint8_t>& output);
bool decode_ss58(std::string_view input, std::vector<uint8_t>& output);
bool decode_filecoin(std::string_view input, std::vector<uint8_t>& output);
bool decode_solana(std::string_view input, std::vector<uint8_t>& output);
bool decode_stellar(std::string_view input, std::vector<uint8_t>& output);
bool decode_stacks(std::string_view input, std::vector<uint8_t>& output);
bool decode_ton(std::string_view input, std::vector<uint8_t>& output);
bool decode_tron(std::string_view input, std::vector<uint8_t>& output);
bool decode_xrp(std::string_view input, std::vector<uint8_t>& output);
bool decode_tezos(std::string_view input, std::vector<uint8_t>& output);

}  // namespace address_tools
