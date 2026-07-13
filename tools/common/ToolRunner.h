#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace address_tools {

using Decoder = bool (*)(std::string_view input, std::vector<uint8_t>& output);

int run_converter(int argc,
                  char** argv,
                  std::string_view tool_name,
                  std::string_view description,
                  Decoder decoder);

}  // namespace address_tools
