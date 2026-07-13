#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "MetalBackend.h"
#include "host_secp/secp256k1_common.h"

bool build_secp256k1_precompute_table_host(unsigned int bits,
                                           std::vector<secp256k1_ge_storage>& entries,
                                           std::size_t& row_pitch,
                                           unsigned int& windows,
                                           std::string& err);
