#pragma once

#include <cstdint>

namespace stronghold_mode {

struct RuntimeHooks {
    void (*credit_completed)(std::uint64_t) = nullptr;
    void (*credit_found)() = nullptr;
};

bool requested(int argc, char** argv);
void print_help();
int run(int argc, char** argv, const RuntimeHooks& hooks);

}  // namespace stronghold_mode
