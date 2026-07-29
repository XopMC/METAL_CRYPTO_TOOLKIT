#pragma once

#include <cstdint>

namespace chia_mode {

struct RuntimeHooks {
    void (*credit_completed)(std::uint64_t completed) = nullptr;
    void (*credit_found)() = nullptr;
};

bool requested(int argc, char** argv);
void print_help();
int run(int argc, char** argv, const RuntimeHooks& hooks);

}  // namespace chia_mode
