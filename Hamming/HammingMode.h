#pragma once

#include <cstdint>

namespace hamming {

struct RuntimeHooks {
    void (*add_completed)(std::uint64_t) = nullptr;
    void (*increment_found)() = nullptr;
};

bool requested(int argc, char** argv);
void print_help();
int run(int argc, char** argv, const RuntimeHooks& hooks);

} // namespace hamming
