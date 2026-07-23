#pragma once

#include <cstdint>

namespace kangaroo {

struct RuntimeHooks {
    void (*add_operations)(std::uint64_t) = nullptr;
    void (*set_speed_context)(double) = nullptr;
    void (*increment_found)() = nullptr;
};

bool requested(int argc, char** argv);
void print_help();
int run(int argc, char** argv, const RuntimeHooks& hooks);

} // namespace kangaroo
