#pragma once

#include <cstdint>

namespace bsgs {

enum class SpeedPhase : std::uint32_t {
    Idle = 0,
    TableBuild = 1,
    CacheLoad = 2,
    Search = 3,
};

struct RuntimeHooks {
    void (*add_operations)(std::uint64_t) = nullptr;
    void (*set_speed_context)(SpeedPhase phase,
                              std::uint64_t phase_total,
                              double covered_scalars_per_operation,
                              std::uint32_t active_targets) = nullptr;
    void (*increment_found)() = nullptr;
};

bool requested(int argc, char** argv);
void print_help();
int run(int argc, char** argv, const RuntimeHooks& hooks);

} // namespace bsgs
