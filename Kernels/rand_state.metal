#include <metal_stdlib>
#include "PrngCommon.metalh"

using namespace metal;

kernel void rand_state(device RandomStateData& state [[buffer(0)]],
                       constant ulong& clock_seed [[buffer(1)]],
                       uint id [[thread_position_in_grid]]) {
    ulong seed = clock_seed;
    if (seed == 0ul) {
        seed = 0x6a09e667f3bcc909ul;
    }
    seed ^= ulong(id);
    state.seed = rng_splitmix64(seed);
    atomic_store_explicit(&state.counter, 0u, memory_order_relaxed);
    state.counterHigh = 0u;
    state.initialized = 1u;
    state.reserved = 0u;
}
