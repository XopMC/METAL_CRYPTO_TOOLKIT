#include "PoetryCommon.metalh"

kernel void initPoetryThreadStates(device PoetryThreadState* states [[buffer(0)]],
                                   constant uint& state_count [[buffer(1)]],
                                   const device PoetryTemplateDevice* poetry_template [[buffer(2)]],
                                   constant ulong& global_thread_prefix [[buffer(3)]],
                                   constant uint& gpu_id [[buffer(4)]],
                                   constant ulong& seed_nonce [[buffer(5)]],
                                   uint tid [[thread_position_in_grid]]) {
    if (tid >= state_count) return;

    device PoetryThreadState& state = states[tid];
    for (uint i = 0u; i < POETRY_MAX_WORDS; ++i) state.digits[i] = 0u;
    if (poetry_template->random_mode != 0u) {
        ulong seed = seed_nonce + global_thread_prefix + ulong(tid) +
            ulong(gpu_id + 1u) * 0x9e3779b97f4a7c15ul;
        state.random_state = rng_splitmix64(seed);
        state.active = 1u;
    } else {
        state.random_state = 0ul;
        state.active = poetry_set_digits_from_index(state.digits,
                                                     poetry_template->wildcard_count,
                                                     global_thread_prefix + ulong(tid)) ? 1u : 0u;
    }
}
