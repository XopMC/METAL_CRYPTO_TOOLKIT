#include <metal_stdlib>
using namespace metal;

#include "StrongholdArgon2Common.metalh"

kernel void workerStrongholdInit(
    const constant StrongholdArgon2Options& options
        [[buffer(0)]],
    const device uchar* passwords [[buffer(1)]],
    const device uchar* password_lengths [[buffer(2)]],
    const device uchar* salt [[buffer(3)]],
    device ulong* scratch [[buffer(4)]],
    device uchar* derived_keys [[buffer(5)]],
    uint candidate [[thread_position_in_grid]]) {
    if (candidate >= options.candidate_count) return;
    const uint length = uint(password_lengths[candidate]);
    if (length >= options.password_stride) return;
    const device uchar* password =
        passwords + ulong(candidate) *
        ulong(options.password_stride);
    if (options.iterations == 0u) {
        uchar local_password[128];
        for (uint index = 0u; index < length; ++index) {
            local_password[index] = password[index];
        }
        uchar key[64];
        stronghold_blake2b(
            local_password, length, 32u, key);
        device uchar* output =
            derived_keys + ulong(candidate) * 32ul;
#pragma unroll
        for (uint index = 0u; index < 32u; ++index) {
            output[index] = key[index];
        }
        return;
    }
    device ulong* blocks =
        scratch + ulong(candidate) *
        ulong(options.memory_block_count) * 128ul;
    stronghold_argon2_initialize(
        password, length, salt, options, blocks);
}
