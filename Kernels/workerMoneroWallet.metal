#include <metal_stdlib>
using namespace metal;

#include "MoneroWalletCommon.metalh"

kernel void workerMoneroWalletCnInit(
    const device uchar* passwords [[buffer(0)]],
    const device uchar* lengths [[buffer(1)]],
    constant ulong& candidate_count [[buffer(2)]],
    device uchar* scratch [[buffer(3)]],
    device MoneroWalletCnState* states [[buffer(4)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;

    device MoneroWalletCnState& output = states[tid];
    output.valid = 0u;
    const uint length = uint(lengths[tid]);
    if (length >= MONERO_WALLET_PASSWORD_STRIDE) return;

    uchar state[200];
    monero_wallet_keccak1600(
        passwords + ulong(tid) * MONERO_WALLET_PASSWORD_STRIDE,
        length, state);

    uchar key[32];
    for (uint i = 0u; i < 32u; ++i) key[i] = state[i];
    uint round_keys[60];
    provider_aes_expand_key(key, round_keys);

    uchar text[128];
    for (uint i = 0u; i < 128u; ++i) text[i] = state[64u + i];
    device uchar* lane =
        scratch + ulong(tid) * ulong(MONERO_WALLET_CN_MEMORY);
    for (uint offset = 0u; offset < MONERO_WALLET_CN_MEMORY;
         offset += 128u) {
#pragma unroll
        for (uint block = 0u; block < 8u; ++block) {
            uchar value[16];
#pragma unroll
            for (uint i = 0u; i < 16u; ++i) {
                value[i] = text[block * 16u + i];
            }
            monero_wallet_aes_pseudo_round(value, round_keys);
#pragma unroll
            for (uint i = 0u; i < 16u; ++i) {
                text[block * 16u + i] = value[i];
                lane[offset + block * 16u + i] = value[i];
            }
        }
    }

    for (uint i = 0u; i < 200u; ++i) output.state[i] = state[i];
    output.a0 = monero_wallet_load_le64_thread(state + 0u) ^
        monero_wallet_load_le64_thread(state + 32u);
    output.a1 = monero_wallet_load_le64_thread(state + 8u) ^
        monero_wallet_load_le64_thread(state + 40u);
    output.b0 = monero_wallet_load_le64_thread(state + 16u) ^
        monero_wallet_load_le64_thread(state + 48u);
    output.b1 = monero_wallet_load_le64_thread(state + 24u) ^
        monero_wallet_load_le64_thread(state + 56u);
    output.valid = 1u;
}

kernel void workerMoneroWalletCnMix(
    constant ulong& candidate_count [[buffer(0)]],
    constant uint& iteration_count [[buffer(1)]],
    device uchar* scratch [[buffer(2)]],
    device MoneroWalletCnState* states [[buffer(3)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count || states[tid].valid == 0u) return;

    device MoneroWalletCnState& state = states[tid];
    device uchar* lane =
        scratch + ulong(tid) * ulong(MONERO_WALLET_CN_MEMORY);
    ulong a0 = state.a0;
    ulong a1 = state.a1;
    ulong b0 = state.b0;
    ulong b1 = state.b1;

    for (uint iteration = 0u; iteration < iteration_count; ++iteration) {
        const uint first_offset = uint(a0) & MONERO_WALLET_CN_MASK;
        uchar c[16];
        monero_wallet_load_block(lane + first_offset, c);
        monero_wallet_aes_single_round(c, a0, a1);
        const ulong c0 = monero_wallet_load_le64_thread(c);
        const ulong c1 = monero_wallet_load_le64_thread(c + 8u);
        monero_wallet_store_le64_device(
            lane + first_offset, c0 ^ b0);
        monero_wallet_store_le64_device(
            lane + first_offset + 8u, c1 ^ b1);

        const uint second_offset = uint(c0) & MONERO_WALLET_CN_MASK;
        const ulong d0 =
            monero_wallet_load_le64_device(lane + second_offset);
        const ulong d1 =
            monero_wallet_load_le64_device(lane + second_offset + 8u);
        const ulong product_low = c0 * d0;
        const ulong product_high = mulhi(c0, d0);
        a0 += product_high;
        a1 += product_low;
        monero_wallet_store_le64_device(lane + second_offset, a0);
        monero_wallet_store_le64_device(lane + second_offset + 8u, a1);
        a0 ^= d0;
        a1 ^= d1;
        b0 = c0;
        b1 = c1;
    }

    state.a0 = a0;
    state.a1 = a1;
    state.b0 = b0;
    state.b1 = b1;
}

kernel void workerMoneroWalletCnFinal(
    constant ulong& candidate_count [[buffer(0)]],
    device uchar* scratch [[buffer(1)]],
    device MoneroWalletCnState* states [[buffer(2)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count || states[tid].valid == 0u) return;

    device MoneroWalletCnState& output = states[tid];
    uchar state[200];
    for (uint i = 0u; i < 200u; ++i) state[i] = output.state[i];

    uchar key[32];
    for (uint i = 0u; i < 32u; ++i) key[i] = state[32u + i];
    uint round_keys[60];
    provider_aes_expand_key(key, round_keys);

    uchar text[128];
    for (uint i = 0u; i < 128u; ++i) text[i] = state[64u + i];
    const device uchar* lane =
        scratch + ulong(tid) * ulong(MONERO_WALLET_CN_MEMORY);
    for (uint offset = 0u; offset < MONERO_WALLET_CN_MEMORY;
         offset += 128u) {
#pragma unroll
        for (uint block = 0u; block < 8u; ++block) {
            uchar value[16];
#pragma unroll
            for (uint i = 0u; i < 16u; ++i) {
                value[i] = text[block * 16u + i] ^
                    lane[offset + block * 16u + i];
            }
            monero_wallet_aes_pseudo_round(value, round_keys);
#pragma unroll
            for (uint i = 0u; i < 16u; ++i) {
                text[block * 16u + i] = value[i];
            }
        }
    }
    for (uint i = 0u; i < 128u; ++i) state[64u + i] = text[i];
    keccakf(reinterpret_cast<thread ulong*>(state));
    for (uint i = 0u; i < 200u; ++i) output.state[i] = state[i];
}
