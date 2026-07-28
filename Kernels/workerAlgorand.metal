#include <metal_stdlib>
using namespace metal;

#include "AlgorandCommon.metalh"

kernel void workerAlgorandDerive(
    const device AlgorandCandidate* candidates [[buffer(0)]],
    constant ulong& candidate_count [[buffer(1)]],
    device AlgorandDerived* derived [[buffer(2)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;

    const AlgorandCandidate candidate = candidates[tid];
    derived[tid].valid = 0u;
    uint checksum_word = 0u;
    uchar public_key[32];
    if (!algorand_derive_public_key(
            candidate, public_key, checksum_word)) return;
    derived[tid].checksum_word = checksum_word;
    for (uint i = 0u; i < 32u; ++i) {
        derived[tid].public_key[i] = public_key[i];
    }
    derived[tid].valid = 1u;
}

kernel void workerAlgorandLookup(
    const device AlgorandCandidate* candidates [[buffer(0)]],
    const device AlgorandDerived* derived [[buffer(1)]],
    constant ulong& candidate_count [[buffer(2)]],
    const device AlgorandTarget* targets [[buffer(3)]],
    constant uint& target_count [[buffer(4)]],
    device AlgorandHit* hits [[buffer(5)]],
    device atomic_uint* hit_count [[buffer(6)]],
    constant uint& hit_capacity [[buffer(7)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count || derived[tid].valid == 0u) return;

    uchar public_key[32];
    for (uint i = 0u; i < 32u; ++i) {
        public_key[i] = derived[tid].public_key[i];
    }
    const int target =
        algorand_find_target(public_key, targets, target_count);
    if (target < 0) return;

    const uint slot = atomic_fetch_add_explicit(
        hit_count, 1u, memory_order_relaxed);
    if (slot >= hit_capacity) return;

    for (uint i = 0u; i < 4u; ++i) {
        hits[slot].ordinal[i] = candidates[tid].ordinal[i];
    }
    hits[slot].template_index = candidates[tid].template_index;
    hits[slot].target_index = targets[target].source_index;
    for (uint i = 0u; i < 32u; ++i) {
        hits[slot].public_key[i] = public_key[i];
    }
    hits[slot].checksum_word = derived[tid].checksum_word;
    hits[slot].reserved = 0u;
}

kernel void workerAlgorandFused(
    const device AlgorandCandidate* candidates [[buffer(0)]],
    constant ulong& candidate_count [[buffer(1)]],
    const device AlgorandTarget* targets [[buffer(2)]],
    constant uint& target_count [[buffer(3)]],
    device AlgorandHit* hits [[buffer(4)]],
    device atomic_uint* hit_count [[buffer(5)]],
    constant uint& hit_capacity [[buffer(6)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;

    const AlgorandCandidate candidate = candidates[tid];
    uint checksum_word = 0u;
    uchar public_key[32];
    if (!algorand_derive_public_key(
            candidate, public_key, checksum_word)) return;

    const int target =
        algorand_find_target(public_key, targets, target_count);
    if (target < 0) return;

    const uint slot = atomic_fetch_add_explicit(
        hit_count, 1u, memory_order_relaxed);
    if (slot >= hit_capacity) return;

    for (uint i = 0u; i < 4u; ++i) {
        hits[slot].ordinal[i] = candidate.ordinal[i];
    }
    hits[slot].template_index = candidate.template_index;
    hits[slot].target_index = targets[target].source_index;
    for (uint i = 0u; i < 32u; ++i) {
        hits[slot].public_key[i] = public_key[i];
    }
    hits[slot].checksum_word = checksum_word;
    hits[slot].reserved = 0u;
}
