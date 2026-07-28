#include <metal_stdlib>
using namespace metal;

#include "MoneroCommon.metalh"

kernel void workerMoneroDerive(
    const device MoneroCandidate* candidates [[buffer(0)]],
    constant ulong& candidate_count [[buffer(1)]],
    device MoneroDerived* derived [[buffer(2)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;

    MoneroCandidate candidate = candidates[tid];
    derived[tid].valid = 0u;
    if (candidate.valid == 0u) return;

    uchar recovery[32];
    if (candidate.scheme == MONERO_SCHEME_POLYSEED) {
        monero_polyseed_key(candidate, recovery);
    } else if (candidate.scheme == MONERO_SCHEME_LEGACY) {
        for (uint i = 0u; i < 32u; ++i) {
            recovery[i] = candidate.material[i];
        }
    } else {
        return;
    }

    uchar spend_private[32];
    monero_reduce_scalar(recovery, spend_private);
    if (!monero_nonzero(spend_private)) return;

    uchar spend_public[32];
    cardano_ed25519_publickey_from_scalar(spend_private, spend_public);

    uchar view_hash[32];
    keccak(reinterpret_cast<thread const char*>(spend_private),
           32, view_hash, 32);
    uchar view_private[32];
    monero_reduce_scalar(view_hash, view_private);
    if (!monero_nonzero(view_private)) return;

    uchar view_public[32];
    cardano_ed25519_publickey_from_scalar(view_private, view_public);

    for (uint i = 0u; i < 32u; ++i) {
        derived[tid].spend_private[i] = spend_private[i];
        derived[tid].view_private[i] = view_private[i];
        derived[tid].spend_public[i] = spend_public[i];
        derived[tid].view_public[i] = view_public[i];
    }
    derived[tid].valid = 1u;
}

kernel void workerMoneroLookup(
    const device MoneroCandidate* candidates [[buffer(0)]],
    const device MoneroDerived* derived [[buffer(1)]],
    constant ulong& candidate_count [[buffer(2)]],
    const device MoneroTarget* targets [[buffer(3)]],
    constant uint& target_count [[buffer(4)]],
    device MoneroHit* hits [[buffer(5)]],
    device atomic_uint* hit_count [[buffer(6)]],
    constant uint& hit_capacity [[buffer(7)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count || derived[tid].valid == 0u) return;

    uchar spend_public[32];
    uchar view_public[32];
    for (uint i = 0u; i < 32u; ++i) {
        spend_public[i] = derived[tid].spend_public[i];
        view_public[i] = derived[tid].view_public[i];
    }
    const int target =
        monero_find_target(spend_public, view_public, targets, target_count);
    if (target < 0) return;

    const uint slot = atomic_fetch_add_explicit(
        hit_count, 1u, memory_order_relaxed);
    if (slot >= hit_capacity) return;

    for (uint i = 0u; i < 4u; ++i) {
        hits[slot].ordinal[i] = candidates[tid].ordinal[i];
    }
    hits[slot].template_index = candidates[tid].template_index;
    hits[slot].target_index = targets[target].source_index;
    hits[slot].scheme = candidates[tid].scheme;
    for (uint i = 0u; i < 32u; ++i) {
        hits[slot].spend_private[i] = derived[tid].spend_private[i];
        hits[slot].view_private[i] = derived[tid].view_private[i];
        hits[slot].spend_public[i] = spend_public[i];
        hits[slot].view_public[i] = view_public[i];
    }
}
