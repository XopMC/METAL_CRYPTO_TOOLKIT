#include "WorkerProfanityCommon.metalh"

kernel void workerProfanityRecoveryReverse_xh_ge(constant secp256k1_ge_storage* precPtr [[buffer(0)]],
                                                 constant ulong& precPitch [[buffer(1)]],
                                                 const device secp256k1_ge* target_ge [[buffer(2)]],
                                                 constant ulong& lane_start [[buffer(3)]],
                                                 constant ulong& lane_count [[buffer(4)]],
                                                 constant ulong& state_index_start [[buffer(5)]],
                                                 constant ulong& round_start [[buffer(6)]],
                                                 constant ulong& round_count [[buffer(7)]],
                                                 device ProfanityRecoveryHit* hits [[buffer(8)]],
                                                 device atomic_uint* hit_count [[buffer(9)]],
                                                 constant uint& max_hits [[buffer(10)]],
                                                 device ProfanityWalkState* walk_state [[buffer(11)]],
                                                 constant ulong& walk_state_capacity [[buffer(12)]],
                                                 constant bool& use_walk_state [[buffer(13)]],
                                                 constant bool& store_walk_state [[buffer(14)]],
                                                 uint tid [[thread_position_in_grid]]) {
    worker_profanity_recovery_reverse_direct_impl(precPtr, precPitch, target_ge, lane_start,
                                                  lane_count, state_index_start, round_start,
                                                  round_count, hits, hit_count, max_hits,
                                                  walk_state, walk_state_capacity, use_walk_state,
                                                  store_walk_state, 0x08u, tid);
}
