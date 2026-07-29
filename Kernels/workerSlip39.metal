#include <metal_stdlib>
using namespace metal;

#include "Slip39Common.metalh"

static inline void slip39_store_hit(
    ulong candidate_index,
    const device char* source,
    uint password_len,
    const thread uchar master_secret[SLIP39_MAX_SECRET_BYTES],
    uint secret_len,
    ulong target_index,
    device Slip39Hit* hits,
    device atomic_uint* hit_count,
    uint hit_capacity) {
    const uint slot = atomic_fetch_add_explicit(
        hit_count, 1u, memory_order_relaxed);
    if (slot >= hit_capacity) return;
    hits[slot].candidate_index = candidate_index;
    hits[slot].target_index = target_index;
    hits[slot].password_len = password_len;
    hits[slot].secret_len = secret_len;
    for (uint i = 0u; i < SLIP39_PASSWORD_STRIDE; ++i) {
        hits[slot].password[i] =
            i < password_len ? uchar(source[i]) : uchar(0u);
    }
    for (uint i = 0u; i < SLIP39_MAX_SECRET_BYTES; ++i) {
        hits[slot].master_secret[i] =
            i < secret_len ? master_secret[i] : uchar(0u);
    }
}

kernel void workerSlip39Derive(
    const constant Slip39Config& config [[buffer(0)]],
    const device char* password_data [[buffer(1)]],
    const device uchar* password_lengths [[buffer(2)]],
    constant ulong& candidate_count [[buffer(3)]],
    device Slip39Derived* derived [[buffer(4)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;
    derived[tid].valid = 0u;
    const uint password_len = uint(password_lengths[tid]);
    if (password_len >= SLIP39_PASSWORD_STRIDE) return;

    uchar password[SLIP39_PASSWORD_STRIDE];
    const device char* source =
        password_data + ulong(tid) * ulong(SLIP39_PASSWORD_STRIDE);
    for (uint i = 0u; i < password_len; ++i) {
        password[i] = uchar(source[i]);
    }

    uchar master_secret[SLIP39_MAX_SECRET_BYTES];
    if (!slip39_decrypt(
            config, password, password_len, master_secret)) return;
    uchar digest[32];
    SHA256(
        master_secret, size_t(config.ciphertext_len), digest);
    for (uint i = 0u; i < 32u; ++i) {
        derived[tid].digest[i] = digest[i];
        derived[tid].master_secret[i] =
            i < config.ciphertext_len
                ? master_secret[i] : uchar(0u);
    }
    derived[tid].valid = 1u;
}

kernel void workerSlip39Lookup(
    const constant Slip39Config& config [[buffer(0)]],
    const device char* password_data [[buffer(1)]],
    const device uchar* password_lengths [[buffer(2)]],
    constant ulong& candidate_base [[buffer(3)]],
    constant ulong& candidate_count [[buffer(4)]],
    const device Slip39Derived* derived [[buffer(5)]],
    const device Slip39Target* targets [[buffer(6)]],
    constant uint& target_count [[buffer(7)]],
    device Slip39Hit* hits [[buffer(8)]],
    device atomic_uint* hit_count [[buffer(9)]],
    constant uint& hit_capacity [[buffer(10)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count ||
        derived[tid].valid == 0u) return;
    uchar digest[32];
    uchar master_secret[SLIP39_MAX_SECRET_BYTES];
    for (uint i = 0u; i < 32u; ++i) {
        digest[i] = derived[tid].digest[i];
        master_secret[i] = derived[tid].master_secret[i];
    }
    const int target =
        slip39_find_target(digest, targets, target_count);
    if (target < 0) return;
    const device char* source =
        password_data + ulong(tid) * ulong(SLIP39_PASSWORD_STRIDE);
    slip39_store_hit(
        candidate_base + ulong(tid), source,
        uint(password_lengths[tid]), master_secret,
        config.ciphertext_len, targets[target].source_index,
        hits, hit_count, hit_capacity);
}

kernel void workerSlip39Fused(
    const constant Slip39Config& config [[buffer(0)]],
    const device char* password_data [[buffer(1)]],
    const device uchar* password_lengths [[buffer(2)]],
    constant ulong& candidate_base [[buffer(3)]],
    constant ulong& candidate_count [[buffer(4)]],
    const device Slip39Target* targets [[buffer(5)]],
    constant uint& target_count [[buffer(6)]],
    device Slip39Hit* hits [[buffer(7)]],
    device atomic_uint* hit_count [[buffer(8)]],
    constant uint& hit_capacity [[buffer(9)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;
    const uint password_len = uint(password_lengths[tid]);
    if (password_len >= SLIP39_PASSWORD_STRIDE) return;
    const device char* source =
        password_data + ulong(tid) * ulong(SLIP39_PASSWORD_STRIDE);
    uchar password[SLIP39_PASSWORD_STRIDE];
    for (uint i = 0u; i < password_len; ++i) {
        password[i] = uchar(source[i]);
    }
    uchar master_secret[SLIP39_MAX_SECRET_BYTES];
    if (!slip39_decrypt(
            config, password, password_len, master_secret)) return;
    uchar digest[32];
    SHA256(
        master_secret, size_t(config.ciphertext_len), digest);
    const int target =
        slip39_find_target(digest, targets, target_count);
    if (target < 0) return;
    slip39_store_hit(
        candidate_base + ulong(tid), source, password_len,
        master_secret, config.ciphertext_len,
        targets[target].source_index, hits, hit_count,
        hit_capacity);
}
