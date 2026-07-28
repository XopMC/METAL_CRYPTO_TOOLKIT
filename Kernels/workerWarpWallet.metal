#include <metal_stdlib>
using namespace metal;

#include "WarpWalletCommon.metalh"

kernel void workerWarpWalletKdf(
    const constant WarpWalletConfig& config [[buffer(0)]],
    const device uchar* salt [[buffer(1)]],
    const device char* password_data [[buffer(2)]],
    const device uchar* password_lengths [[buffer(3)]],
    constant ulong& candidate_count [[buffer(4)]],
    device uchar* scratch [[buffer(5)]],
    constant ulong& scratch_stride [[buffer(6)]],
    device WarpWalletDerived* derived [[buffer(7)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;
    derived[tid].valid = 0u;
    const uint password_len = uint(password_lengths[tid]);
    if (password_len >= 128u) return;
    uchar password[128];
    const device char* source = password_data + ulong(tid) * 128ul;
    for (uint i = 0u; i < password_len; ++i) {
        password[i] = uchar(source[i]);
    }
    uchar private_key[32];
    if (!warp_derive_private(
            password, password_len, config, salt, scratch,
            scratch_stride, ulong(tid), private_key)) {
        return;
    }
    for (uint i = 0u; i < 32u; ++i) {
        derived[tid].private_key[i] = private_key[i];
    }
    derived[tid].valid = 1u;
}

kernel void workerBrainV2First(
    const constant WarpWalletConfig& config [[buffer(0)]],
    const device uchar* salt [[buffer(1)]],
    const device char* password_data [[buffer(2)]],
    const device uchar* password_lengths [[buffer(3)]],
    constant ulong& candidate_count [[buffer(4)]],
    device uchar* scratch [[buffer(5)]],
    constant ulong& scratch_stride [[buffer(6)]],
    device uchar* key1 [[buffer(7)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;
    const uint password_len = uint(password_lengths[tid]);
    if (password_len >= 128u) return;
    uchar password[128];
    const device char* source = password_data + ulong(tid) * 128ul;
    for (uint i = 0u; i < password_len; ++i) {
        password[i] = uchar(source[i]);
    }
    (void)warp_scrypt_sha256_output(
        password, password_len, salt, config.salt_len,
        1u << 14u, 1u, 64u, scratch, scratch_stride,
        ulong(tid), key1 + ulong(tid) * 16384ul, 16384u);
}

kernel void workerBrainV2Middle(
    const device uchar* key1 [[buffer(0)]],
    device uchar* key2 [[buffer(1)]],
    constant ulong& job_base [[buffer(2)]],
    constant ulong& job_count [[buffer(3)]],
    device uchar* scratch [[buffer(4)]],
    constant ulong& scratch_stride [[buffer(5)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= job_count) return;
    const ulong job = job_base + ulong(tid);
    const device uchar* pair = key1 + job * 64ul;
    uchar password[32];
    for (uint i = 0u; i < 32u; ++i) password[i] = pair[i];
    (void)warp_scrypt_sha256_output(
        password, 32u, pair + 32u, 32u,
        1u << 16u, 1u, 64u, scratch, scratch_stride,
        ulong(tid), key2 + job * 32ul, 32u);
}

kernel void workerBrainV2Last(
    const device char* password_data [[buffer(0)]],
    const device uchar* password_lengths [[buffer(1)]],
    const device uchar* key2 [[buffer(2)]],
    constant ulong& candidate_count [[buffer(3)]],
    device uchar* scratch [[buffer(4)]],
    constant ulong& scratch_stride [[buffer(5)]],
    device uchar* key3 [[buffer(6)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;
    const uint password_len = uint(password_lengths[tid]);
    if (password_len >= 128u) return;
    uchar password[128];
    const device char* source = password_data + ulong(tid) * 128ul;
    for (uint i = 0u; i < password_len; ++i) {
        password[i] = uchar(source[i]);
    }
    (void)warp_scrypt_sha256_output(
        password, password_len, key2 + ulong(tid) * 8192ul,
        8192u, 1u << 14u, 1u, 64u, scratch, scratch_stride,
        ulong(tid), key3 + ulong(tid) * 16ul, 16u);
}

kernel void workerBrainV2Finalize(
    const device uchar* key3 [[buffer(0)]],
    constant ulong& candidate_count [[buffer(1)]],
    device WarpWalletDerived* derived [[buffer(2)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;
    uchar encoded[32];
    const device uchar* source = key3 + ulong(tid) * 16ul;
    for (uint i = 0u; i < 16u; ++i) {
        encoded[i * 2u] = warp_hex_digit(source[i] >> 4u);
        encoded[i * 2u + 1u] =
            warp_hex_digit(source[i] & 15u);
    }
    uchar private_key[32];
    SHA256(encoded, 32u, private_key);
    for (uint i = 0u; i < 32u; ++i) {
        derived[tid].private_key[i] = private_key[i];
    }
    derived[tid].valid = 1u;
}

kernel void workerWarpWalletHash160(
    const constant secp256k1_ge_storage* precompute [[buffer(0)]],
    constant ulong& pitch [[buffer(1)]],
    constant uint& window_count [[buffer(2)]],
    constant uint& window_bits [[buffer(3)]],
    const device WarpWalletDerived* derived [[buffer(4)]],
    constant ulong& candidate_count [[buffer(5)]],
    device WarpWalletResolved* resolved [[buffer(6)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;
    resolved[tid].valid = 0u;
    if (derived[tid].valid == 0u) return;
    uchar private_key[32];
    for (uint i = 0u; i < 32u; ++i) {
        private_key[i] = derived[tid].private_key[i];
    }
    secp256k1_scalar scalar;
    if (!secp256k1_scalar_set_b32_seckey(&scalar, private_key)) return;
    secp256k1_gej jacobian;
    secp256k1_ecmult_big(
        &jacobian, &scalar, precompute, size_t(pitch),
        int(window_count), window_bits);
    if (jacobian.infinity != 0) return;
    secp256k1_ge affine;
    secp256k1_ge_set_gej(&affine, &jacobian);
    secp256k1_pubkey point;
    secp256k1_pubkey_save(&point, &affine);
    uchar compressed[33];
    if (secp256k1_ec_pubkey_serialize(
            compressed, 33u, &point, true) == 0) return;

    uchar sha_digest[32];
    SHA256(compressed, 33u, sha_digest);
    uint hash_words[5];
    _GetRMD160(reinterpret_cast<thread uint*>(sha_digest), hash_words);
    uchar hash160[20];
    for (uint i = 0u; i < 20u; ++i) {
        hash160[i] =
            reinterpret_cast<thread uchar*>(hash_words)[i];
        resolved[tid].hash160[i] = hash160[i];
    }
    resolved[tid].valid = 1u;
}

kernel void workerWarpWalletLookup(
    const device WarpWalletResolved* resolved [[buffer(0)]],
    const device WarpWalletDerived* derived [[buffer(1)]],
    const device char* password_data [[buffer(2)]],
    const device uchar* password_lengths [[buffer(3)]],
    constant ulong& candidate_base [[buffer(4)]],
    constant ulong& candidate_count [[buffer(5)]],
    const device WarpWalletTarget* targets [[buffer(6)]],
    constant uint& target_count [[buffer(7)]],
    constant uint& profile [[buffer(8)]],
    device WarpWalletHit* hits [[buffer(9)]],
    device atomic_uint* hit_count [[buffer(10)]],
    constant uint& hit_capacity [[buffer(11)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count || resolved[tid].valid == 0u) return;
    uchar hash160[20];
    for (uint i = 0u; i < 20u; ++i) {
        hash160[i] = resolved[tid].hash160[i];
    }
    const int target = warp_find_target(hash160, targets, target_count);
    if (target < 0) return;

    const uint slot = atomic_fetch_add_explicit(
        hit_count, 1u, memory_order_relaxed);
    if (slot >= hit_capacity) return;
    hits[slot].candidate_index = candidate_base + ulong(tid);
    hits[slot].target_index = targets[target].source_index;
    const uint password_len = uint(password_lengths[tid]);
    hits[slot].password_len = password_len;
    const device char* password =
        password_data + ulong(tid) * 128ul;
    for (uint i = 0u; i < 128u; ++i) {
        hits[slot].password[i] =
            i < password_len ? uchar(password[i]) : 0u;
    }
    for (uint i = 0u; i < 32u; ++i) {
        hits[slot].private_key[i] = derived[tid].private_key[i];
    }
    for (uint i = 0u; i < 20u; ++i) {
        hits[slot].hash160[i] = hash160[i];
    }
    hits[slot].profile = profile;
}
