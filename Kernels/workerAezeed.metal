#include <metal_stdlib>
using namespace metal;

#include "AezeedCommon.metalh"

kernel void workerAezeed(
    const constant AezeedConfig& config [[buffer(0)]],
    const device char* password_data [[buffer(1)]],
    const device uchar* password_lengths [[buffer(2)]],
    constant ulong& candidate_base [[buffer(3)]],
    constant ulong& candidate_count [[buffer(4)]],
    device uchar* scratch [[buffer(5)]],
    constant ulong& scratch_stride [[buffer(6)]],
    device AezeedHit* hits [[buffer(7)]],
    device atomic_uint* hit_count [[buffer(8)]],
    constant uint& hit_capacity [[buffer(9)]],
    const device uchar* salt [[buffer(10)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count) return;
    const uint raw_length = uint(password_lengths[tid]);
    if (raw_length >= AEZEED_PASSWORD_STRIDE) return;
    uchar password[128];
    uint password_length = raw_length;
    if (raw_length == 0u) {
        constexpr uchar default_password[6] = {
            'a', 'e', 'z', 'e', 'e', 'd'
        };
        for (uint n = 0u; n < 6u; ++n) password[n] = default_password[n];
        password_length = 6u;
    } else {
        const device char* source =
            password_data + ulong(tid) * ulong(AEZEED_PASSWORD_STRIDE);
        for (uint n = 0u; n < raw_length; ++n) {
            password[n] = uchar(source[n]);
        }
    }

    uchar key[32];
    if (!walletks_scrypt_sha256_32_params(
            password, password_length, salt, 5u,
            AEZEED_SCRYPT_N, AEZEED_SCRYPT_R, AEZEED_SCRYPT_P,
            scratch, scratch_stride, ulong(tid), key)) {
        return;
    }
    uchar plaintext[19];
    if (!aezeed_decipher(key, config, plaintext)) return;
    const uint internal_version = uint(plaintext[0]);
    if (internal_version >= 32u ||
        ((config.known_internal_versions >> internal_version) & 1u) == 0u) {
        return;
    }
    const uint birthday =
        (uint(plaintext[1]) << 8u) | uint(plaintext[2]);
    if (birthday > config.maximum_birthday) return;

    const uint slot = atomic_fetch_add_explicit(
        hit_count, 1u, memory_order_relaxed);
    if (slot >= hit_capacity) return;
    hits[slot].candidate_index = candidate_base + ulong(tid);
    hits[slot].password_len = raw_length;
    hits[slot].internal_version = internal_version;
    hits[slot].birthday = birthday;
    hits[slot].reserved = 0u;
    const device char* original =
        password_data + ulong(tid) * ulong(AEZEED_PASSWORD_STRIDE);
    for (uint n = 0u; n < 128u; ++n) {
        hits[slot].password[n] =
            n < raw_length ? uchar(original[n]) : 0u;
    }
    for (uint n = 0u; n < 16u; ++n) {
        hits[slot].entropy[n] = plaintext[n + 3u];
    }
    for (uint n = 0u; n < 19u; ++n) {
        hits[slot].plaintext[n] = plaintext[n];
    }
    for (uint n = 0u; n < 32u; ++n) hits[slot].key[n] = key[n];
    for (uint n = 0u; n < 5u; ++n) hits[slot].padding[n] = 0u;
}
