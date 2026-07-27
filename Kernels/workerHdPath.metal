#include "WorkerPrivCommon.metalh"

#ifdef memcpy
#undef memcpy
#endif
#ifdef memset
#undef memset
#endif

struct HdPathComponent {
    uint kind;
    uint base;
    uint count;
    uint values_offset;
};

struct HdPathTarget {
    ulong prefix;
    uint source_index;
    uint reserved;
    uchar key[33];
    uchar padding[15];
};

struct HdPathHit {
    ulong ordinal[4];
    uint target_index;
    uint has_private;
    uchar private_key[32];
    uchar public_key[33];
    uchar padding[7];
};

static inline void hd_copy_device_to_thread(thread uchar* dst,
                                            const device uchar* src,
                                            uint count) {
    for (uint i = 0u; i < count; ++i) dst[i] = src[i];
}

static inline void hd_copy_thread_to_device(device uchar* dst,
                                            const thread uchar* src,
                                            uint count) {
    for (uint i = 0u; i < count; ++i) dst[i] = src[i];
}

static inline void hd_copy_thread(thread uchar* dst,
                                  const thread uchar* src,
                                  uint count) {
    for (uint i = 0u; i < count; ++i) dst[i] = src[i];
}

static inline void hd_copy_u256_from_device(
    thread ulong out[4], const device ulong* source) {
    for (uint i = 0u; i < 4u; ++i) out[i] = source[i];
}

static inline bool hd_add_u64(thread ulong value[4], ulong addend) {
    const ulong before = value[0];
    value[0] += addend;
    ulong carry = value[0] < before ? 1ul : 0ul;
    for (uint i = 1u; i < 4u && carry != 0ul; ++i) {
        const ulong limb = value[i];
        value[i] += carry;
        carry = value[i] < limb ? 1ul : 0ul;
    }
    return carry == 0ul;
}

static inline uint hd_divmod_u32(thread ulong value[4], uint divisor) {
    uint words[8];
    for (uint i = 0u; i < 4u; ++i) {
        words[i * 2u] = uint(value[i]);
        words[i * 2u + 1u] = uint(value[i] >> 32u);
    }
    ulong remainder = 0ul;
    for (int i = 7; i >= 0; --i) {
        const ulong current = (remainder << 32u) | ulong(words[i]);
        words[i] = uint(current / ulong(divisor));
        remainder = current % ulong(divisor);
    }
    for (uint i = 0u; i < 4u; ++i) {
        value[i] = ulong(words[i * 2u]) |
                   (ulong(words[i * 2u + 1u]) << 32u);
    }
    return uint(remainder);
}

static inline ulong hd_prefix(const thread uchar key[33]) {
    ulong result = 0ul;
    for (uint i = 0u; i < 8u; ++i) {
        result = (result << 8u) | ulong(key[i]);
    }
    return result;
}

static inline bool hd_equal_key(const thread uchar left[33],
                                const device uchar* right) {
    for (uint i = 0u; i < 33u; ++i) {
        if (left[i] != right[i]) return false;
    }
    return true;
}

static inline bool hd_parse_compressed(const thread uchar serialized[33],
                                       thread secp256k1_pubkey* output) {
    if (serialized[0] != 0x02u && serialized[0] != 0x03u) return false;
    secp256k1_fe x;
    if (!secp256k1_fe_set_b32(&x, serialized + 1u)) return false;
    secp256k1_ge point;
    if (!secp256k1_ge_set_xo_var(
            &point, &x, serialized[0] == 0x03u)) {
        return false;
    }
    secp256k1_pubkey_save(output, &point);
    return true;
}

static inline bool hd_public_from_private(
    const constant secp256k1_ge_storage* precompute,
    size_t pitch,
    uint window_count,
    uint window_bits,
    const thread uchar private_key[32],
    thread secp256k1_pubkey* public_key) {
    secp256k1_scalar scalar;
    if (!secp256k1_scalar_set_b32_seckey(&scalar, private_key)) {
        return false;
    }
    secp256k1_gej jacobian;
    secp256k1_ecmult_big(
        &jacobian, &scalar, precompute, pitch,
        int(window_count), window_bits);
    if (jacobian.infinity != 0) return false;
    secp256k1_ge point;
    secp256k1_ge_set_gej(&point, &jacobian);
    secp256k1_pubkey_save(public_key, &point);
    return true;
}

static inline void hd_hmac_child(const thread uchar chain[32],
                                 const thread uchar data33[33],
                                 uint index,
                                 thread uchar output[64]) {
    uchar input[40] = {};
    for (uint i = 0u; i < 33u; ++i) input[i] = data33[i];
    input[33] = uchar(index >> 24u);
    input[34] = uchar(index >> 16u);
    input[35] = uchar(index >> 8u);
    input[36] = uchar(index);
    hmac_sha512_const(
        reinterpret_cast<const thread uint*>(chain),
        reinterpret_cast<const thread uint*>(input),
        reinterpret_cast<thread uint*>(output));
}

static inline bool hd_ckd_private_once(
    const constant secp256k1_ge_storage* precompute,
    size_t pitch,
    uint window_count,
    uint window_bits,
    const thread extended_private_key_t& parent,
    const thread uchar parent_public[33],
    bool has_parent_public,
    uint index,
    thread extended_private_key_t& child) {
    uchar data[33];
    if ((index & 0x80000000u) != 0u) {
        data[0] = 0u;
        for (uint i = 0u; i < 32u; ++i) data[i + 1u] = parent.key[i];
    } else if (has_parent_public) {
        hd_copy_thread(data, parent_public, 33u);
    } else {
        secp256k1_pubkey public_key;
        if (!hd_public_from_private(
                precompute, pitch, window_count, window_bits,
                parent.key, &public_key)) {
            return false;
        }
        serialized_public_key(
            reinterpret_cast<thread uchar*>(&public_key), data);
    }
    uchar digest[64];
    hd_hmac_child(parent.chain_code, data, index, digest);
    uchar candidate[32];
    for (uint i = 0u; i < 32u; ++i) candidate[i] = parent.key[i];
    if (!secp256k1_ec_seckey_tweak_add(candidate, digest)) {
        return false;
    }
    for (uint i = 0u; i < 32u; ++i) {
        child.key[i] = candidate[i];
        child.chain_code[i] = digest[i + 32u];
    }
    return true;
}

static inline bool hd_ckd_private(
    const constant secp256k1_ge_storage* precompute,
    size_t pitch,
    uint window_count,
    uint window_bits,
    const thread extended_private_key_t& parent,
    const thread uchar parent_public[33],
    bool has_parent_public,
    uint initial_index,
    thread extended_private_key_t& child) {
    uint index = initial_index;
    const uint boundary = (initial_index & 0x80000000u) != 0u
        ? 0xffffffffu : 0x7fffffffu;
    for (;;) {
        if (hd_ckd_private_once(
                precompute, pitch, window_count, window_bits,
                parent, parent_public, has_parent_public,
                index, child)) {
            return true;
        }
        if (index == boundary) return false;
        ++index;
    }
}

static inline bool hd_ckd_public_once(
    const constant secp256k1_ge_storage* precompute,
    size_t pitch,
    uint window_count,
    uint window_bits,
    const thread uchar parent_key[33],
    const thread uchar parent_chain[32],
    uint index,
    thread uchar child_key[33],
    thread uchar child_chain[32]) {
    if ((index & 0x80000000u) != 0u) return false;
    uchar digest[64];
    hd_hmac_child(parent_chain, parent_key, index, digest);

    secp256k1_scalar tweak;
    int overflow = 0;
    secp256k1_scalar_set_b32(&tweak, digest, &overflow);
    if (overflow) return false;

    secp256k1_pubkey point;
    if (!hd_parse_compressed(parent_key, &point)) return false;
    if (!secp256k1_scalar_is_zero(&tweak)) {
        secp256k1_ge parent;
        if (!secp256k1_pubkey_load(&parent, &point)) return false;
        secp256k1_gej sum;
        secp256k1_gej_set_ge(&sum, &parent);
        secp256k1_gej tweak_point;
        secp256k1_ecmult_big(
            &tweak_point, &tweak, precompute, pitch,
            int(window_count), window_bits);
        secp256k1_gej_add_var(&sum, &sum, &tweak_point, nullptr);
        if (sum.infinity != 0) return false;
        secp256k1_ge result;
        secp256k1_ge_set_gej(&result, &sum);
        secp256k1_pubkey_save(&point, &result);
    }
    if (!secp256k1_ec_pubkey_serialize(
            child_key, 33u, &point, true)) {
        return false;
    }
    for (uint i = 0u; i < 32u; ++i) child_chain[i] = digest[i + 32u];
    return true;
}

static inline bool hd_ckd_public(
    const constant secp256k1_ge_storage* precompute,
    size_t pitch,
    uint window_count,
    uint window_bits,
    const thread uchar parent_key[33],
    const thread uchar parent_chain[32],
    uint initial_index,
    thread uchar child_key[33],
    thread uchar child_chain[32]) {
    uint index = initial_index;
    for (;;) {
        if (hd_ckd_public_once(
                precompute, pitch, window_count, window_bits,
                parent_key, parent_chain,
                index, child_key, child_chain)) {
            return true;
        }
        if (index == 0x7fffffffu) return false;
        ++index;
    }
}

static inline int hd_find_target(
    const thread uchar key[33],
    const device HdPathTarget* targets,
    uint target_count) {
    const ulong prefix = hd_prefix(key);
    uint low = 0u;
    uint high = target_count;
    while (low < high) {
        const uint middle = low + ((high - low) >> 1u);
        if (targets[middle].prefix < prefix) low = middle + 1u;
        else high = middle;
    }
    for (uint i = low;
         i < target_count && targets[i].prefix == prefix;
         ++i) {
        if (hd_equal_key(key, targets[i].key)) return int(i);
    }
    return -1;
}

kernel void workerHdPath(
    const constant secp256k1_ge_storage* precompute [[buffer(0)]],
    constant ulong& pitch_value [[buffer(1)]],
    constant uint& window_count [[buffer(2)]],
    constant uint& window_bits [[buffer(3)]],
    const device uchar* root_private [[buffer(4)]],
    const device uchar* root_public [[buffer(5)]],
    const device uchar* root_chain [[buffer(6)]],
    constant uint& root_kind [[buffer(7)]],
    const device HdPathComponent* components [[buffer(8)]],
    const device uint* component_values [[buffer(9)]],
    constant uint& component_count [[buffer(10)]],
    const device ulong* base_ordinal [[buffer(11)]],
    const device HdPathTarget* targets [[buffer(12)]],
    constant uint& target_count [[buffer(13)]],
    device HdPathHit* hits [[buffer(14)]],
    device atomic_uint* hit_count [[buffer(15)]],
    constant uint& hit_capacity [[buffer(16)]],
    constant ulong& candidate_count [[buffer(17)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count || component_count > 32u) return;

    ulong ordinal[4];
    hd_copy_u256_from_device(ordinal, base_ordinal);
    if (!hd_add_u64(ordinal, ulong(tid))) return;
    ulong remaining[4];
    for (uint i = 0u; i < 4u; ++i) remaining[i] = ordinal[i];

    uint indexes[32] = {};
    for (uint i = 0u; i < component_count; ++i) {
        const HdPathComponent component = components[i];
        if (component.count == 0u) return;
        const uint digit = hd_divmod_u32(remaining, component.count);
        if (component.kind == 0u) {
            indexes[i] = component.base + digit;
        } else {
            indexes[i] =
                component_values[component.values_offset + digit];
        }
    }

    uchar private_key[32] = {};
    uchar public_key[33] = {};
    bool valid = true;
    if (root_kind == 0u) {
        extended_private_key_t current;
        hd_copy_device_to_thread(current.key, root_private, 32u);
        hd_copy_device_to_thread(current.chain_code, root_chain, 32u);
        uchar root_public_key[33];
        hd_copy_device_to_thread(root_public_key, root_public, 33u);
        for (uint i = 0u; i < component_count && valid; ++i) {
            extended_private_key_t next;
            valid = hd_ckd_private(
                precompute, size_t(pitch_value),
                window_count, window_bits, current,
                root_public_key, i == 0u,
                indexes[i], next);
            current = next;
        }
        if (valid) {
            for (uint i = 0u; i < 32u; ++i) private_key[i] = current.key[i];
            secp256k1_pubkey point;
            valid = hd_public_from_private(
                precompute, size_t(pitch_value),
                window_count, window_bits, private_key, &point);
            if (valid) {
                valid = secp256k1_ec_pubkey_serialize(
                    public_key, 33u, &point, true) != 0;
            }
        }
    } else {
        hd_copy_device_to_thread(public_key, root_public, 33u);
        uchar chain[32];
        hd_copy_device_to_thread(chain, root_chain, 32u);
        for (uint i = 0u; i < component_count && valid; ++i) {
            uchar next_key[33];
            uchar next_chain[32];
            valid = hd_ckd_public(
                precompute, size_t(pitch_value),
                window_count, window_bits, public_key, chain,
                indexes[i], next_key, next_chain);
            if (valid) {
                hd_copy_thread(public_key, next_key, 33u);
                hd_copy_thread(chain, next_chain, 32u);
            }
        }
    }
    if (!valid) return;

    const int target_index =
        hd_find_target(public_key, targets, target_count);
    if (target_index < 0) return;
    const uint slot = atomic_fetch_add_explicit(
        hit_count, 1u, memory_order_relaxed);
    if (slot >= hit_capacity) return;
    for (uint i = 0u; i < 4u; ++i) hits[slot].ordinal[i] = ordinal[i];
    hits[slot].target_index = uint(target_index);
    hits[slot].has_private = root_kind == 0u ? 1u : 0u;
    hd_copy_thread_to_device(hits[slot].private_key, private_key, 32u);
    hd_copy_thread_to_device(hits[slot].public_key, public_key, 33u);
}
