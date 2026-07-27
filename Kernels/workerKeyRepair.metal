#include <metal_stdlib>
#include "GPUHash.metalh"
#include "ProfanityRecoveryCommon.metalh"

using namespace metal;

constant uchar KEYREPAIR_BASE58[58] = {
    '1','2','3','4','5','6','7','8','9',
    'A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z'
};

enum KeyRepairType : uint {
    KEYREPAIR_WIF = 1u,
    KEYREPAIR_XPRV = 2u,
    KEYREPAIR_XPUB = 3u,
    KEYREPAIR_ADDRESS = 4u,
    KEYREPAIR_RAW_PRIVATE = 5u,
    KEYREPAIR_RAW_PUBLIC = 6u,
};

struct KeyRepairHit {
    ulong ordinal;
    uint decoded_len;
    uint kind;
    uchar decoded[128];
};

static inline int keyrepair_base58_digit(uchar c) {
    for (int i = 0; i < 58; ++i) {
        if (KEYREPAIR_BASE58[i] == c) return i;
    }
    return -1;
}

static inline uint keyrepair_be32(const thread uchar* p) {
    return (uint(p[0]) << 24u) | (uint(p[1]) << 16u) |
           (uint(p[2]) << 8u) | uint(p[3]);
}

static inline bool keyrepair_scalar_nonzero(const thread uchar* scalar) {
    uchar aggregate = 0u;
    for (uint i = 0u; i < 32u; ++i) aggregate |= scalar[i];
    return aggregate != 0u;
}

static inline bool keyrepair_scalar_below_order(const thread uchar* scalar) {
    thread uchar order[32] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
        0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,
        0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
    };
    for (uint i = 0u; i < 32u; ++i) {
        if (scalar[i] < order[i]) return true;
        if (scalar[i] > order[i]) return false;
    }
    return false;
}

static inline bool keyrepair_version_is_private(uint version) {
    return version == 0x0488ade4u || version == 0x049d7878u ||
           version == 0x04b2430cu || version == 0x0295b005u ||
           version == 0x02aa7a99u || version == 0x04358394u;
}

static inline bool keyrepair_version_is_public(uint version) {
    return version == 0x0488b21eu || version == 0x049d7cb2u ||
           version == 0x04b24746u || version == 0x0295b43fu ||
           version == 0x02aa7ed3u || version == 0x043587cfu;
}

static inline void keyrepair_sha256(const thread uchar* data,
                                    uint len,
                                    thread uchar out[32]) {
    uint state[8];
    SHA256Initialize(state);
    const uint blocks = len >> 6u;
    if (blocks != 0u) {
        sha256_process_blocks(state, data, blocks);
    }
    const uint tail_len = len & 63u;
    sha256_finalize_from_state(state, data + (blocks << 6u), tail_len,
                               ulong(len), out);
}

static inline bool keyrepair_decode_base58(const thread uchar* text,
                                           uint text_len,
                                           thread uchar decoded[128],
                                           thread uint& decoded_len) {
    uchar little[128];
    for (uint i = 0u; i < 128u; ++i) {
        little[i] = 0u;
        decoded[i] = 0u;
    }
    uint leading = 0u;
    while (leading < text_len && text[leading] == '1') ++leading;
    uint little_len = 0u;
    for (uint i = leading; i < text_len; ++i) {
        const int digit = keyrepair_base58_digit(text[i]);
        if (digit < 0) return false;
        uint carry = uint(digit);
        for (uint j = 0u; j < little_len; ++j) {
            carry += uint(little[j]) * 58u;
            little[j] = uchar(carry & 0xffu);
            carry >>= 8u;
        }
        while (carry != 0u) {
            if (little_len >= 128u) return false;
            little[little_len++] = uchar(carry & 0xffu);
            carry >>= 8u;
        }
    }
    if (leading + little_len > 128u) return false;
    for (uint i = 0u; i < little_len; ++i) {
        decoded[leading + i] = little[little_len - 1u - i];
    }
    decoded_len = leading + little_len;
    return decoded_len >= 5u;
}

static inline bool keyrepair_valid_structure(const thread uchar decoded[128],
                                             uint decoded_len,
                                             uint kind) {
    if (decoded_len < 5u) return false;
    const uint payload_len = decoded_len - 4u;
    if (kind == KEYREPAIR_WIF) {
        if (payload_len != 33u && payload_len != 34u) return false;
        if (decoded[0] != 0x80u && decoded[0] != 0xefu) return false;
        if (payload_len == 34u && decoded[33] != 0x01u) return false;
        return keyrepair_scalar_nonzero(decoded + 1u) &&
               keyrepair_scalar_below_order(decoded + 1u);
    }
    if (kind == KEYREPAIR_XPRV || kind == KEYREPAIR_XPUB) {
        if (payload_len != 78u) return false;
        const uint version = keyrepair_be32(decoded);
        if (kind == KEYREPAIR_XPRV) {
            return keyrepair_version_is_private(version) &&
                   decoded[45] == 0u &&
                   keyrepair_scalar_nonzero(decoded + 46u) &&
                   keyrepair_scalar_below_order(decoded + 46u);
        }
        return keyrepair_version_is_public(version) &&
               (decoded[45] == 0x02u || decoded[45] == 0x03u);
    }
    if (kind == KEYREPAIR_ADDRESS) {
        if (payload_len != 21u) return false;
        const uchar version = decoded[0];
        return version == 0x00u || version == 0x05u ||
               version == 0x6fu || version == 0xc4u;
    }
    return false;
}

static inline void keyrepair_emit(device KeyRepairHit* hits,
                                  device atomic_uint* hit_count,
                                  uint hit_capacity,
                                  ulong ordinal,
                                  uint kind,
                                  const thread uchar* decoded,
                                  uint decoded_len) {
    const uint slot =
        atomic_fetch_add_explicit(hit_count, 1u, memory_order_relaxed);
    if (slot >= hit_capacity) return;
    hits[slot].ordinal = ordinal;
    hits[slot].decoded_len = decoded_len;
    hits[slot].kind = kind;
    for (uint i = 0u; i < 128u; ++i) {
        hits[slot].decoded[i] = i < decoded_len ? decoded[i] : 0u;
    }
}

kernel void keyRepairBase58Check(const device uchar* template_text [[buffer(0)]],
                                 constant uint& text_len [[buffer(1)]],
                                 const device uint* missing_positions [[buffer(2)]],
                                 constant uint& missing_count [[buffer(3)]],
                                 constant uint& kind [[buffer(4)]],
                                 const device uint* start_digits [[buffer(5)]],
                                 constant ulong& range_count [[buffer(6)]],
                                 device KeyRepairHit* hits [[buffer(7)]],
                                 device atomic_uint* hit_count [[buffer(8)]],
                                 constant uint& hit_capacity [[buffer(9)]],
                                 uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= range_count || text_len == 0u || text_len > 128u ||
        missing_count > 15u) {
        return;
    }
    const ulong ordinal = ulong(tid);
    ulong carry = ordinal;
    uchar text[128];
    for (uint i = 0u; i < text_len; ++i) text[i] = template_text[i];
    for (uint i = 0u; i < missing_count; ++i) {
        const uint pos = missing_positions[i];
        if (pos >= text_len) return;
        const ulong sum = ulong(start_digits[i]) + carry;
        text[pos] = KEYREPAIR_BASE58[sum % 58u];
        carry = sum / 58u;
    }
    if (carry != 0u) return;
    uchar decoded[128];
    uint decoded_len = 0u;
    if (!keyrepair_decode_base58(text, text_len, decoded, decoded_len) ||
        !keyrepair_valid_structure(decoded, decoded_len, kind)) {
        return;
    }
    uchar first[32];
    uchar second[32];
    keyrepair_sha256(decoded, decoded_len - 4u, first);
    keyrepair_sha256(first, 32u, second);
    uint diff = 0u;
    for (uint i = 0u; i < 4u; ++i) {
        diff |= uint(second[i] ^ decoded[decoded_len - 4u + i]);
    }
    if (diff == 0u) {
        keyrepair_emit(hits, hit_count, hit_capacity, ordinal, kind,
                       decoded, decoded_len);
    }
}

static inline int keyrepair_hex_digit(uchar c) {
    if (c >= '0' && c <= '9') return int(c - '0');
    if (c >= 'a' && c <= 'f') return int(c - 'a') + 10;
    if (c >= 'A' && c <= 'F') return int(c - 'A') + 10;
    return -1;
}

static inline bool keyrepair_fill_hex(const device uchar* template_text,
                                      uint text_len,
                                      const device uint* missing_positions,
                                      const device uint* start_digits,
                                      uint missing_count,
                                      ulong ordinal,
                                      thread uchar* bytes,
                                      uint byte_len) {
    uchar text[130];
    if (text_len > 130u || text_len != byte_len * 2u) return false;
    for (uint i = 0u; i < text_len; ++i) text[i] = template_text[i];
    ulong carry = ordinal;
    for (uint i = 0u; i < missing_count; ++i) {
        const uint pos = missing_positions[i];
        if (pos >= text_len) return false;
        const ulong sum = ulong(start_digits[i]) + carry;
        const uint nibble = uint(sum & 15u);
        text[pos] = uchar(nibble < 10u ? ('0' + nibble) : ('a' + nibble - 10u));
        carry = sum >> 4u;
    }
    if (carry != 0u) return false;
    for (uint i = 0u; i < byte_len; ++i) {
        const int high = keyrepair_hex_digit(text[i * 2u]);
        const int low = keyrepair_hex_digit(text[i * 2u + 1u]);
        if (high < 0 || low < 0) return false;
        bytes[i] = uchar((high << 4) | low);
    }
    return true;
}

kernel void keyRepairRawPrivate(const device uchar* template_text [[buffer(0)]],
                                constant uint& text_len [[buffer(1)]],
                                const device uint* missing_positions [[buffer(2)]],
                                constant uint& missing_count [[buffer(3)]],
                                const device uint* start_digits [[buffer(4)]],
                                constant ulong& range_count [[buffer(5)]],
                                const device uchar* target_pubkey [[buffer(6)]],
                                constant uint& target_len [[buffer(7)]],
                                const constant secp256k1_ge_storage* prec [[buffer(8)]],
                                constant ulong& prec_pitch [[buffer(9)]],
                                device KeyRepairHit* hits [[buffer(10)]],
                                device atomic_uint* hit_count [[buffer(11)]],
                                constant uint& hit_capacity [[buffer(12)]],
                                uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= range_count || text_len != 64u ||
        missing_count > 15u || (target_len != 33u && target_len != 65u)) {
        return;
    }
    const ulong ordinal = ulong(tid);
    uchar private_key[32];
    if (!keyrepair_fill_hex(template_text, text_len, missing_positions,
                            start_digits, missing_count, ordinal,
                            private_key, 32u) ||
        !keyrepair_scalar_nonzero(private_key) ||
        !keyrepair_scalar_below_order(private_key)) {
        return;
    }
    uchar pubkey65[65];
    pubkey65[0] = 0x04u;
    const int ok = secp256k1_ec_pubkey_create(
        reinterpret_cast<thread secp256k1_pubkey*>(pubkey65 + 1u),
        private_key, prec, size_t(prec_pitch));
    if (ok == 0 ||
        !profanity_pubkey_matches_target(pubkey65, target_pubkey, target_len)) {
        return;
    }
    keyrepair_emit(hits, hit_count, hit_capacity, ordinal,
                   KEYREPAIR_RAW_PRIVATE, private_key, 32u);
}

kernel void keyRepairRawPublic(const device uchar* template_text [[buffer(0)]],
                               constant uint& text_len [[buffer(1)]],
                               const device uint* missing_positions [[buffer(2)]],
                               constant uint& missing_count [[buffer(3)]],
                               const device uint* start_digits [[buffer(4)]],
                               constant ulong& range_count [[buffer(5)]],
                               const device uchar* target_pubkey [[buffer(6)]],
                               constant uint& target_len [[buffer(7)]],
                               device KeyRepairHit* hits [[buffer(8)]],
                               device atomic_uint* hit_count [[buffer(9)]],
                               constant uint& hit_capacity [[buffer(10)]],
                               uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= range_count || (text_len != 66u && text_len != 130u) ||
        missing_count > 15u) {
        return;
    }
    const ulong ordinal = ulong(tid);
    const uint byte_len = text_len >> 1u;
    uchar public_key[65];
    if (!keyrepair_fill_hex(template_text, text_len, missing_positions,
                            start_digits, missing_count, ordinal,
                            public_key, byte_len)) {
        return;
    }
    secp256k1_ge point;
    bool valid = false;
    if (byte_len == 33u &&
        (public_key[0] == 0x02u || public_key[0] == 0x03u)) {
        secp256k1_fe x;
        valid = secp256k1_fe_set_b32(&x, public_key + 1u) != 0 &&
                secp256k1_ge_set_xo_var(
                    &point, &x, public_key[0] == 0x03u) != 0;
    } else if (byte_len == 65u && public_key[0] == 0x04u) {
        secp256k1_fe x;
        secp256k1_fe y;
        valid = secp256k1_fe_set_b32(&x, public_key + 1u) != 0 &&
                secp256k1_fe_set_b32(&y, public_key + 33u) != 0 &&
                secp256k1_ge_set_xo_var(
                    &point, &x, secp256k1_fe_is_odd(&y)) != 0 &&
                secp256k1_fe_equal(&point.y, &y) != 0;
    }
    if (!valid) return;
    if (target_len != 0u) {
        if (target_len != byte_len) return;
        uint diff = 0u;
        for (uint i = 0u; i < byte_len; ++i) {
            diff |= uint(public_key[i] ^ target_pubkey[i]);
        }
        if (diff != 0u) return;
    }
    keyrepair_emit(hits, hit_count, hit_capacity, ordinal,
                   KEYREPAIR_RAW_PUBLIC, public_key, byte_len);
}
