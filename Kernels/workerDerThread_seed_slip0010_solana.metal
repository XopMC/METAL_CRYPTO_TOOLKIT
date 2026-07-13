#include "WorkerDerThreadCommon.metalh"

static inline uchar der_seed_fast_hex_nibble(uchar c) {
    if (c >= uchar('0') && c <= uchar('9')) return c - uchar('0');
    if (c >= uchar('a') && c <= uchar('f')) return c - uchar('a') + 10u;
    if (c >= uchar('A') && c <= uchar('F')) return c - uchar('A') + 10u;
    return 0u;
}

static inline void der_seed_fast_copy_input(thread char dst[512],
                                            thread uchar material[512],
                                            thread uint& save_len,
                                            thread uint& material_len,
                                            const device char* input,
                                            uint input_len,
                                            device RuntimeConfig& config) {
    save_len = min(input_len, 511u);
    for (uint i = 0u; i < save_len; ++i) {
        const char c = input[i];
        dst[i] = c;
        material[i] = uchar(c);
    }
    dst[save_len] = 0;
    for (uint i = save_len + 1u; i < 512u; ++i) {
        dst[i] = 0;
    }
    material_len = save_len;

    if (config.isHex != 0u) {
        const uint n = min(input_len >> 1u, 512u);
        for (uint i = 0u; i < n; ++i) {
            const uchar hi = der_seed_fast_hex_nibble(uchar(input[i * 2u]));
            const uchar lo = der_seed_fast_hex_nibble(uchar(input[i * 2u + 1u]));
            material[i] = uchar((hi << 4u) | lo);
        }
        for (uint i = n; i < 512u; ++i) {
            material[i] = 0u;
        }
        material_len = n;
    }
}

kernel void workerDerThread_seed_slip0010_solana(device bool* isResult [[buffer(0)]],
                                                 device bool* buffResult [[buffer(1)]],
                                                 const device char* input_str [[buffer(2)]],
                                                 constant uint& input_len [[buffer(3)]],
                                                 const device uint* d_derivations [[buffer(4)]],
                                                 const device uint* d_deriv_offsets [[buffer(5)]],
                                                 const device uint* derindex [[buffer(6)]],
                                                 constant uint& der_indexes_size [[buffer(7)]],
                                                 constant uint& der_offset [[buffer(8)]],
                                                 constant ulong& round [[buffer(9)]],
                                                 device RuntimeConfig& config [[buffer(10)]],
                                                 device XorFilterState& filters [[buffer(11)]],
                                                 device FilterStorageState& filter_storage [[buffer(12)]],
                                                 const device uchar* bloom_storage [[buffer(13)]],
                                                 const device uchar* xor_storage [[buffer(14)]],
                                                 const device uchar* xor_un_storage [[buffer(15)]],
                                                 const device uchar* xor_uc_storage [[buffer(16)]],
                                                 const device uchar* xor_hc_storage [[buffer(17)]],
                                                 device char* foundStrings [[buffer(18)]],
                                                 device uchar* foundPrvKeys [[buffer(19)]],
                                                 device uint* foundHash160 [[buffer(20)]],
                                                 device uint* foundLen [[buffer(21)]],
                                                 device uchar* foundType [[buffer(22)]],
                                                 device uint* foundDerivations [[buffer(23)]],
                                                 device char* foundPass [[buffer(24)]],
                                                 device ushort* foundPassSize [[buffer(25)]],
                                                 device long* foundRound [[buffer(26)]],
                                                 device ulong* foundSeed [[buffer(27)]],
                                                 device atomic_uint* resultsCount [[buffer(28)]],
                                                 uint tid [[thread_position_in_grid]]) {
    const uint global_path = tid + der_offset;
    if (global_path >= der_indexes_size || input_str == nullptr ||
        d_derivations == nullptr || d_deriv_offsets == nullptr || derindex == nullptr) {
        return;
    }

    FoundBuffers found;
    der_make_found_buffers(foundStrings, foundPrvKeys, foundHash160, foundLen, nullptr,
                           foundType, foundDerivations, nullptr, foundPass,
                           foundPassSize, foundRound, foundSeed, resultsCount,
                           config.maxFounds, found);

    char save_str[512] = { 0 };
    uchar material[512] = { 0 };
    uint save_len = 0u;
    uint material_len = 0u;
    der_seed_fast_copy_input(save_str, material, save_len, material_len,
                             input_str, input_len, config);

    extended_private_key_t master_private = {};
    if (material_len == 64u) {
        HMAC_SHA512_ED25519_SEED_64(material, reinterpret_cast<thread uchar*>(&master_private));
    } else {
        HMAC_SHA512(ed_key, 12ul, material, ulong(material_len),
                    reinterpret_cast<thread uchar*>(&master_private));
    }

    const uint path_offset = d_deriv_offsets[global_path];
    const uint path_len = derindex[global_path];
    uchar sol_priv[32];
    der_get_child_key_ed25519(&master_private, d_derivations + path_offset,
                              path_len, sol_priv);

    if (round > 0ul) {
        bump_key_256(sol_priv, round, false);
    }

    for (ulong s = 0ul; s <= (2ul * round); ++s) {
        const long current_round = long(s) - long(round);

        uchar publ[32];
        priv_ed25519_key_to_pub_one_config(sol_priv, publ, config);
        uint hash_words[8] = { 0 };
        priv_hash_words_from_bytes(publ, hash_words, 32u);
        der_check_and_store_words(isResult, buffResult, sol_priv, publ, 32u,
                                  hash_words, 0x60u, global_path, input_str,
                                  save_len, nullptr, 0u, false, 0ul,
                                  current_round, config, filters, filter_storage,
                                  bloom_storage, xor_storage, xor_un_storage,
                                  xor_uc_storage, xor_hc_storage, found);

        if (s < (2ul * round)) {
            bump_key_256(sol_priv, 1ul, true);
        }
    }
}
