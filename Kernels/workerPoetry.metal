#include "WorkerPrivCommon.metalh"
#include "PoetryCommon.metalh"

#ifndef METAL_CRYPTO_TARGET_FC_DECLARED
#define METAL_CRYPTO_TARGET_FC_DECLARED
constant bool TFC_COMPRESSED [[function_constant(0)]];
constant bool TFC_UNCOMPRESSED [[function_constant(1)]];
constant bool TFC_SEGWIT [[function_constant(2)]];
constant bool TFC_P2WSH [[function_constant(3)]];
constant bool TFC_TAPROOT [[function_constant(4)]];
constant bool TFC_ETHEREUM [[function_constant(5)]];
constant bool TFC_XPOINT [[function_constant(6)]];
constant bool TFC_XRP_SECP [[function_constant(7)]];
constant bool TFC_SUI_SECP [[function_constant(8)]];
constant bool TFC_IOTA_SECP [[function_constant(9)]];
constant bool TFC_APTOS_SECP [[function_constant(10)]];
constant bool TFC_ICP_SECP [[function_constant(11)]];
constant bool TFC_FIL_SECP [[function_constant(12)]];
constant bool TFC_XTZ_SECP [[function_constant(13)]];
constant bool TFC_SECP_ANY [[function_constant(14)]];
constant bool TFC_ED_ANY [[function_constant(15)]];
constant bool TFC_SOLANA [[function_constant(16)]];
constant bool TFC_DOT [[function_constant(17)]];
constant bool TFC_ADA [[function_constant(18)]];
constant bool TFC_TON [[function_constant(19)]];
constant bool TFC_TON_ALL [[function_constant(20)]];
constant bool TFC_XRP_ED [[function_constant(21)]];
constant bool TFC_APTOS_ED [[function_constant(22)]];
constant bool TFC_SUI_ED [[function_constant(23)]];
constant bool TFC_IOTA_ED [[function_constant(24)]];
constant bool TFC_ICP_ED [[function_constant(25)]];
constant bool TFC_XTZ_ED [[function_constant(26)]];
#endif

static inline void poetry_found_buffers(device char* foundStrings,
                                        device uchar* foundPrvKeys,
                                        device uint* foundHash160,
                                        device uint* foundLen,
                                        device uchar* foundType,
                                        device long* foundRound,
                                        device atomic_uint* resultsCount,
                                        device RuntimeConfig& config,
                                        thread FoundBuffers& found) {
    found.foundStrings = foundStrings;
    found.foundPrvKeys = foundPrvKeys;
    found.foundHash160 = foundHash160;
    found.len = foundLen;
    found.iter = nullptr;
    found.type = foundType;
    found.foundDerivations = nullptr;
    found.foundDerivations2 = nullptr;
    found.pass = nullptr;
    found.passSize = nullptr;
    found.round = foundRound;
    found.seed = nullptr;
    found.resultsCount = resultsCount;
    found.maxFounds = config.maxFounds;
}

kernel void workerPoetry(device bool* isResult [[buffer(0)]],
                         device bool* buffResult [[buffer(1)]],
                         const device PoetryTemplateDevice* poetry_template [[buffer(2)]],
                         device PoetryThreadState* poetry_states [[buffer(3)]],
                         constant ulong& global_stride [[buffer(4)]],
                         const device char* dictionary_blob [[buffer(5)]],
                         const device ushort* dictionary_offsets [[buffer(6)]],
                         const device uchar* dictionary_lengths [[buffer(7)]],
                         device atomic_uint* processed_candidates [[buffer(8)]],
                         device atomic_uint* active_threads [[buffer(9)]],
                         constant secp256k1_ge_storage* precPtr [[buffer(10)]],
                         constant ulong& precPitch [[buffer(11)]],
                         constant ulong& round [[buffer(12)]],
                         device RuntimeConfig& config [[buffer(13)]],
                         device XorFilterState& filters [[buffer(14)]],
                         device FilterStorageState& filter_storage [[buffer(15)]],
                         const device uchar* bloom_storage [[buffer(16)]],
                         const device uchar* xor_storage [[buffer(17)]],
                         const device uchar* xor_un_storage [[buffer(18)]],
                         const device uchar* xor_uc_storage [[buffer(19)]],
                         const device uchar* xor_hc_storage [[buffer(20)]],
                         device char* foundStrings [[buffer(21)]],
                         device uchar* foundPrvKeys [[buffer(22)]],
                         device uint* foundHash160 [[buffer(23)]],
                         device uint* foundLen [[buffer(24)]],
                         device uchar* foundType [[buffer(25)]],
                         device long* foundRound [[buffer(26)]],
                         device atomic_uint* resultsCount [[buffer(27)]],
                         const device SubstratePathDevice* substratePaths [[buffer(28)]],
                         uint tid [[thread_position_in_grid]]) {
    device PoetryThreadState& state = poetry_states[tid];
    if (state.active == 0u) return;

    FoundBuffers found;
    poetry_found_buffers(foundStrings, foundPrvKeys, foundHash160, foundLen, foundType,
                         foundRound, resultsCount, config, found);

    uchar prvKeys[PRIV_THREAD_STEPS * 32u];
    uchar pubKeys[PRIV_THREAD_STEPS * 65u];
    uchar pubKeysED[PRIV_THREAD_STEPS * 32u];
    ushort batch_start_digits[POETRY_MAX_WORDS];
    ulong lane_seeds[PRIV_THREAD_STEPS];
    for (uint i = 0u; i < POETRY_MAX_WORDS; ++i) batch_start_digits[i] = state.digits[i];
    for (uint i = 0u; i < PRIV_THREAD_STEPS; ++i) lane_seeds[i] = 0ul;

    int key_count = 0;
    if (poetry_template->random_mode != 0u) {
        ulong persistent_state = state.random_state;
        for (uint lane = 0u; lane < PRIV_THREAD_STEPS; ++lane) {
            lane_seeds[lane] = rng_splitmix64(persistent_state);
            ushort word_ids[POETRY_MAX_WORDS];
            poetry_materialize_random_ids(*poetry_template, lane_seeds[lane], word_ids);
            poetry_decode_private_key(word_ids, poetry_template->word_count, prvKeys + lane * 32u);
            ++key_count;
        }
        state.random_state = persistent_state;
    } else {
        ushort digits[POETRY_MAX_WORDS];
        for (uint i = 0u; i < POETRY_MAX_WORDS; ++i) digits[i] = state.digits[i];
        for (uint lane = 0u; lane < PRIV_THREAD_STEPS; ++lane) {
            ushort word_ids[POETRY_MAX_WORDS];
            poetry_materialize_finite_ids(*poetry_template, digits, word_ids);
            poetry_decode_private_key(word_ids, poetry_template->word_count, prvKeys + lane * 32u);
            ++key_count;
            if (!poetry_add_stride(digits, poetry_template->wildcard_count, global_stride)) {
                state.active = 0u;
                break;
            }
        }
        for (uint i = 0u; i < POETRY_MAX_WORDS; ++i) state.digits[i] = digits[i];
        if (state.active != 0u) {
            atomic_fetch_add_explicit(active_threads, 1u, memory_order_relaxed);
        }
    }
    atomic_fetch_add_explicit(processed_candidates, uint(key_count), memory_order_relaxed);
    if (key_count == 0) return;

    if (round > 0ul) bump_all_keys(prvKeys, key_count, round, false, nullptr);

    const bool secp256_dev = TFC_SECP_ANY && config.secp256 != 0u && config.secpTargetsAny != 0u;
    const bool ed25519_dev = TFC_ED_ANY && config.ed25519 != 0u && config.edTargetsAny != 0u;
    const bool compressed = TFC_COMPRESSED && config.compressed != 0u;
    const bool uncompressed = TFC_UNCOMPRESSED && config.uncompressed != 0u;
    const bool segwit = TFC_SEGWIT && config.segwit != 0u;
    const bool p2wsh = TFC_P2WSH && config.p2wsh != 0u;
    const bool taproot = TFC_TAPROOT && config.taproot != 0u;
    const bool ethereum = TFC_ETHEREUM && config.ethereum != 0u;
    const bool xpoint = TFC_XPOINT && config.xpoint != 0u;
    const bool xrp_secp = TFC_XRP_SECP && config.xrp != 0u;
    const bool sui_secp = TFC_SUI_SECP && config.sui != 0u;
    const bool iota_secp = TFC_IOTA_SECP && config.iota != 0u;
    const bool aptos_secp = TFC_APTOS_SECP && config.aptos != 0u;
    const bool icp_secp = TFC_ICP_SECP && config.icp != 0u;
    const bool fil_secp = TFC_FIL_SECP && config.fil != 0u;
    const bool xtz_secp = TFC_XTZ_SECP && config.xtz != 0u;
    const bool solana = TFC_SOLANA && config.solana != 0u;
    const bool dot = TFC_DOT && config.dot != 0u;
    const bool ada = TFC_ADA && config.ada != 0u;
    const bool ton = TFC_TON && config.ton != 0u;
    const bool ton_all = TFC_TON_ALL && config.tonAll != 0u;
    const bool xrp_ed = TFC_XRP_ED && config.xrp != 0u;
    const bool aptos_ed = TFC_APTOS_ED && config.aptos != 0u;
    const bool sui_ed = TFC_SUI_ED && config.sui != 0u;
    const bool iota_ed = TFC_IOTA_ED && config.iota != 0u;
    const bool icp_ed = TFC_ICP_ED && config.icp != 0u;
    const bool xtz_ed = TFC_XTZ_ED && config.xtz != 0u;
    const bool ed_common_pub_needed = priv_ed_common_pub_needed(solana, dot, ton, ton_all,
                                                                xrp_ed, aptos_ed, sui_ed,
                                                                iota_ed, icp_ed, xtz_ed, config);

    for (ulong i = 0ul; i <= 2ul * round; ++i) {
        const long current_round = long(i) - long(round);

        if (secp256_dev) {
            uchar tap_hash[32u * PRIV_THREAD_STEPS];
            if (i == 0ul) {
                secp256k1_ec_pubkey_create_serialized_batch_myunsafe(pubKeys, prvKeys, key_count,
                                                                     precPtr, size_t(precPitch));
            }
            if (taproot) TweakTaproot_batch(tap_hash, pubKeys, key_count, precPtr, size_t(precPitch));
            for (uint lane = 0u; lane < uint(key_count); ++lane) {
                char phrase[POETRY_MAX_PHRASE_BYTES];
                const ushort phrase_len = poetry_phrase_for_lane(*poetry_template, batch_start_digits,
                                                                  lane_seeds, lane, global_stride,
                                                                  dictionary_blob, dictionary_offsets,
                                                                  dictionary_lengths, phrase);
                priv_emit_secp_targets_round(isResult, buffResult, phrase, ulong(phrase_len),
                                             prvKeys, pubKeys, tap_hash, lane, 0u, current_round,
                                             0u, false, compressed, uncompressed, segwit, p2wsh,
                                             taproot, ethereum, xpoint, xrp_secp, sui_secp,
                                             aptos_secp, iota_secp, icp_secp, fil_secp, xtz_secp,
                                             config, filters, filter_storage, bloom_storage,
                                             xor_storage, xor_un_storage, xor_uc_storage,
                                             xor_hc_storage, found);
            }
        }

        if (ed25519_dev) {
            if (ed_common_pub_needed) {
                priv_ed25519_key_to_pub_batch_config(prvKeys, pubKeysED, key_count, config);
            }
            for (uint lane = 0u; lane < uint(key_count); ++lane) {
                char phrase[POETRY_MAX_PHRASE_BYTES];
                const ushort phrase_len = poetry_phrase_for_lane(*poetry_template, batch_start_digits,
                                                                  lane_seeds, lane, global_stride,
                                                                  dictionary_blob, dictionary_offsets,
                                                                  dictionary_lengths, phrase);
                thread uchar* pkey = prvKeys + lane * 32u;
                thread uchar* publ = ed_common_pub_needed ? (pubKeysED + lane * 32u) : nullptr;
                const thread uchar* next_key = (lane + 1u < uint(key_count)) ? (pkey + 32u) : nullptr;
                priv_emit_ed_targets_round(isResult, buffResult, phrase, ulong(phrase_len), pkey,
                                           next_key, publ, 0u, current_round, 0u, false, solana,
                                           dot, ton, ton_all, xrp_ed, aptos_ed, sui_ed, iota_ed,
                                           ada, icp_ed, xtz_ed, substratePaths, config, filters,
                                           filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                           xor_uc_storage, xor_hc_storage, found);
            }
        }

        if (i < 2ul * round) {
            int zeroz[PRIV_THREAD_STEPS] = { 0 };
            const int wrapped = bump_all_keys(prvKeys, key_count, 1ul, true, zeroz);
            if (secp256_dev) {
                if (wrapped != 0) {
                    for (int lane = 0; lane < key_count; ++lane) {
                        if (zeroz[lane] != 0) {
                            secp256k1_ge base;
                            secp256k1_ge_from_storage(&base, &precPtr[0]);
                            thread uchar* dst = pubKeys + uint(zeroz[lane] - 1) * 65u;
                            dst[0] = 0x04u;
                            secp256k1_fe bx = base.x;
                            secp256k1_fe by = base.y;
                            secp256k1_fe_normalize_var(&bx);
                            secp256k1_fe_normalize_var(&by);
                            secp256k1_fe_get_b32(dst + 1u, &bx);
                            secp256k1_fe_get_b32(dst + 33u, &by);
                        }
                    }
                }
                priv_pub_add_basepoint_batch(pubKeys, key_count, +1, precPtr);
            }
        }
    }
}
