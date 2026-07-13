#include "WorkerPrivCommon.metalh"
#include "HexsetSeqCommon.metalh"

kernel void workerPRIV_seq_hexset(device bool* isResult [[buffer(0)]],
                                  device bool* buffResult [[buffer(1)]],
                                  constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                  constant ulong& precPitch [[buffer(3)]],
                                  const device uchar* hexset_start_digits [[buffer(4)]],
                                  const device uchar* hexset_lower_exact [[buffer(5)]],
                                  const device uchar* hexset_upper_exact [[buffer(6)]],
                                  constant ushort& hexset_digit_count [[buffer(7)]],
                                  const device uchar* hexset_alphabet [[buffer(8)]],
                                  constant uchar& hexset_base [[buffer(9)]],
                                  constant ulong& gpu_stride [[buffer(10)]],
                                  constant ulong& round [[buffer(11)]],
                                  device RuntimeConfig& config [[buffer(12)]],
                                  device XorFilterState& filters [[buffer(13)]],
                                  device FilterStorageState& filter_storage [[buffer(14)]],
                                  const device uchar* bloom_storage [[buffer(15)]],
                                  const device uchar* xor_storage [[buffer(16)]],
                                  const device uchar* xor_un_storage [[buffer(17)]],
                                  const device uchar* xor_uc_storage [[buffer(18)]],
                                  const device uchar* xor_hc_storage [[buffer(19)]],
                                  device uchar* foundPrvKeys [[buffer(20)]],
                                  device uint* foundHash160 [[buffer(21)]],
                                  device uchar* foundType [[buffer(22)]],
                                  device long* foundRound [[buffer(23)]],
                                  device atomic_uint* resultsCount [[buffer(24)]],
                                  const device SubstratePathDevice* substratePaths [[buffer(25)]],
                                  uint tid [[thread_position_in_grid]]) {
    if (hexset_digit_count == 0u || hexset_digit_count > 64u ||
        (hexset_digit_count & 1u) != 0u || gpu_stride == 0ul || hexset_base == 0u) {
        return;
    }

    FoundBuffers found;
    found.foundStrings = nullptr;
    found.foundPrvKeys = foundPrvKeys;
    found.foundHash160 = foundHash160;
    found.len = nullptr;
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

    uchar pubKeys[PRIV_THREAD_STEPS * 65u];
    uchar prvKeys[PRIV_THREAD_STEPS * 32u];
    uchar pubKeysED[PRIV_THREAD_STEPS * 32u];

    int privKeyIx = 0;
    const ulong thread_base_start = ulong(tid) * ulong(PRIV_THREAD_STEPS);
    for (int base_idx = 0; base_idx < int(PRIV_THREAD_STEPS) && privKeyIx < int(PRIV_THREAD_STEPS); ++base_idx) {
        const ulong offset = (thread_base_start + ulong(base_idx)) * gpu_stride;
        uchar exact_key[32];
        const uint exact_size = uint(hexset_digit_count >> 1);
        if (!hexset_materialize_candidate_exact(hexset_start_digits,
                                                uint(hexset_digit_count),
                                                hexset_alphabet,
                                                uint(hexset_base),
                                                offset,
                                                exact_key)) {
            continue;
        }
        if (!hexset_candidate_within_exact_bounds(exact_key, hexset_lower_exact, hexset_upper_exact, exact_size)) {
            continue;
        }
        hexset_zero_pad_left(prvKeys + uint(privKeyIx) * 32u, 32u, exact_key, exact_size);
        ++privKeyIx;
    }

    if (privKeyIx == 0) {
        return;
    }
    if (round > 0ul) {
        bump_all_keys(prvKeys, privKeyIx, round, false, nullptr);
    }

    const bool secp256_dev = config.secp256 != 0u;
    const bool ed25519_dev = config.ed25519 != 0u;
    const bool compressed = config.compressed != 0u;
    const bool uncompressed = config.uncompressed != 0u;
    const bool segwit = config.segwit != 0u;
    const bool p2wsh = config.p2wsh != 0u;
    const bool taproot = config.taproot != 0u;
    const bool ethereum = config.ethereum != 0u;
    const bool xpoint = config.xpoint != 0u;
    const bool solana = config.solana != 0u;
    const bool ton = config.ton != 0u;
    const bool ton_all = config.tonAll != 0u;
    const bool dot = config.dot != 0u;
    const bool aptos = config.aptos != 0u;
    const bool sui = config.sui != 0u;
    const bool xrp = config.xrp != 0u;
    const bool iota = config.iota != 0u;
    const bool ada = config.ada != 0u;
    const bool icp = config.icp != 0u;
    const bool fil = config.fil != 0u;
    const bool xtz = config.xtz != 0u;
    const bool ed_common_pub_needed = priv_ed_common_pub_needed(solana, dot, ton, ton_all,
                                                                xrp, aptos, sui, iota,
                                                                icp, xtz, config);

    for (ulong i = 0ul; i <= 2ul * round; ++i) {
        const long current_round = long(i) - long(round);

        if (secp256_dev) {
            if (i == 0ul) {
                secp256k1_ec_pubkey_create_serialized_batch_myunsafe(pubKeys,
                                                                     prvKeys,
                                                                     privKeyIx,
                                                                     precPtr,
                                                                     size_t(precPitch));
            }
            uchar tap_hash[32u * PRIV_THREAD_STEPS];
            if (taproot) {
                TweakTaproot_batch(tap_hash, pubKeys, privKeyIx, precPtr, size_t(precPitch));
            }
            for (uint pkField = 0u; pkField < PRIV_THREAD_STEPS && pkField < uint(privKeyIx); ++pkField) {
                priv_emit_secp_targets_round(isResult,
                                             buffResult,
                                             nullptr,
                                             0ul,
                                             prvKeys,
                                             pubKeys,
                                             tap_hash,
                                             pkField,
                                             0u,
                                             current_round,
                                             0u,
                                             false,
                                             compressed,
                                             uncompressed,
                                             segwit,
                                             p2wsh,
                                             taproot,
                                             ethereum,
                                             xpoint,
                                             xrp,
                                             sui,
                                             aptos,
                                             iota,
                                             icp,
                                             fil,
                                             xtz,
                                             config,
                                             filters,
                                             filter_storage,
                                             bloom_storage,
                                             xor_storage,
                                             xor_un_storage,
                                             xor_uc_storage,
                                             xor_hc_storage,
                                             found);
            }
        }

        if (ed25519_dev) {
            if (ed_common_pub_needed) {
                priv_ed25519_key_to_pub_batch_config(prvKeys, pubKeysED, privKeyIx, config);
            }
            for (uint pkField = 0u; pkField < PRIV_THREAD_STEPS && pkField < uint(privKeyIx); ++pkField) {
                const uint pk4 = pkField * 32u;
                thread uchar* publ = ed_common_pub_needed ? (pubKeysED + pk4) : nullptr;
                thread uchar* pkey = prvKeys + pk4;
                const thread uchar* next_key = nullptr;
                if (pkField < uint(privKeyIx - 1)) {
                    next_key = prvKeys + pk4 + 32u;
                }
                priv_emit_ed_targets_round(isResult,
                                           buffResult,
                                           nullptr,
                                           0ul,
                                           pkey,
                                           next_key,
                                           publ,
                                           0u,
                                           current_round,
                                           0u,
                                           false,
                                           solana,
                                           dot,
                                           ton,
                                           ton_all,
                                           xrp,
                                           aptos,
                                           sui,
                                           iota,
                                           ada,
                                           icp,
                                           xtz,
                                           substratePaths,
                                           config,
                                           filters,
                                           filter_storage,
                                           bloom_storage,
                                           xor_storage,
                                           xor_un_storage,
                                           xor_uc_storage,
                                           xor_hc_storage,
                                           found);
            }
        }

        if (i < 2ul * round) {
            int zeroz[32] = { 0 };
            const int wrapped = bump_all_keys(prvKeys, privKeyIx, 1ul, true, zeroz);
            if (secp256_dev) {
                if (wrapped != 0) {
                    for (int n = 0; n < privKeyIx; ++n) {
                        if (zeroz[n] != 0) {
                            thread uchar* dst = pubKeys + uint(zeroz[n] - 1) * 65u;
                            for (uint k = 0u; k < 65u; ++k) {
                                dst[k] = PRIV_SECP_G65[k];
                            }
                        }
                    }
                }
                priv_pub_add_basepoint_batch(pubKeys, privKeyIx, +1, precPtr);
            }
        }
    }
}
