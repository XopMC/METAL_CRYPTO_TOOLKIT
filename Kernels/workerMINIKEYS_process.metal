#include "WorkerMinikeysCommon.metalh"

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

static inline void _GetHash160ED(const thread unsigned char* pubkey,
                                 thread int& keyLen,
                                 thread uint8_t* hash) {
    uchar tmp[32];
    const uint start = uint(keyLen);
    for (uint i = 0u; i < 32u; ++i) {
        tmp[i] = pubkey[start + i];
    }
    int local_key_len = 0;
    _GetHash160ED(tmp, local_key_len, hash);
    keyLen += 32;
}

#include "WorkerPrivCommon.metalh"

static inline void minikey_process_copy_device(thread uchar* dst,
                                               const device uchar* src,
                                               uint len) {
    for (uint i = 0u; i < len; ++i) {
        dst[i] = src[i];
    }
}

static inline void minikey_process_store(device bool* isResult,
                                         device bool* buffResult,
                                         const thread uchar* private_key32,
                                         const thread void* payload,
                                         uint payload_len,
                                         uchar type_value,
                                         long current_round,
                                         const thread uchar* minikey,
                                         uchar minikey_len,
                                         FoundBuffers found) {
    if (buffResult != nullptr) {
        buffResult[0] = true;
    }
    if (isResult != nullptr) {
        isResult[0] = true;
    }
    if (found.resultsCount == nullptr) {
        return;
    }
    const ulong idx64 = found_atomic_add_count(found.resultsCount, 1u);
    if (idx64 >= ulong(found.maxFounds)) {
        return;
    }
    const uint idx = uint(idx64);

    if (found.foundPrvKeys != nullptr && private_key32 != nullptr) {
        found_copy_thread_to_device_uchar(found.foundPrvKeys + ulong(idx) * kFoundPrivateKeyBytes,
                                          private_key32,
                                          32u);
    }
    if (found.foundHash160 != nullptr && payload != nullptr && payload_len > 0u) {
        const uint n = min(payload_len, kFoundHashWords * 4u);
        device uchar* out = reinterpret_cast<device uchar*>(found.foundHash160 + ulong(idx) * kFoundHashWords);
        found_copy_thread_to_device_bytes(out, payload, n);
    }
    if (found.type != nullptr) {
        found.type[idx] = type_value;
    }
    if (found.round != nullptr) {
        found.round[idx] = current_round;
    }
    if (found.len != nullptr) {
        found.len[idx] = uint(minikey_len);
    }
    if (found.foundStrings != nullptr && minikey != nullptr) {
        device char* dst = found.foundStrings + ulong(idx) * kFoundStringBytes;
        for (uint i = 0u; i < MINIKEY_STAGE_STRIDE; ++i) {
            dst[i] = char((i < uint(minikey_len)) ? minikey[i] : 0u);
        }
    }
}

static inline void minikey_process_check_words(device bool* isResult,
                                               device bool* buffResult,
                                               const thread uchar* private_key32,
                                               const thread void* payload,
                                               uint payload_len,
                                               const thread uint* hash_words,
                                               uchar type_value,
                                               long current_round,
                                               const thread uchar* minikey,
                                               uchar minikey_len,
                                               device RuntimeConfig& config,
                                               device XorFilterState& filters,
                                               device FilterStorageState& storage,
                                               const device uchar* bloom_storage,
                                               const device uchar* xor_storage,
                                               const device uchar* xor_un_storage,
                                               const device uchar* xor_uc_storage,
                                               const device uchar* xor_hc_storage,
                                               FoundBuffers found) {
    if (priv_check_hash_words(config, filters, storage, bloom_storage, xor_storage, xor_un_storage,
                              xor_uc_storage, xor_hc_storage, hash_words)) {
        minikey_process_store(isResult, buffResult, private_key32, payload, payload_len,
                              type_value, current_round, minikey, minikey_len, found);
    }
}

static inline void minikey_process_check_bytes(device bool* isResult,
                                               device bool* buffResult,
                                               const thread uchar* private_key32,
                                               const thread uchar* payload,
                                               uint payload_len,
                                               const thread uchar* hash_bytes,
                                               uint hash_len,
                                               uchar type_value,
                                               long current_round,
                                               const thread uchar* minikey,
                                               uchar minikey_len,
                                               device RuntimeConfig& config,
                                               device XorFilterState& filters,
                                               device FilterStorageState& storage,
                                               const device uchar* bloom_storage,
                                               const device uchar* xor_storage,
                                               const device uchar* xor_un_storage,
                                               const device uchar* xor_uc_storage,
                                               const device uchar* xor_hc_storage,
                                               FoundBuffers found) {
    uint hash_words[8];
    priv_hash_words_from_bytes(hash_bytes, hash_words, hash_len);
    minikey_process_check_words(isResult, buffResult, private_key32, payload, payload_len,
                                hash_words, type_value, current_round, minikey, minikey_len,
                                config, filters, storage, bloom_storage, xor_storage,
                                xor_un_storage, xor_uc_storage, xor_hc_storage, found);
}

static inline void minikey_process_emit_ton(device bool* isResult,
                                            device bool* buffResult,
                                            const thread uchar* private_key32,
                                            const thread uchar* publ,
                                            const constant char* ton_kind,
                                            uchar type_value,
                                            long current_round,
                                            const thread uchar* minikey,
                                            uchar minikey_len,
                                            device RuntimeConfig& config,
                                            device XorFilterState& filters,
                                            device FilterStorageState& storage,
                                            const device uchar* bloom_storage,
                                            const device uchar* xor_storage,
                                            const device uchar* xor_un_storage,
                                            const device uchar* xor_uc_storage,
                                            const device uchar* xor_hc_storage,
                                            FoundBuffers found) {
    uchar hash_addr[32];
    if (ton_type_enabled_config(config, type_value) &&
        pubkey_to_hash_ton(publ, ton_kind, hash_addr, config.tonTypeMask)) {
        minikey_process_check_bytes(isResult, buffResult, private_key32, hash_addr, 32u,
                                    hash_addr, 32u, type_value, current_round, minikey,
                                    minikey_len, config, filters, storage, bloom_storage,
                                    xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage,
                                    found);
    }
}

kernel void workerMINIKEYS_process(device bool* isResult [[buffer(0)]],
                                   device bool* buffResult [[buffer(1)]],
                                   constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                   constant ulong& precPitch [[buffer(3)]],
                                   const device uchar* valid_minikeys [[buffer(4)]],
                                   const device uchar* valid_minikey_lens [[buffer(5)]],
                                   const device uint* valid_count_ptr [[buffer(6)]],
                                   constant ulong& round [[buffer(7)]],
                                   constant uint& valid_capacity [[buffer(8)]],
                                   device RuntimeConfig& config [[buffer(9)]],
                                   device XorFilterState& filters [[buffer(10)]],
                                   device FilterStorageState& filter_storage [[buffer(11)]],
                                   const device uchar* bloom_storage [[buffer(12)]],
                                   const device uchar* xor_storage [[buffer(13)]],
                                   const device uchar* xor_un_storage [[buffer(14)]],
                                   const device uchar* xor_uc_storage [[buffer(15)]],
                                   const device uchar* xor_hc_storage [[buffer(16)]],
                                   device char* foundStrings [[buffer(17)]],
                                   device uchar* foundPrvKeys [[buffer(18)]],
                                   device uint* foundHash160 [[buffer(19)]],
                                   device uint* foundLen [[buffer(20)]],
                                   device uint* foundIter [[buffer(21)]],
                                   device uchar* foundType [[buffer(22)]],
                                   device uint* foundDerivations [[buffer(23)]],
                                   device uint* foundDerivations2 [[buffer(24)]],
                                   device char* foundPass [[buffer(25)]],
                                   device ushort* foundPassSize [[buffer(26)]],
                                   device long* foundRound [[buffer(27)]],
                                   device ulong* foundSeed [[buffer(28)]],
                                   device atomic_uint* resultsCount [[buffer(29)]],
                                   const device SubstratePathDevice* substratePaths [[buffer(30)]],
                                   uint tid [[thread_position_in_grid]]) {
    if (valid_minikeys == nullptr || valid_minikey_lens == nullptr || valid_count_ptr == nullptr) {
        return;
    }

    FoundBuffers found;
    found.foundStrings = foundStrings;
    found.foundPrvKeys = foundPrvKeys;
    found.foundHash160 = foundHash160;
    found.len = foundLen;
    found.iter = foundIter;
    found.type = foundType;
    found.foundDerivations = foundDerivations;
    found.foundDerivations2 = foundDerivations2;
    found.pass = foundPass;
    found.passSize = foundPassSize;
    found.round = foundRound;
    found.seed = foundSeed;
    found.resultsCount = resultsCount;
    found.maxFounds = config.maxFounds;

    const uint valid_count = min(valid_count_ptr[0], valid_capacity);
    if (valid_count == 0u) {
        return;
    }

    const ulong thread_base = ulong(tid) * ulong(MINIKEY_THREAD_STEPS);
    if (thread_base >= ulong(valid_count)) {
        return;
    }
    int privKeyIx = int(ulong(valid_count) - thread_base);
    if (privKeyIx > int(MINIKEY_THREAD_STEPS)) {
        privKeyIx = int(MINIKEY_THREAD_STEPS);
    }

    uchar prvKeys[MINIKEY_THREAD_STEPS * 32u];
    uchar minikeys[MINIKEY_THREAD_STEPS * MINIKEY_STAGE_STRIDE];
    uchar minikey_lens[MINIKEY_THREAD_STEPS];
    for (uint i = 0u; i < MINIKEY_THREAD_STEPS; ++i) {
        minikey_lens[i] = 0u;
        for (uint b = 0u; b < 32u; ++b) {
            prvKeys[i * 32u + b] = 0u;
        }
        for (uint b = 0u; b < MINIKEY_STAGE_STRIDE; ++b) {
            minikeys[i * MINIKEY_STAGE_STRIDE + b] = 0u;
        }
    }

    for (int i = 0; i < privKeyIx; ++i) {
        const ulong item = thread_base + ulong(i);
        const uchar mlen = valid_minikey_lens[item];
        minikey_lens[i] = mlen;
        const ulong src_mini = item * ulong(MINIKEY_STAGE_STRIDE);
        const uint dst_mini = uint(i) * MINIKEY_STAGE_STRIDE;
        const uint dst_key = uint(i) * 32u;
        if (mlen >= 2u && mlen <= 30u) {
            minikey_process_copy_device(minikeys + dst_mini, valid_minikeys + src_mini, uint(mlen));
            SHA256(minikeys + dst_mini, size_t(mlen), prvKeys + dst_key);
        } else {
            minikey_lens[i] = 0u;
        }
    }

    if (round > 0ul) {
        bump_all_keys(prvKeys, privKeyIx, round, false, nullptr);
    }

    for (ulong r = 0ul; r <= (2ul * round); ++r) {
        const long current_round = long(r) - long(round);

        if (TFC_SECP_ANY && config.secp256 != 0u && config.secpTargetsAny != 0u) {
            uchar pubKeys[MINIKEY_THREAD_STEPS * 65u];
            secp256k1_ec_pubkey_create_serialized_batch_myunsafe(pubKeys,
                                                                 prvKeys,
                                                                 privKeyIx,
                                                                 precPtr,
                                                                 size_t(precPitch));
            uchar tap_hash[32u * MINIKEY_THREAD_STEPS];
            if (TFC_TAPROOT && config.taproot != 0u) {
                TweakTaproot_batch(tap_hash, pubKeys, privKeyIx, precPtr, size_t(precPitch));
            }

            for (int pkField = 0; pkField < privKeyIx; ++pkField) {
                if (minikey_lens[pkField] == 0u) {
                    continue;
                }
                thread uchar* private_key = prvKeys + uint(pkField) * 32u;
                thread uchar* pubkey = pubKeys + uint(pkField) * 65u;
                thread uchar* minikey = minikeys + uint(pkField) * MINIKEY_STAGE_STRIDE;
                const uchar minikey_len = minikey_lens[pkField];
                uint hash160[8] = { 0 };
                uint compressed_hash160[8] = { 0 };
                int keyLenSkip = int(uint(pkField) * 65u);

                if (TFC_UNCOMPRESSED && config.uncompressed != 0u) {
                    _GetHash160(pubKeys, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
                    minikey_process_check_words(isResult, buffResult, private_key, hash160, 32u,
                                                hash160, 0x01u, current_round, minikey, minikey_len,
                                                config, filters, filter_storage, bloom_storage,
                                                xor_storage, xor_un_storage, xor_uc_storage,
                                                xor_hc_storage, found);
                }
                const bool compressed_enabled = TFC_COMPRESSED && config.compressed != 0u;
                const bool segwit_enabled = TFC_SEGWIT && config.segwit != 0u;
                const bool xrp_secp_enabled = TFC_XRP_SECP && config.xrp != 0u &&
                                              xrp_type_enabled(config, 0x90u);
                const bool need_compressed_hash160 = compressed_enabled || segwit_enabled ||
                                                     xrp_secp_enabled;
                if (need_compressed_hash160) {
                    keyLenSkip = int(uint(pkField) * 65u);
                    _GetHash160Comp(pubKeys, keyLenSkip,
                                    reinterpret_cast<thread uchar*>(compressed_hash160));
                }
                if (compressed_enabled) {
                    minikey_process_check_words(isResult, buffResult, private_key,
                                                compressed_hash160, 32u, compressed_hash160,
                                                0x02u, current_round, minikey, minikey_len,
                                                config, filters, filter_storage, bloom_storage,
                                                xor_storage, xor_un_storage, xor_uc_storage,
                                                xor_hc_storage, found);
                }
                if (segwit_enabled) {
                    for (uint i = 0u; i < 8u; ++i) {
                        hash160[i] = compressed_hash160[i];
                    }
                    _GetHash160P2SHCompFromHash(hash160, hash160);
                    minikey_process_check_words(isResult, buffResult, private_key, hash160, 32u,
                                                hash160, 0x03u, current_round, minikey, minikey_len,
                                                config, filters, filter_storage, bloom_storage,
                                                xor_storage, xor_un_storage, xor_uc_storage,
                                                xor_hc_storage, found);
                }
                if (TFC_P2WSH && config.p2wsh != 0u) {
                    uchar p2wsh_hash[32];
                    uint p2wsh_rmd[8] = { 0 };
                    _GetP2WSHComp(pubkey, p2wsh_hash, p2wsh_rmd);
                    minikey_process_check_words(isResult, buffResult, private_key, p2wsh_hash, 32u,
                                                p2wsh_rmd, 0x07u, current_round, minikey, minikey_len,
                                                config, filters, filter_storage, bloom_storage,
                                                xor_storage, xor_un_storage, xor_uc_storage,
                                                xor_hc_storage, found);
                }
                if (TFC_TAPROOT && config.taproot != 0u) {
                    thread uchar* taproot_hash = tap_hash + uint(pkField) * 32u;
                    _GetRMD160(reinterpret_cast<thread uint*>(taproot_hash), hash160);
                    minikey_process_check_words(isResult, buffResult, private_key, taproot_hash, 32u,
                                                hash160, 0x04u, current_round, minikey, minikey_len,
                                                config, filters, filter_storage, bloom_storage,
                                                xor_storage, xor_un_storage, xor_uc_storage,
                                                xor_hc_storage, found);
                }
                if (TFC_ETHEREUM && config.ethereum != 0u) {
                    uchar keccak_hash[32];
                    keccak(reinterpret_cast<thread char*>(pubkey + 1), 64, keccak_hash, 32);
                    for (uint h = 12u, i = 0u; i < 5u; ++i) {
                        hash160[i] = uint(keccak_hash[h]) |
                                     ((uint(keccak_hash[h + 1u]) << 8u) & 0x0000ff00u) |
                                     ((uint(keccak_hash[h + 2u]) << 16u) & 0x00ff0000u) |
                                     ((uint(keccak_hash[h + 3u]) << 24u) & 0xff000000u);
                        h += 4u;
                    }
                    minikey_process_check_words(isResult, buffResult, private_key, hash160, 32u,
                                                hash160, 0x06u, current_round, minikey, minikey_len,
                                                config, filters, filter_storage, bloom_storage,
                                                xor_storage, xor_un_storage, xor_uc_storage,
                                                xor_hc_storage, found);
                }
                if (TFC_XPOINT && config.xpoint != 0u) {
                    uint xpoint_hash[8] = { 0 };
                    thread uchar* xbytes = reinterpret_cast<thread uchar*>(xpoint_hash);
                    priv_copy_thread_uchar(xbytes, pubkey + 1, 32u);
                    minikey_process_check_words(isResult, buffResult, private_key, xpoint_hash, 32u,
                                                xpoint_hash, 0x05u, current_round, minikey, minikey_len,
                                                config, filters, filter_storage, bloom_storage,
                                                xor_storage, xor_un_storage, xor_uc_storage,
                                                xor_hc_storage, found);
                }
                if (xrp_secp_enabled) {
                    minikey_process_check_words(isResult, buffResult, private_key,
                                                compressed_hash160, 32u, compressed_hash160,
                                                0x90u, current_round, minikey, minikey_len,
                                                config, filters, filter_storage, bloom_storage,
                                                xor_storage, xor_un_storage, xor_uc_storage,
                                                xor_hc_storage, found);
                }
                if (TFC_SUI_SECP && config.sui != 0u && sui_type_enabled(config, 0x70u)) {
                    uchar buff[34];
                    buff[0] = 0x01u;
                    buff[1] = 0x02u + (pubkey[64] & 1u);
                    priv_copy_thread_uchar(buff + 2, pubkey + 1, 32u);
                    uchar hash_addr[32];
                    Blake2b_256(buff, 34u, hash_addr);
                    minikey_process_check_bytes(isResult, buffResult, private_key, hash_addr, 32u,
                                                hash_addr, 32u, 0x70u, current_round, minikey,
                                                minikey_len, config, filters, filter_storage,
                                                bloom_storage, xor_storage, xor_un_storage,
                                                xor_uc_storage, xor_hc_storage, found);
                }
                if (TFC_APTOS_SECP && config.aptos != 0u && aptos_type_enabled(config, 0x22u)) {
                    uchar buff[35] = { 0 };
                    buff[0] = 0x01u;
                    buff[1] = 0x02u + (pubkey[64] & 1u);
                    priv_copy_thread_uchar(buff + 2, pubkey + 1, 32u);
                    buff[34] = 0x02u;
                    uchar hash_addr[32];
                    sha3_256(reinterpret_cast<thread char*>(buff), 35, hash_addr);
                    minikey_process_check_bytes(isResult, buffResult, private_key, hash_addr, 32u,
                                                hash_addr, 32u, 0x22u, current_round, minikey,
                                                minikey_len, config, filters, filter_storage,
                                                bloom_storage, xor_storage, xor_un_storage,
                                                xor_uc_storage, xor_hc_storage, found);
                }
                if (TFC_IOTA_SECP && config.iota != 0u && iota_type_enabled(config, 0x50u)) {
                    uchar buff[34];
                    buff[0] = 0x01u;
                    buff[1] = 0x02u + (pubkey[64] & 1u);
                    priv_copy_thread_uchar(buff + 2, pubkey + 1, 32u);
                    uchar hash_addr[32];
                    Blake2b_256(buff, 34u, hash_addr);
                    minikey_process_check_bytes(isResult, buffResult, private_key, hash_addr, 32u,
                                                hash_addr, 32u, 0x50u, current_round, minikey,
                                                minikey_len, config, filters, filter_storage,
                                                bloom_storage, xor_storage, xor_un_storage,
                                                xor_uc_storage, xor_hc_storage, found);
                }
                if (TFC_ICP_SECP && config.icp != 0u && icp_type_enabled(config, 0x53u)) {
                    uchar principal[29] = { 0 };
                    icp_principal_from_secp256k1(pubkey, principal);
                    uchar hash_addr[32];
                    icp_account_identifier(principal, nullptr, hash_addr);
                    minikey_process_check_bytes(isResult, buffResult, private_key, hash_addr, 32u,
                                                hash_addr, 32u, 0x53u, current_round, minikey,
                                                minikey_len, config, filters, filter_storage,
                                                bloom_storage, xor_storage, xor_un_storage,
                                                xor_uc_storage, xor_hc_storage, found);
                }
                if (TFC_FIL_SECP && config.fil != 0u) {
                    if (fil_type_enabled(config, 0x41u)) {
                        uchar hash_addr[20];
                        Blake2b_160(pubkey, 65u, hash_addr);
                        minikey_process_check_bytes(isResult, buffResult, private_key, hash_addr, 20u,
                                                    hash_addr, 20u, 0x41u, current_round, minikey,
                                                    minikey_len, config, filters, filter_storage,
                                                    bloom_storage, xor_storage, xor_un_storage,
                                                    xor_uc_storage, xor_hc_storage, found);
                    }
                    if (fil_type_enabled(config, 0x42u)) {
                        uchar keccak_hash[32];
                        keccak(reinterpret_cast<thread char*>(pubkey + 1), 64, keccak_hash, 32);
                        for (uint h = 12u, i = 0u; i < 5u; ++i) {
                            hash160[i] = uint(keccak_hash[h]) |
                                         ((uint(keccak_hash[h + 1u]) << 8u) & 0x0000ff00u) |
                                         ((uint(keccak_hash[h + 2u]) << 16u) & 0x00ff0000u) |
                                         ((uint(keccak_hash[h + 3u]) << 24u) & 0xff000000u);
                            h += 4u;
                        }
                        minikey_process_check_words(isResult, buffResult, private_key, hash160, 20u,
                                                    hash160, 0x42u, current_round, minikey, minikey_len,
                                                    config, filters, filter_storage, bloom_storage,
                                                    xor_storage, xor_un_storage, xor_uc_storage,
                                                    xor_hc_storage, found);
                    }
                }
                if (TFC_XTZ_SECP && config.xtz != 0u && xtz_type_enabled(config, 0x92u)) {
                    uchar buff[33] = { 0 };
                    buff[0] = 0x02u + (pubkey[64] & 1u);
                    priv_copy_thread_uchar(buff + 1, pubkey + 1, 32u);
                    uchar hash_addr[20];
                    Blake2b_160(buff, 33u, hash_addr);
                    minikey_process_check_bytes(isResult, buffResult, private_key, hash_addr, 20u,
                                                hash_addr, 20u, 0x92u, current_round, minikey,
                                                minikey_len, config, filters, filter_storage,
                                                bloom_storage, xor_storage, xor_un_storage,
                                                xor_uc_storage, xor_hc_storage, found);
                }
            }
        }

        if (TFC_ED_ANY && config.ed25519 != 0u && config.edTargetsAny != 0u) {
            uchar pubKeysED[MINIKEY_THREAD_STEPS * 32u];
            priv_ed25519_key_to_pub_batch_config(prvKeys, pubKeysED, privKeyIx, config);
            for (int pkField = 0; pkField < privKeyIx; ++pkField) {
                if (minikey_lens[pkField] == 0u) {
                    continue;
                }
                thread uchar* publ = pubKeysED + uint(pkField) * 32u;
                thread uchar* pkey = prvKeys + uint(pkField) * 32u;
                thread uchar* minikey = minikeys + uint(pkField) * MINIKEY_STAGE_STRIDE;
                const uchar minikey_len = minikey_lens[pkField];
                uint hash160[8] = { 0 };

                if (TFC_SOLANA && config.solana != 0u) {
                    minikey_process_check_bytes(isResult, buffResult, pkey, publ, 32u, publ, 32u,
                                                0x60u, current_round, minikey, minikey_len,
                                                config, filters, filter_storage, bloom_storage,
                                                xor_storage, xor_un_storage, xor_uc_storage,
                                                xor_hc_storage, found);
                }
                if (TFC_DOT && config.dot != 0u) {
                    adadot_emit_dot_ed25519_public(isResult, buffResult, nullptr, 0ul, pkey, publ,
                                                   0u, current_round, 0u, nullptr, 0u, 0ul, false,
                                                   0ul, 0u, false, config, filters, filter_storage,
                                                   bloom_storage, xor_storage, xor_un_storage,
                                                   xor_uc_storage, xor_hc_storage, found);
                    adadot_emit_dot_sr25519_seed(isResult, buffResult, nullptr, 0ul, pkey,
                                                 0u, current_round, 0u, nullptr, 0u, 0ul, false,
                                                 0ul, 0u, false, config, filters, filter_storage,
                                                 bloom_storage, xor_storage, xor_un_storage,
                                                 xor_uc_storage, xor_hc_storage, found);
                    adadot_emit_dot_substrate_from_seed(isResult, buffResult, nullptr, 0ul, pkey,
                                                        current_round, 0u, nullptr, 0u, 0ul, false,
                                                        0ul, 0u, false, config, substratePaths,
                                                        filters, filter_storage, bloom_storage,
                                                        xor_storage, xor_un_storage, xor_uc_storage,
                                                        xor_hc_storage, found);
                }
                if (TFC_TON && config.ton != 0u) {
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v3r1", 0x85u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v3r2", 0x86u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v4r2", 0x88u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v5r1", 0x89u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "hv3", 0x8cu,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                }
                if (TFC_TON_ALL && config.tonAll != 0u) {
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v1r1", 0x80u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v1r2", 0x81u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v1r3", 0x82u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v2r1", 0x83u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v2r2", 0x84u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v3r1", 0x85u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v3r2", 0x86u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v4r1", 0x87u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v4r2", 0x88u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "v5r1", 0x89u,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "hv1", 0x8au,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "hv2", 0x8bu,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                    minikey_process_emit_ton(isResult, buffResult, pkey, publ, "hv3", 0x8cu,
                                             current_round, minikey, minikey_len, config, filters,
                                             filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
                }
                if (TFC_XRP_ED && config.xrp != 0u && xrp_type_enabled(config, 0x91u)) {
                    int keyLenSkip = 0;
                    _GetHash160ED(publ, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
                    minikey_process_check_words(isResult, buffResult, pkey, hash160, 32u, hash160,
                                                0x91u, current_round, minikey, minikey_len,
                                                config, filters, filter_storage, bloom_storage,
                                                xor_storage, xor_un_storage, xor_uc_storage,
                                                xor_hc_storage, found);
                }
                if (TFC_APTOS_ED && config.aptos != 0u) {
                    if (aptos_type_enabled(config, 0x20u)) {
                        uchar buff[33] = { 0 };
                        priv_copy_thread_uchar(buff, publ, 32u);
                        uchar hash_addr[32];
                        sha3_256(reinterpret_cast<thread char*>(buff), 33, hash_addr);
                        minikey_process_check_bytes(isResult, buffResult, pkey, hash_addr, 32u,
                                                    hash_addr, 32u, 0x20u, current_round, minikey,
                                                    minikey_len, config, filters, filter_storage,
                                                    bloom_storage, xor_storage, xor_un_storage,
                                                    xor_uc_storage, xor_hc_storage, found);
                    }
                    if (aptos_type_enabled(config, 0x21u)) {
                        uchar buff2[34] = { 0 };
                        priv_copy_thread_uchar(buff2 + 1, publ, 32u);
                        buff2[33] = 0x02u;
                        uchar hash_addr2[32];
                        sha3_256(reinterpret_cast<thread char*>(buff2), 34, hash_addr2);
                        minikey_process_check_bytes(isResult, buffResult, pkey, hash_addr2, 32u,
                                                    hash_addr2, 32u, 0x21u, current_round, minikey,
                                                    minikey_len, config, filters, filter_storage,
                                                    bloom_storage, xor_storage, xor_un_storage,
                                                    xor_uc_storage, xor_hc_storage, found);
                    }
                }
                if (TFC_SUI_ED && config.sui != 0u && sui_type_enabled(config, 0x71u)) {
                    uchar buff[33] = { 0 };
                    priv_copy_thread_uchar(buff + 1, publ, 32u);
                    uchar hash_addr[32];
                    Blake2b_256(buff, 33u, hash_addr);
                    minikey_process_check_bytes(isResult, buffResult, pkey, hash_addr, 32u,
                                                hash_addr, 32u, 0x71u, current_round, minikey,
                                                minikey_len, config, filters, filter_storage,
                                                bloom_storage, xor_storage, xor_un_storage,
                                                xor_uc_storage, xor_hc_storage, found);
                }
                if (TFC_IOTA_ED && config.iota != 0u && iota_type_enabled(config, 0x51u)) {
                    uchar hash_addr[32];
                    Blake2b_256(publ, 32u, hash_addr);
                    minikey_process_check_bytes(isResult, buffResult, pkey, hash_addr, 32u,
                                                hash_addr, 32u, 0x51u, current_round, minikey,
                                                minikey_len, config, filters, filter_storage,
                                                bloom_storage, xor_storage, xor_un_storage,
                                                xor_uc_storage, xor_hc_storage, found);
                }
                if (TFC_ADA && config.ada != 0u) {
                    const thread uchar* next_key = (pkField + 1 < privKeyIx) ? (prvKeys + (uint(pkField) + 1u) * 32u) : nullptr;
                    adadot_emit_ada_direct_keyset(isResult, buffResult, nullptr, 0ul, pkey, next_key,
                                                  0u, current_round, 0u, nullptr, 0u, 0ul, false,
                                                  0ul, 0u, false, false, config, filters,
                                                  filter_storage, bloom_storage, xor_storage,
                                                  xor_un_storage, xor_uc_storage, xor_hc_storage, found);
                }
                if (TFC_ICP_ED && config.icp != 0u && icp_type_enabled(config, 0x52u)) {
                    uchar principal[29] = { 0 };
                    icp_principal_from_ed25519(publ, principal);
                    uchar hash_addr[32];
                    icp_account_identifier(principal, nullptr, hash_addr);
                    minikey_process_check_bytes(isResult, buffResult, pkey, hash_addr, 32u,
                                                hash_addr, 32u, 0x52u, current_round, minikey,
                                                minikey_len, config, filters, filter_storage,
                                                bloom_storage, xor_storage, xor_un_storage,
                                                xor_uc_storage, xor_hc_storage, found);
                }
                if (TFC_XTZ_ED && config.xtz != 0u && xtz_type_enabled(config, 0x93u)) {
                    uchar hash_addr[20];
                    Blake2b_160(publ, 32u, hash_addr);
                    minikey_process_check_bytes(isResult, buffResult, pkey, hash_addr, 20u,
                                                hash_addr, 20u, 0x93u, current_round, minikey,
                                                minikey_len, config, filters, filter_storage,
                                                bloom_storage, xor_storage, xor_un_storage,
                                                xor_uc_storage, xor_hc_storage, found);
                }
            }
        }

        if (r < (2ul * round)) {
            bump_all_keys(prvKeys, privKeyIx, 1ul, true, nullptr);
        }
    }
}
