#include "WorkerPrivCommon.metalh"

kernel void workerPRIV_seq(device bool* isResult [[buffer(0)]],
                           device bool* buffResult [[buffer(1)]],
                           constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                           constant ulong& precPitch [[buffer(3)]],
                           constant int& mode [[buffer(4)]],
                           const device uchar* start_point [[buffer(5)]],
                           device RuntimeConfig& config [[buffer(6)]],
                           device XorFilterState& filters [[buffer(7)]],
                           device FilterStorageState& filter_storage [[buffer(8)]],
                           const device uchar* bloom_storage [[buffer(9)]],
                           const device uchar* xor_storage [[buffer(10)]],
                           const device uchar* xor_un_storage [[buffer(11)]],
                           const device uchar* xor_uc_storage [[buffer(12)]],
                           const device uchar* xor_hc_storage [[buffer(13)]],
                           device char* foundStrings [[buffer(14)]],
                           device uchar* foundPrvKeys [[buffer(15)]],
                           device uint* foundHash160 [[buffer(16)]],
                           device uint* foundLen [[buffer(17)]],
                           device uint* foundIter [[buffer(18)]],
                           device uchar* foundType [[buffer(19)]],
                           device uint* foundDerivations [[buffer(20)]],
                           device uint* foundDerivations2 [[buffer(21)]],
                           device char* foundPass [[buffer(22)]],
                           device ushort* foundPassSize [[buffer(23)]],
                           device long* foundRound [[buffer(24)]],
                           device ulong* foundSeed [[buffer(25)]],
                           device atomic_uint* resultsCount [[buffer(26)]],
                           const device SubstratePathDevice* substratePaths [[buffer(27)]],
                           uint tid [[thread_position_in_grid]]) {
    if (start_point == nullptr) {
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

    const ulong tIx = ulong(tid);
    uchar pubKeys[PRIV_THREAD_STEPS * 65u];
    uchar prvKeys[PRIV_THREAD_STEPS * 32u];
    uchar pubKeysED[PRIV_THREAD_STEPS * 32u];
    uint hash160[8];

    priv_build_seq_keys(prvKeys, start_point, mode, config.seqStep, tIx);

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

    if (secp256_dev) {
        secp256k1_ec_pubkey_create_serialized_batch_myunsafe(pubKeys,
                                                             prvKeys,
                                                             int(PRIV_THREAD_STEPS),
                                                             precPtr,
                                                             size_t(precPitch));
        uchar tap_hash[32u * PRIV_THREAD_STEPS];
        if (taproot) {
            TweakTaproot_batch(tap_hash, pubKeys, int(PRIV_THREAD_STEPS), precPtr, size_t(precPitch));
        }

        for (uint pkField = 0u; pkField < PRIV_THREAD_STEPS; ++pkField) {
            thread uchar* private_key = prvKeys + pkField * 32u;
            thread uchar* pubkey = pubKeys + pkField * 65u;
            int keyLenSkip = int(65u * pkField);

            if (uncompressed) {
                _GetHash160(pubKeys, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
                priv_check_and_store_words(isResult, buffResult, private_key, hash160, 32u, hash160,
                                           0x01u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (compressed) {
                keyLenSkip = int(65u * pkField);
                _GetHash160Comp(pubKeys, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
                priv_check_and_store_words(isResult, buffResult, private_key, hash160, 32u, hash160,
                                           0x02u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (segwit) {
                keyLenSkip = int(65u * pkField);
                if (!compressed) {
                    _GetHash160Comp(pubKeys, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
                }
                _GetHash160P2SHCompFromHash(hash160, hash160);
                priv_check_and_store_words(isResult, buffResult, private_key, hash160, 32u, hash160,
                                           0x03u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (p2wsh) {
                priv_emit_p2wsh_from_pubkey65(isResult, buffResult, private_key, pubkey, config,
                                              filters, filter_storage, bloom_storage, xor_storage,
                                              xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (ethereum) {
                uchar keccak_hash[32];
                keccak(reinterpret_cast<thread char*>(pubkey + 1), 64, keccak_hash, 32);
                for (uint h = 12u, i = 0u; i < 5u; ++i) {
                    hash160[i] = uint(keccak_hash[h]) |
                                 ((uint(keccak_hash[h + 1u]) << 8u) & 0x0000ff00u) |
                                 ((uint(keccak_hash[h + 2u]) << 16u) & 0x00ff0000u) |
                                 ((uint(keccak_hash[h + 3u]) << 24u) & 0xff000000u);
                    h += 4u;
                }
                priv_check_and_store_words(isResult, buffResult, private_key, hash160, 32u, hash160,
                                           0x06u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (taproot) {
                thread uchar* taproot_hash = tap_hash + pkField * 32u;
                _GetRMD160(reinterpret_cast<thread uint*>(taproot_hash), hash160);
                priv_check_and_store_words(isResult, buffResult, private_key, taproot_hash, 32u, hash160,
                                           0x04u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (xpoint) {
                uint xpoint_hash[8] = { 0 };
                thread uchar* xbytes = reinterpret_cast<thread uchar*>(xpoint_hash);
                priv_copy_thread_uchar(xbytes, pubkey + 1, 32u);
                priv_check_and_store_words(isResult, buffResult, private_key, xpoint_hash, 32u, xpoint_hash,
                                           0x05u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (xrp && xrp_type_enabled(config, 0x90u)) {
                keyLenSkip = int(65u * pkField);
                _GetHash160Comp(pubKeys, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
                priv_check_and_store_words(isResult, buffResult, private_key, hash160, 32u, hash160,
                                           0x90u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (sui && sui_type_enabled(config, 0x70u)) {
                uchar buff[34];
                buff[0] = 0x01u;
                buff[1] = 0x02u + (pubkey[64] & 1u);
                priv_copy_thread_uchar(buff + 2, pubkey + 1, 32u);
                uchar hash_addr[32];
                Blake2b_256(buff, 34u, hash_addr);
                priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 32u, hash_addr, 32u,
                                           0x70u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (iota && iota_type_enabled(config, 0x50u)) {
                uchar buff[34];
                buff[0] = 0x01u;
                buff[1] = 0x02u + (pubkey[64] & 1u);
                priv_copy_thread_uchar(buff + 2, pubkey + 1, 32u);
                uchar hash_addr[32];
                Blake2b_256(buff, 34u, hash_addr);
                priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 32u, hash_addr, 32u,
                                           0x50u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (aptos && aptos_type_enabled(config, 0x22u)) {
                uchar buff[35] = { 0 };
                buff[0] = 0x01u;
                buff[1] = 0x02u + (pubkey[64] & 1u);
                priv_copy_thread_uchar(buff + 2, pubkey + 1, 32u);
                buff[34] = 0x02u;
                uchar hash_addr[32];
                sha3_256(reinterpret_cast<thread char*>(buff), 35, hash_addr);
                priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 32u, hash_addr, 32u,
                                           0x22u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (icp && icp_type_enabled(config, 0x53u)) {
                uchar principal[29] = { 0 };
                icp_principal_from_secp256k1(pubkey, principal);
                uchar hash_addr[32];
                icp_account_identifier(principal, nullptr, hash_addr);
                priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 32u, hash_addr, 32u,
                                           0x53u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (fil) {
                if (fil_type_enabled(config, 0x41u)) {
                    uchar hash_addr[20];
                    Blake2b_160(pubkey, 65u, hash_addr);
                    priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 20u, hash_addr, 20u,
                                               0x41u, config, filters, filter_storage, bloom_storage,
                                               xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
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
                    priv_check_and_store_words(isResult, buffResult, private_key, hash160, 20u, hash160,
                                               0x42u, config, filters, filter_storage, bloom_storage,
                                               xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
                }
            }
            if (xtz && xtz_type_enabled(config, 0x92u)) {
                uchar buff[33] = { 0 };
                buff[0] = 0x02u + (pubKeys[64] & 1u);
                priv_copy_thread_uchar(buff + 1, pubkey + 1, 32u);
                uchar hash_addr[20];
                Blake2b_160(buff, 33u, hash_addr);
                priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 20u, hash_addr, 20u,
                                           0x92u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
        }
    }

    if (ed25519_dev) {
        if (ed_common_pub_needed) {
            priv_ed25519_key_to_pub_batch_config(prvKeys, pubKeysED, int(PRIV_THREAD_STEPS), config);
        }

        for (uint pkField = 0u; pkField < PRIV_THREAD_STEPS; ++pkField) {
            thread uchar* publ = ed_common_pub_needed ? (pubKeysED + pkField * 32u) : nullptr;
            thread uchar* pkey = prvKeys + pkField * 32u;
            const thread uchar* next_key = (pkField < (PRIV_THREAD_STEPS - 1u)) ? (prvKeys + (pkField + 1u) * 32u) : nullptr;

            if (dot) {
                if (dot_type_enabled(config, 0x30u)) {
                    adadot_emit_dot_ed25519_public(isResult, buffResult, nullptr, 0ul, pkey, publ,
                                                   0u, 0l, 0u, nullptr, 0u, 0ul, false, 0ul, 0u, false,
                                                   config, filters, filter_storage, bloom_storage, xor_storage,
                                                   xor_un_storage, xor_uc_storage, xor_hc_storage, found);
                }
                if (dot_type_enabled(config, 0x31u)) {
                    adadot_emit_dot_sr25519_seed(isResult, buffResult, nullptr, 0ul, pkey,
                                                 0u, 0l, 0u, nullptr, 0u, 0ul, false, 0ul, 0u, false,
                                                 config, filters, filter_storage, bloom_storage, xor_storage,
                                                 xor_un_storage, xor_uc_storage, xor_hc_storage, found);
                }
                if (substratePaths != nullptr &&
                    config.substratePathCount > 0u &&
                    (dot_type_enabled(config, 0x30u) || dot_type_enabled(config, 0x31u))) {
                    adadot_emit_dot_substrate_from_seed(isResult, buffResult, nullptr, 0ul, pkey,
                                                        0l, 0u, nullptr, 0u, 0ul, false, 0ul, 0u, false,
                                                        config, substratePaths, filters, filter_storage, bloom_storage,
                                                        xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
                }
            }
            if (ada) {
                adadot_emit_ada_direct_keyset(isResult, buffResult, nullptr, 0ul, pkey, next_key,
                                              0u, 0l, 0u, nullptr, 0u, 0ul, false, 0ul, 0u, false, false,
                                              config, filters, filter_storage, bloom_storage, xor_storage,
                                              xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (solana) {
                priv_check_and_store_bytes(isResult, buffResult, pkey, publ, 32u, publ, 32u,
                                           0x60u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (ton) {
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v3r1", 0x85u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v3r2", 0x86u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v4r2", 0x88u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v5r1", 0x89u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "hv3", 0x8cu, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
            }
            if (ton_all) {
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v1r1", 0x80u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v1r2", 0x81u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v1r3", 0x82u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v2r1", 0x83u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v2r2", 0x84u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v3r1", 0x85u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v3r2", 0x86u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v4r1", 0x87u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v4r2", 0x88u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "v5r1", 0x89u, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "hv1", 0x8au, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "hv2", 0x8bu, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
                priv_emit_ton_type(isResult, buffResult, pkey, publ, "hv3", 0x8cu, config, filters,
                                   filter_storage, bloom_storage, xor_storage, xor_un_storage,
                                   xor_uc_storage, xor_hc_storage, found);
            }
            if (xrp && xrp_type_enabled(config, 0x91u)) {
                int keyLenSkip = 0;
                _GetHash160ED(publ, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
                priv_check_and_store_words(isResult, buffResult, pkey, hash160, 32u, hash160,
                                           0x91u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (aptos) {
                if (aptos_type_enabled(config, 0x20u)) {
                    uchar buff[33] = { 0 };
                    priv_copy_thread_uchar(buff, publ, 32u);
                    uchar hash_addr[32];
                    sha3_256(reinterpret_cast<thread char*>(buff), 33, hash_addr);
                    priv_check_and_store_bytes(isResult, buffResult, pkey, hash_addr, 32u, hash_addr, 32u,
                                               0x20u, config, filters, filter_storage, bloom_storage,
                                               xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
                }
                if (aptos_type_enabled(config, 0x21u)) {
                    uchar buff2[34] = { 0 };
                    priv_copy_thread_uchar(buff2 + 1, publ, 32u);
                    buff2[33] = 0x02u;
                    uchar hash_addr2[32];
                    sha3_256(reinterpret_cast<thread char*>(buff2), 34, hash_addr2);
                    priv_check_and_store_bytes(isResult, buffResult, pkey, hash_addr2, 32u, hash_addr2, 32u,
                                               0x21u, config, filters, filter_storage, bloom_storage,
                                               xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
                }
            }
            if (sui && sui_type_enabled(config, 0x71u)) {
                uchar buff[33] = { 0 };
                priv_copy_thread_uchar(buff + 1, publ, 32u);
                uchar hash_addr[32];
                Blake2b_256(buff, 33u, hash_addr);
                priv_check_and_store_bytes(isResult, buffResult, pkey, hash_addr, 32u, hash_addr, 32u,
                                           0x71u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (iota && iota_type_enabled(config, 0x51u)) {
                uchar hash_addr[32];
                Blake2b_256(publ, 32u, hash_addr);
                priv_check_and_store_bytes(isResult, buffResult, pkey, hash_addr, 32u, hash_addr, 32u,
                                           0x51u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (icp && icp_type_enabled(config, 0x52u)) {
                uchar principal[29] = { 0 };
                icp_principal_from_ed25519(publ, principal);
                uchar hash_addr[32];
                icp_account_identifier(principal, nullptr, hash_addr);
                priv_check_and_store_bytes(isResult, buffResult, pkey, hash_addr, 32u, hash_addr, 32u,
                                           0x52u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
            if (xtz && xtz_type_enabled(config, 0x93u)) {
                uchar hash_addr[20];
                Blake2b_160(publ, 32u, hash_addr);
                priv_check_and_store_bytes(isResult, buffResult, pkey, hash_addr, 20u, hash_addr, 20u,
                                           0x93u, config, filters, filter_storage, bloom_storage,
                                           xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
            }
        }
    }
}
