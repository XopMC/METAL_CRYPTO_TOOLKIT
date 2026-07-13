#include "WorkerPrivCommon.metalh"
#include "WorkerPRIVSeqNewCommon.metalh"

static inline void worker_priv_seq128_found(device bool* isResult,
                                            device bool* buffResult,
                                            device char* foundStrings,
                                            device uchar* foundPrvKeys,
                                            device uint* foundHash160,
                                            device uint* foundLen,
                                            device uint* foundIter,
                                            device uchar* foundType,
                                            device uint* foundDerivations,
                                            device uint* foundDerivations2,
                                            device char* foundPass,
                                            device ushort* foundPassSize,
                                            device long* foundRound,
                                            device ulong* foundSeed,
                                            device atomic_uint* resultsCount,
                                            device RuntimeConfig& config,
                                            thread FoundBuffers& found) {
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
    (void)isResult;
    (void)buffResult;
}

static inline void worker_priv_seq128_pubkey_from_walk(thread uchar pubkey65[65],
                                                       const device SecpWalkState& walkState,
                                                       ulong idx) {
    secp256k1_gej point_j;
    secp256k1_ge point;
    size_t out_len = 65;
    worker_priv_seq_walk_get_start_gej(&point_j, walkState, idx);
    secp256k1_ge_set_gej(&point, &point_j);
    secp256k1_eckey_pubkey_serialize(&point, pubkey65, &out_len, false);
}

static inline uint worker_priv_seq128_walk_pkfield(uint order) {
    if (order == 0u) {
        return VS_GRP_HALF_METAL;
    }
    if (order == (VS_GRP_SIZE_METAL - 1u)) {
        return 0u;
    }
    const uint offset = (order + 1u) >> 1u;
    return ((order & 1u) != 0u) ? (VS_GRP_HALF_METAL + offset)
                                : (VS_GRP_HALF_METAL - offset);
}

static inline void worker_priv_seq128_emit_secp(device bool* isResult,
                                                device bool* buffResult,
                                                const thread uchar* private_key,
                                                thread uchar pubkey65[65],
                                                constant secp256k1_ge_storage* precPtr,
                                                ulong precPitch,
                                                device RuntimeConfig& config,
                                                device XorFilterState& filters,
                                                device FilterStorageState& filter_storage,
                                                const device uchar* bloom_storage,
                                                const device uchar* xor_storage,
                                                const device uchar* xor_un_storage,
                                                const device uchar* xor_uc_storage,
                                                const device uchar* xor_hc_storage,
                                                FoundBuffers found) {
    uint hash160[8];
    int keyLenSkip = 0;

    if (config.uncompressed != 0u) {
        keyLenSkip = 0;
        _GetHash160(pubkey65, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
        priv_check_and_store_words(isResult, buffResult, private_key, hash160, 32u, hash160,
                                   0x01u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.compressed != 0u) {
        keyLenSkip = 0;
        _GetHash160Comp(pubkey65, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
        priv_check_and_store_words(isResult, buffResult, private_key, hash160, 32u, hash160,
                                   0x02u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.segwit != 0u) {
        keyLenSkip = 0;
        if (config.compressed == 0u) {
            _GetHash160Comp(pubkey65, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
        }
        _GetHash160P2SHCompFromHash(hash160, hash160);
        priv_check_and_store_words(isResult, buffResult, private_key, hash160, 32u, hash160,
                                   0x03u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.p2wsh != 0u) {
        priv_emit_p2wsh_from_pubkey65(isResult, buffResult, private_key, pubkey65, config,
                                      filters, filter_storage, bloom_storage, xor_storage,
                                      xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.ethereum != 0u) {
        uchar keccak_hash[32];
        keccak(reinterpret_cast<thread char*>(pubkey65 + 1), 64, keccak_hash, 32);
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
    if (config.taproot != 0u) {
        uchar taproot_hash[32];
        TweakTaproot(taproot_hash, pubkey65, precPtr, size_t(precPitch));
        _GetRMD160(reinterpret_cast<thread uint*>(taproot_hash), hash160);
        priv_check_and_store_words(isResult, buffResult, private_key, taproot_hash, 32u, hash160,
                                   0x04u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.xpoint != 0u) {
        uint xpoint_hash[8] = { 0 };
        thread uchar* xbytes = reinterpret_cast<thread uchar*>(xpoint_hash);
        priv_copy_thread_uchar(xbytes, pubkey65 + 1, 32u);
        priv_check_and_store_words(isResult, buffResult, private_key, xpoint_hash, 32u, xpoint_hash,
                                   0x05u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.xrp != 0u && xrp_type_enabled(config, 0x90u)) {
        keyLenSkip = 0;
        _GetHash160Comp(pubkey65, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
        priv_check_and_store_words(isResult, buffResult, private_key, hash160, 32u, hash160,
                                   0x90u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.sui != 0u && sui_type_enabled(config, 0x70u)) {
        uchar buff[34];
        buff[0] = 0x01u;
        buff[1] = 0x02u + (pubkey65[64] & 1u);
        priv_copy_thread_uchar(buff + 2, pubkey65 + 1, 32u);
        uchar hash_addr[32];
        Blake2b_256(buff, 34u, hash_addr);
        priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 32u, hash_addr, 32u,
                                   0x70u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.iota != 0u && iota_type_enabled(config, 0x50u)) {
        uchar buff[34];
        buff[0] = 0x01u;
        buff[1] = 0x02u + (pubkey65[64] & 1u);
        priv_copy_thread_uchar(buff + 2, pubkey65 + 1, 32u);
        uchar hash_addr[32];
        Blake2b_256(buff, 34u, hash_addr);
        priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 32u, hash_addr, 32u,
                                   0x50u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.aptos != 0u && aptos_type_enabled(config, 0x22u)) {
        uchar buff[35] = { 0 };
        buff[0] = 0x01u;
        buff[1] = 0x02u + (pubkey65[64] & 1u);
        priv_copy_thread_uchar(buff + 2, pubkey65 + 1, 32u);
        buff[34] = 0x02u;
        uchar hash_addr[32];
        sha3_256(reinterpret_cast<thread char*>(buff), 35, hash_addr);
        priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 32u, hash_addr, 32u,
                                   0x22u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.icp != 0u && icp_type_enabled(config, 0x53u)) {
        uchar principal[29] = { 0 };
        icp_principal_from_secp256k1(pubkey65, principal);
        uchar hash_addr[32];
        icp_account_identifier(principal, nullptr, hash_addr);
        priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 32u, hash_addr, 32u,
                                   0x53u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.fil != 0u) {
        if (fil_type_enabled(config, 0x41u)) {
            uchar hash_addr[20];
            Blake2b_160(pubkey65, 65u, hash_addr);
            priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 20u, hash_addr, 20u,
                                       0x41u, config, filters, filter_storage, bloom_storage,
                                       xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
        }
        if (fil_type_enabled(config, 0x42u)) {
            uchar keccak_hash[32];
            keccak(reinterpret_cast<thread char*>(pubkey65 + 1), 64, keccak_hash, 32);
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
    if (config.xtz != 0u && xtz_type_enabled(config, 0x92u)) {
        uchar buff[33] = { 0 };
        buff[0] = 0x02u + (pubkey65[64] & 1u);
        priv_copy_thread_uchar(buff + 1, pubkey65 + 1, 32u);
        uchar hash_addr[20];
        Blake2b_160(buff, 33u, hash_addr);
        priv_check_and_store_bytes(isResult, buffResult, private_key, hash_addr, 20u, hash_addr, 20u,
                                   0x92u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
}

static inline void worker_priv_seq128_emit_ed(device bool* isResult,
                                              device bool* buffResult,
                                              const thread uchar* pkey,
                                              const thread uchar* next_key,
                                              thread uchar publ[32],
                                              const device SubstratePathDevice* substratePaths,
                                              device RuntimeConfig& config,
                                              device XorFilterState& filters,
                                              device FilterStorageState& filter_storage,
                                              const device uchar* bloom_storage,
                                              const device uchar* xor_storage,
                                              const device uchar* xor_un_storage,
                                              const device uchar* xor_uc_storage,
                                              const device uchar* xor_hc_storage,
                                              FoundBuffers found) {
    uint hash160[8];

    if (config.dot != 0u) {
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
    if (config.ada != 0u) {
        adadot_emit_ada_direct_keyset(isResult, buffResult, nullptr, 0ul, pkey, next_key,
                                      0u, 0l, 0u, nullptr, 0u, 0ul, false, 0ul, 0u, false, false,
                                      config, filters, filter_storage, bloom_storage, xor_storage,
                                      xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.solana != 0u) {
        priv_check_and_store_bytes(isResult, buffResult, pkey, publ, 32u, publ, 32u,
                                   0x60u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.ton != 0u) {
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
    if (config.tonAll != 0u) {
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
    if (config.xrp != 0u && xrp_type_enabled(config, 0x91u)) {
        int keyLenSkip = 0;
        _GetHash160ED(publ, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
        priv_check_and_store_words(isResult, buffResult, pkey, hash160, 32u, hash160,
                                   0x91u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.aptos != 0u) {
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
    if (config.sui != 0u && sui_type_enabled(config, 0x71u)) {
        uchar buff[33] = { 0 };
        priv_copy_thread_uchar(buff + 1, publ, 32u);
        uchar hash_addr[32];
        Blake2b_256(buff, 33u, hash_addr);
        priv_check_and_store_bytes(isResult, buffResult, pkey, hash_addr, 32u, hash_addr, 32u,
                                   0x71u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.iota != 0u && iota_type_enabled(config, 0x51u)) {
        uchar hash_addr[32];
        Blake2b_256(publ, 32u, hash_addr);
        priv_check_and_store_bytes(isResult, buffResult, pkey, hash_addr, 32u, hash_addr, 32u,
                                   0x51u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.icp != 0u && icp_type_enabled(config, 0x52u)) {
        uchar principal[29] = { 0 };
        icp_principal_from_ed25519(publ, principal);
        uchar hash_addr[32];
        icp_account_identifier(principal, nullptr, hash_addr);
        priv_check_and_store_bytes(isResult, buffResult, pkey, hash_addr, 32u, hash_addr, 32u,
                                   0x52u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (config.xtz != 0u && xtz_type_enabled(config, 0x93u)) {
        uchar hash_addr[20];
        Blake2b_160(publ, 32u, hash_addr);
        priv_check_and_store_bytes(isResult, buffResult, pkey, hash_addr, 20u, hash_addr, 20u,
                                   0x93u, config, filters, filter_storage, bloom_storage,
                                   xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
}

kernel void workerPRIV_seq_128(device bool* isResult [[buffer(0)]],
                               device bool* buffResult [[buffer(1)]],
                               constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                               constant ulong& precPitch [[buffer(3)]],
                               constant int& mode [[buffer(4)]],
                               const device uchar* start_point [[buffer(5)]],
                               constant ulong& step [[buffer(6)]],
                               constant int& thread_steps_pub [[buffer(7)]],
                               device RuntimeConfig& config [[buffer(8)]],
                               device XorFilterState& filters [[buffer(9)]],
                               device FilterStorageState& filter_storage [[buffer(10)]],
                               const device uchar* bloom_storage [[buffer(11)]],
                               const device uchar* xor_storage [[buffer(12)]],
                               const device uchar* xor_un_storage [[buffer(13)]],
                               const device uchar* xor_uc_storage [[buffer(14)]],
                               const device uchar* xor_hc_storage [[buffer(15)]],
                               device char* foundStrings [[buffer(16)]],
                               device uchar* foundPrvKeys [[buffer(17)]],
                               device uint* foundHash160 [[buffer(18)]],
                               device uint* foundLen [[buffer(19)]],
                               device uint* foundIter [[buffer(20)]],
                               device uchar* foundType [[buffer(21)]],
                               device uint* foundDerivations [[buffer(22)]],
                               device uint* foundDerivations2 [[buffer(23)]],
                               device char* foundPass [[buffer(24)]],
                               device ushort* foundPassSize [[buffer(25)]],
                               device long* foundRound [[buffer(26)]],
                               device ulong* foundSeed [[buffer(27)]],
                               device atomic_uint* resultsCount [[buffer(28)]],
                               const device SubstratePathDevice* substratePaths [[buffer(29)]],
                               device SecpWalkState& walkState [[buffer(30)]],
                               uint tid [[thread_position_in_grid]]) {
    if (start_point == nullptr || thread_steps_pub <= 0) {
        return;
    }

    FoundBuffers found;
    worker_priv_seq128_found(isResult, buffResult, foundStrings, foundPrvKeys, foundHash160,
                             foundLen, foundIter, foundType, foundDerivations, foundDerivations2,
                             foundPass, foundPassSize, foundRound, foundSeed, resultsCount,
                             config, found);

    const ulong tIx = ulong(tid);
    const ulong starter = ulong(thread_steps_pub) * tIx;
    const bool use_vanity = (thread_steps_pub % int(VS_GRP_SIZE_METAL)) == 0;

    if (config.secp256 != 0u && use_vanity) {
        const int numBatches = thread_steps_pub / int(VS_GRP_SIZE_METAL);
        for (int batch = 0; batch < numBatches; ++batch) {
            const ulong batchBase = starter + ulong(batch) * ulong(VS_GRP_SIZE_METAL);
            for (uint order = 0u; order < VS_GRP_SIZE_METAL; ++order) {
                const uint pkField = worker_priv_seq128_walk_pkfield(order);
                const ulong idx = (mode == 1)
                    ? (batchBase + ulong(pkField))
                    : (batchBase + ulong(VS_GRP_SIZE_METAL) - ulong(pkField));
                uchar private_key[32];
                uchar pubkey65[65];
                priv_build_seq128_key(private_key, start_point, mode, idx, step);
                worker_priv_seq128_pubkey_from_walk(pubkey65, walkState, idx);
                worker_priv_seq128_emit_secp(isResult, buffResult, private_key, pubkey65,
                                             precPtr, precPitch, config, filters, filter_storage,
                                             bloom_storage, xor_storage, xor_un_storage,
                                             xor_uc_storage, xor_hc_storage, found);
            }
        }
    }

    if (config.ed25519 != 0u) {
        const bool ed_common_pub_needed = priv_ed_common_pub_needed(
            config.solana != 0u,
            config.dot != 0u,
            config.ton != 0u,
            config.tonAll != 0u,
            config.xrp != 0u,
            config.aptos != 0u,
            config.sui != 0u,
            config.iota != 0u,
            config.icp != 0u,
            config.xtz != 0u,
            config);
        uchar priv_next[32];
        uchar pkey[32];
        uchar publ[32];
        for (int pkField = 0; pkField < thread_steps_pub; ++pkField) {
            const ulong idx = starter + ulong(pkField);
            priv_build_seq128_key(pkey, start_point, mode, idx, step);
            if (ed_common_pub_needed) {
                priv_ed25519_key_to_pub_batch_config(pkey, publ, 1, config);
            }
            const thread uchar* next_key = nullptr;
            if (pkField + 1 < thread_steps_pub) {
                priv_build_seq128_key(priv_next, start_point, mode, idx + 1ul, step);
                next_key = priv_next;
            }
            worker_priv_seq128_emit_ed(isResult, buffResult, pkey, next_key, publ, substratePaths,
                                       config, filters, filter_storage, bloom_storage,
                                       xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found);
        }
    }
}
