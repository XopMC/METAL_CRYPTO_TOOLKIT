#define METAL_CRYPTO_NO_FUNCTION_CONSTANTS 1
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

kernel void workerPRIV_seq_128_edonly(device bool* isResult [[buffer(0)]],
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
    (void)precPtr;
    (void)precPitch;
    (void)walkState;

    FoundBuffers found;
    worker_priv_seq128_found(isResult, buffResult, foundStrings, foundPrvKeys, foundHash160,
                             foundLen, foundIter, foundType, foundDerivations, foundDerivations2,
                             foundPass, foundPassSize, foundRound, foundSeed, resultsCount,
                             config, found);

    const ulong tIx = ulong(tid);
    const ulong starter = ulong(thread_steps_pub) * tIx;

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
