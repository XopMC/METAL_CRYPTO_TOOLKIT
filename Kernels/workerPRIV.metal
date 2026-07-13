#include "WorkerPrivCommon.metalh"
#include "PrngCommon.metalh"

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

constant int WORKER_PRIV_FC_MODE [[function_constant(35)]];

static constant uchar WORKER_PRIV_SECP_G65[65] = {
    0x04u,
    0x79u,0xbeu,0x66u,0x7eu,0xf9u,0xdcu,0xbbu,0xacu,0x55u,0xa0u,0x62u,0x95u,0xceu,0x87u,0x0bu,0x07u,
    0x02u,0x9bu,0xfcu,0xdbu,0x2du,0xceu,0x28u,0xd9u,0x59u,0xf2u,0x81u,0x5bu,0x16u,0xf8u,0x17u,0x98u,
    0x48u,0x3au,0xdau,0x77u,0x26u,0xa3u,0xc4u,0x65u,0x5du,0xa4u,0xfbu,0xfcu,0x0eu,0x11u,0x08u,0xa8u,
    0xfdu,0x17u,0xb4u,0x48u,0xa6u,0x85u,0x54u,0x19u,0x9cu,0x47u,0xd0u,0x8fu,0xfbu,0x10u,0xd4u,0xb8u
};

static inline void worker_priv_found(device char* foundStrings,
                                     device uchar* foundPrvKeys,
                                     device uint* foundHash160,
                                     device uint* foundLen,
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
    found.iter = nullptr;
    found.type = foundType;
    found.foundDerivations = foundDerivations;
    found.foundDerivations2 = foundDerivations2;
    found.pass = foundPass;
    found.passSize = foundPassSize;
    found.round = foundRound;
    found.seed = foundSeed;
    found.resultsCount = resultsCount;
    found.maxFounds = config.maxFounds;
}

static inline ulong worker_priv_line_cursor(const device uint* indexes, ulong starter) {
    return (starter == 0ul) ? 0ul : ulong(indexes[starter - 1ul]);
}

static inline ulong worker_priv_line_len(const device uint* indexes, ulong starter) {
    return (starter == 0ul)
        ? ulong(indexes[0])
        : ulong(indexes[starter] - indexes[starter - 1ul]);
}

static inline void worker_priv_read_line(thread uchar toHash[65],
                                         const device char* lines,
                                         ulong len,
                                         thread ulong& cursor) {
    for (uint i = 0u; i < 65u; ++i) {
        toHash[i] = 0u;
    }
    ulong ix = 0ul;
    for (; ix < len; ++ix) {
        toHash[ix] = uchar(lines[cursor]);
        if (ix + 1ul == 65ul) {
            break;
        }
        ++cursor;
    }
    if (ix < len && ix + 1ul == 65ul) {
        cursor += 0ul;
    } else {
        cursor += (ix < len) ? 1ul : 0ul;
    }
    const ulong pad = (len < 65ul) ? len : 64ul;
    toHash[pad] = 0x80u;
}

static inline void worker_priv_line_to_key(thread uchar key32[32],
                                           const thread uchar toHash[65],
                                           device RuntimeConfig& config) {
    if (config.isHex != 0u) {
        uchar tmp[65];
        for (uint i = 0u; i < 65u; ++i) {
            tmp[i] = toHash[i];
        }
        priv_unhex(tmp, 64u, key32, 32u);
    } else {
        priv_copy_thread_uchar(key32, toHash, 32u);
    }
}

static inline void worker_priv_pub_add_basepoint_inplace(thread uchar* pub65,
                                                         int sign,
                                                         constant secp256k1_ge_storage* precPtr) {
    secp256k1_ge B;
    secp256k1_ge_from_storage(&B, &precPtr[0]);
    if (sign < 0) {
        secp256k1_ge_neg(&B, &B);
    }

    secp256k1_ge A;
    if (pub65[0] == 0x04u) {
        secp256k1_fe x;
        secp256k1_fe y;
        secp256k1_fe_set_b32(&x, pub65 + 1);
        secp256k1_fe_set_b32(&y, pub65 + 33);
        A.x = x;
        A.y = y;
        A.infinity = 0;
    } else {
        A.infinity = 1;
    }

    secp256k1_gej J;
    if (A.infinity != 0) {
        secp256k1_gej_set_ge(&J, &B);
    } else {
        secp256k1_gej_set_ge(&J, &A);
        secp256k1_gej_add_ge_var(&J, &J, &B, nullptr);
    }

    secp256k1_ge R;
    secp256k1_ge_set_gej(&R, &J);
    pub65[0] = 0x04u;
    secp256k1_fe tx = R.x;
    secp256k1_fe ty = R.y;
    secp256k1_fe_normalize_var(&tx);
    secp256k1_fe_normalize_var(&ty);
    secp256k1_fe_get_b32(pub65 + 1, &tx);
    secp256k1_fe_get_b32(pub65 + 33, &ty);
}

static inline void worker_priv_pub_add_basepoint_batch(thread uchar* pubKeys,
                                                       int count,
                                                       int sign,
                                                       constant secp256k1_ge_storage* precPtr) {
    for (int i = 0; i < count; ++i) {
        worker_priv_pub_add_basepoint_inplace(pubKeys + uint(i) * 65u, sign, precPtr);
    }
}

static inline void worker_priv_emit_ton_type_round(device bool* isResult,
                                                   device bool* buffResult,
                                                   const thread uchar* private_key32,
                                                   const thread uchar* publ,
                                                   const constant char* ton_kind,
                                                   uchar type_value,
                                                   long current_round,
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
        pubkey_to_hash_ton(publ, ton_kind, hash_addr, config.tonTypeMask) &&
        priv_check_hash_bytes(config, filters, storage, bloom_storage, xor_storage, xor_un_storage,
                              xor_uc_storage, xor_hc_storage, hash_addr, 32u)) {
        priv_store_result_round(isResult, buffResult, private_key32, hash_addr, 32u,
                                type_value, current_round, found);
    }
}

static inline void worker_priv_emit_secp_round(device bool* isResult,
                                               device bool* buffResult,
                                               thread uchar* prvKeys,
                                               thread uchar* pubKeys,
                                               thread uchar* tap_hash,
                                               uint pkField,
                                               long current_round,
                                               bool compressed,
                                               bool uncompressed,
                                               bool segwit,
                                               bool p2wsh,
                                               bool taproot,
                                               bool ethereum,
                                               bool xpoint,
                                               bool xrp,
                                               bool sui,
                                               bool aptos,
                                               bool iota,
                                               bool icp,
                                               bool fil,
                                               bool xtz,
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
    uint compressed_hash160[8] = { 0 };
    thread uchar* private_key = prvKeys + pkField * 32u;
    thread uchar* pubkey = pubKeys + pkField * 65u;
    int keyLenSkip = int(65u * pkField);

    if (uncompressed) {
        _GetHash160(pubKeys, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
        priv_check_and_store_words_round(isResult, buffResult, private_key, hash160, 32u,
                                         hash160, 0x01u, current_round, config, filters,
                                         filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    const bool xrp_secp_enabled = xrp && xrp_type_enabled(config, 0x90u);
    const bool need_compressed_hash160 = compressed || segwit || xrp_secp_enabled;
    if (need_compressed_hash160) {
        keyLenSkip = int(65u * pkField);
        _GetHash160Comp(pubKeys, keyLenSkip,
                        reinterpret_cast<thread uchar*>(compressed_hash160));
    }
    if (compressed) {
        priv_check_and_store_words_round(isResult, buffResult, private_key,
                                         compressed_hash160, 32u, compressed_hash160, 0x02u,
                                         current_round, config, filters,
                                         filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (segwit) {
        for (uint i = 0u; i < 8u; ++i) {
            hash160[i] = compressed_hash160[i];
        }
        _GetHash160P2SHCompFromHash(hash160, hash160);
        priv_check_and_store_words_round(isResult, buffResult, private_key, hash160, 32u,
                                         hash160, 0x03u,
                                         current_round, config, filters,
                                         filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (p2wsh) {
        priv_emit_p2wsh_from_pubkey65_round(isResult, buffResult, private_key, pubkey,
                                            current_round, config, filters, filter_storage,
                                            bloom_storage, xor_storage, xor_un_storage,
                                            xor_uc_storage, xor_hc_storage, found);
    }
    if (taproot) {
        thread uchar* taproot_hash = tap_hash + pkField * 32u;
        _GetRMD160(reinterpret_cast<thread uint*>(taproot_hash), hash160);
        priv_check_and_store_words_round(isResult, buffResult, private_key, taproot_hash, 32u,
                                         hash160, 0x04u, current_round, config, filters,
                                         filter_storage, bloom_storage, xor_storage,
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
        priv_check_and_store_words_round(isResult, buffResult, private_key, hash160, 32u,
                                         hash160, 0x06u, current_round, config, filters,
                                         filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (xpoint) {
        uint xpoint_hash[8] = { 0 };
        thread uchar* xbytes = reinterpret_cast<thread uchar*>(xpoint_hash);
        priv_copy_thread_uchar(xbytes, pubkey + 1, 32u);
        priv_check_and_store_words_round(isResult, buffResult, private_key, xpoint_hash, 32u,
                                         xpoint_hash, 0x05u, current_round, config, filters,
                                         filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (xrp_secp_enabled) {
        priv_check_and_store_words_round(isResult, buffResult, private_key,
                                         compressed_hash160, 32u, compressed_hash160, 0x90u,
                                         current_round, config, filters,
                                         filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (sui && sui_type_enabled(config, 0x70u)) {
        uchar buff[34];
        buff[0] = 0x01u;
        buff[1] = 0x02u + (pubkey[64] & 1u);
        priv_copy_thread_uchar(buff + 2, pubkey + 1, 32u);
        uchar hash_addr[32];
        Blake2b_256(buff, 34u, hash_addr);
        priv_check_and_store_bytes_round(isResult, buffResult, private_key, hash_addr, 32u,
                                         hash_addr, 32u, 0x70u, current_round, config,
                                         filters, filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (aptos && aptos_type_enabled(config, 0x22u)) {
        uchar buff[35] = { 0 };
        buff[0] = 0x01u;
        buff[1] = 0x02u + (pubkey[64] & 1u);
        priv_copy_thread_uchar(buff + 2, pubkey + 1, 32u);
        buff[34] = 0x02u;
        uchar hash_addr[32];
        sha3_256(reinterpret_cast<thread char*>(buff), 35, hash_addr);
        priv_check_and_store_bytes_round(isResult, buffResult, private_key, hash_addr, 32u,
                                         hash_addr, 32u, 0x22u, current_round, config,
                                         filters, filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (iota && iota_type_enabled(config, 0x50u)) {
        uchar buff[34];
        buff[0] = 0x01u;
        buff[1] = 0x02u + (pubkey[64] & 1u);
        priv_copy_thread_uchar(buff + 2, pubkey + 1, 32u);
        uchar hash_addr[32];
        Blake2b_256(buff, 34u, hash_addr);
        priv_check_and_store_bytes_round(isResult, buffResult, private_key, hash_addr, 32u,
                                         hash_addr, 32u, 0x50u, current_round, config,
                                         filters, filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (icp && icp_type_enabled(config, 0x53u)) {
        uchar principal[29] = { 0 };
        icp_principal_from_secp256k1(pubkey, principal);
        uchar hash_addr[32];
        icp_account_identifier(principal, nullptr, hash_addr);
        priv_check_and_store_bytes_round(isResult, buffResult, private_key, hash_addr, 32u,
                                         hash_addr, 32u, 0x53u, current_round, config,
                                         filters, filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (fil) {
        if (fil_type_enabled(config, 0x41u)) {
            uchar hash_addr[20];
            Blake2b_160(pubkey, 65u, hash_addr);
            priv_check_and_store_bytes_round(isResult, buffResult, private_key, hash_addr, 20u,
                                             hash_addr, 20u, 0x41u, current_round, config,
                                             filters, filter_storage, bloom_storage, xor_storage,
                                             xor_un_storage, xor_uc_storage, xor_hc_storage, found);
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
            priv_check_and_store_words_round(isResult, buffResult, private_key, hash160, 20u,
                                             hash160, 0x42u, current_round, config, filters,
                                             filter_storage, bloom_storage, xor_storage,
                                             xor_un_storage, xor_uc_storage, xor_hc_storage, found);
        }
    }
    if (xtz && xtz_type_enabled(config, 0x92u)) {
        uchar buff[33] = { 0 };
        priv_copy_thread_uchar(buff + 1, pubkey + 1, 32u);
        buff[0] = 0x02u + (pubkey[64] & 1u);
        uchar hash_addr[20];
        Blake2b_160(buff, 33u, hash_addr);
        priv_check_and_store_bytes_round(isResult, buffResult, private_key, hash_addr, 20u,
                                         hash_addr, 20u, 0x92u, current_round, config,
                                         filters, filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
}

static inline void worker_priv_emit_ed_round(device bool* isResult,
                                             device bool* buffResult,
                                             const thread uchar* pkey,
                                             const thread uchar* next_key,
                                             const thread uchar* publ,
                                             long current_round,
                                             bool solana,
                                             bool dot,
                                             bool ton,
                                             bool ton_all,
                                             bool xrp,
                                             bool aptos,
                                             bool sui,
                                             bool iota,
                                             bool ada,
                                             bool icp,
                                             bool xtz,
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

    if (solana) {
        priv_check_and_store_bytes_round(isResult, buffResult, pkey, publ, 32u, publ, 32u,
                                         0x60u, current_round, config, filters, filter_storage,
                                         bloom_storage, xor_storage, xor_un_storage,
                                         xor_uc_storage, xor_hc_storage, found);
    }
    if (dot) {
        if (dot_type_enabled(config, 0x30u)) {
            adadot_emit_dot_ed25519_public(isResult, buffResult, nullptr, 0ul, pkey, publ,
                                           0u, current_round, 0u, nullptr, 0u, 0ul, false,
                                           0ul, 0u, false, config, filters, filter_storage,
                                           bloom_storage, xor_storage, xor_un_storage,
                                           xor_uc_storage, xor_hc_storage, found);
        }
        if (dot_type_enabled(config, 0x31u)) {
            adadot_emit_dot_sr25519_seed(isResult, buffResult, nullptr, 0ul, pkey,
                                         0u, current_round, 0u, nullptr, 0u, 0ul, false,
                                         0ul, 0u, false, config, filters, filter_storage,
                                         bloom_storage, xor_storage, xor_un_storage,
                                         xor_uc_storage, xor_hc_storage, found);
        }
        if (substratePaths != nullptr &&
            config.substratePathCount > 0u &&
            (dot_type_enabled(config, 0x30u) || dot_type_enabled(config, 0x31u))) {
            adadot_emit_dot_substrate_from_seed(isResult, buffResult, nullptr, 0ul, pkey,
                                                current_round, 0u, nullptr, 0u, 0ul, false,
                                                0ul, 0u, false, config, substratePaths, filters,
                                                filter_storage, bloom_storage, xor_storage,
                                                xor_un_storage, xor_uc_storage, xor_hc_storage, found);
        }
    }
    if (ton) {
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v3r1", 0x85u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v3r2", 0x86u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v4r2", 0x88u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v5r1", 0x89u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "hv3", 0x8cu,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
    }
    if (ton_all) {
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v1r1", 0x80u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v1r2", 0x81u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v1r3", 0x82u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v2r1", 0x83u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v2r2", 0x84u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v3r1", 0x85u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v3r2", 0x86u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v4r1", 0x87u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v4r2", 0x88u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "v5r1", 0x89u,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "hv1", 0x8au,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "hv2", 0x8bu,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
        worker_priv_emit_ton_type_round(isResult, buffResult, pkey, publ, "hv3", 0x8cu,
                                        current_round, config, filters, filter_storage,
                                        bloom_storage, xor_storage, xor_un_storage,
                                        xor_uc_storage, xor_hc_storage, found);
    }
    if (xrp && xrp_type_enabled(config, 0x91u)) {
        int keyLenSkip = 0;
        uchar publ_mut[32];
        priv_copy_thread_uchar(publ_mut, publ, 32u);
        _GetHash160ED(publ_mut, keyLenSkip, reinterpret_cast<thread uchar*>(hash160));
        priv_check_and_store_words_round(isResult, buffResult, pkey, hash160, 32u,
                                         hash160, 0x91u, current_round, config, filters,
                                         filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (aptos) {
        if (aptos_type_enabled(config, 0x20u)) {
            uchar buff[33] = { 0 };
            priv_copy_thread_uchar(buff, publ, 32u);
            uchar hash_addr[32];
            sha3_256(reinterpret_cast<thread char*>(buff), 33, hash_addr);
            priv_check_and_store_bytes_round(isResult, buffResult, pkey, hash_addr, 32u,
                                             hash_addr, 32u, 0x20u, current_round, config,
                                             filters, filter_storage, bloom_storage, xor_storage,
                                             xor_un_storage, xor_uc_storage, xor_hc_storage, found);
        }
        if (aptos_type_enabled(config, 0x21u)) {
            uchar buff2[34] = { 0 };
            priv_copy_thread_uchar(buff2 + 1, publ, 32u);
            buff2[33] = 0x02u;
            uchar hash_addr2[32];
            sha3_256(reinterpret_cast<thread char*>(buff2), 34, hash_addr2);
            priv_check_and_store_bytes_round(isResult, buffResult, pkey, hash_addr2, 32u,
                                             hash_addr2, 32u, 0x21u, current_round, config,
                                             filters, filter_storage, bloom_storage, xor_storage,
                                             xor_un_storage, xor_uc_storage, xor_hc_storage, found);
        }
    }
    if (sui && sui_type_enabled(config, 0x71u)) {
        uchar buff[33] = { 0 };
        priv_copy_thread_uchar(buff + 1, publ, 32u);
        uchar hash_addr[32];
        Blake2b_256(buff, 33u, hash_addr);
        priv_check_and_store_bytes_round(isResult, buffResult, pkey, hash_addr, 32u,
                                         hash_addr, 32u, 0x71u, current_round, config,
                                         filters, filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (iota && iota_type_enabled(config, 0x51u)) {
        uchar hash_addr[32];
        Blake2b_256(publ, 32u, hash_addr);
        priv_check_and_store_bytes_round(isResult, buffResult, pkey, hash_addr, 32u,
                                         hash_addr, 32u, 0x51u, current_round, config,
                                         filters, filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (ada) {
        adadot_emit_ada_direct_keyset(isResult, buffResult, nullptr, 0ul, pkey, next_key,
                                      0u, current_round, 0u, nullptr, 0u, 0ul, false, 0ul,
                                      0u, false, false, config, filters, filter_storage,
                                      bloom_storage, xor_storage, xor_un_storage,
                                      xor_uc_storage, xor_hc_storage, found);
    }
    if (icp && icp_type_enabled(config, 0x52u)) {
        uchar principal[29] = { 0 };
        icp_principal_from_ed25519(publ, principal);
        uchar hash_addr[32];
        icp_account_identifier(principal, nullptr, hash_addr);
        priv_check_and_store_bytes_round(isResult, buffResult, pkey, hash_addr, 32u,
                                         hash_addr, 32u, 0x52u, current_round, config,
                                         filters, filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
    if (xtz && xtz_type_enabled(config, 0x93u)) {
        uchar hash_addr[20];
        Blake2b_160(publ, 32u, hash_addr);
        priv_check_and_store_bytes_round(isResult, buffResult, pkey, hash_addr, 20u,
                                         hash_addr, 20u, 0x93u, current_round, config,
                                         filters, filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
}

static inline int worker_priv_prepare_keys(thread uchar prvKeys[PRIV_THREAD_STEPS * 32u],
                                           const device char* lines,
                                           const device uint* indexes,
                                           uint indexes_size,
                                           int true_priv,
                                           device RandomStateData& rngState,
                                           device RuntimeConfig& config,
                                           uint tid) {
    int privKeyIx = 0;

    if (true_priv == 0) {
        ulong starter = ulong(PRIV_THREAD_STEPS) * ulong(tid);
        ulong cursor = worker_priv_line_cursor(indexes, starter);
        while (privKeyIx < int(PRIV_THREAD_STEPS) && starter < ulong(indexes_size)) {
            const ulong len = worker_priv_line_len(indexes, starter);
            uchar toHash[65];
            uchar toHash2[32];
            worker_priv_read_line(toHash, lines, len, cursor);
            worker_priv_line_to_key(toHash2, toHash, config);
            priv_copy_thread_uchar(prvKeys + uint(privKeyIx) * 32u, toHash2, 32u);
            ++privKeyIx;
            ++starter;
        }
    } else if (true_priv == 1) {
        const ulong starter = ulong(tid);
        if (starter < ulong(indexes_size)) {
            ulong cursor = worker_priv_line_cursor(indexes, starter);
            const ulong len = worker_priv_line_len(indexes, starter);
            uchar toHash[65];
            uchar toHash2[32];
            worker_priv_read_line(toHash, lines, len, cursor);
            worker_priv_line_to_key(toHash2, toHash, config);
            for (uint i = 0u; i < 32u; ++i) {
                for (uint j = 0u; j < 32u - i; ++j) {
                    prvKeys[i * 32u + j] = toHash2[i + j];
                }
                for (uint j = 0u; j < i; ++j) {
                    prvKeys[i * 32u + (32u - i) + j] = toHash2[j];
                }
            }
            privKeyIx = 32;
        }
    } else if (true_priv == 2) {
        const ulong starter = ulong(tid);
        if (starter < ulong(indexes_size)) {
            ulong cursor = worker_priv_line_cursor(indexes, starter);
            const ulong len = worker_priv_line_len(indexes, starter);
            uchar toHash[65];
            uchar toHash2[32];
            worker_priv_read_line(toHash, lines, len, cursor);
            worker_priv_line_to_key(toHash2, toHash, config);
            priv_copy_thread_uchar(prvKeys, toHash2, 32u);
            privKeyIx = 1;
            uint randomNumbers[31];
            random32(rngState, randomNumbers, 31 * 4, tid);
            for (uint i = 0u; i < 31u; ++i) {
                thread uchar* dst = prvKeys + (uint(privKeyIx) + i) * 32u;
                priv_copy_thread_uchar(dst, toHash2, 32u);
                const uint randomBytePosition = randomNumbers[i] % 32u;
                const uchar randomByteValue = uchar(randomNumbers[i] & 0xffu);
                dst[randomBytePosition] = randomByteValue;
            }
            privKeyIx += 31;
        }
    } else if (true_priv == 3) {
        const ulong starter = ulong(tid);
        if (starter < ulong(indexes_size)) {
            ulong cursor = worker_priv_line_cursor(indexes, starter);
            const ulong len = worker_priv_line_len(indexes, starter);
            uchar toHash[65];
            uchar toHash2[32];
            uchar hash_prepared[32];
            worker_priv_read_line(toHash, lines, len, cursor);
            worker_priv_line_to_key(toHash2, toHash, config);
            priv_copy_thread_uchar(hash_prepared, toHash2, 32u);
            for (uint i = 0u; i < 32u; ++i) {
                hash_prepared[i] = uchar(hash_prepared[i] + 1u);
                priv_copy_thread_uchar(prvKeys + i * 32u, hash_prepared, 32u);
                hash_prepared[i] = uchar(hash_prepared[i] - 1u);
            }
            privKeyIx = 32;
        }
    }

    return privKeyIx;
}

kernel void workerPRIV(device bool* isResult [[buffer(0)]],
                       device bool* buffResult [[buffer(1)]],
                       const device char* lines [[buffer(2)]],
                       const device uint* indexes [[buffer(3)]],
                       constant uint& indexes_size [[buffer(4)]],
                       constant secp256k1_ge_storage* precPtr [[buffer(5)]],
                       constant ulong& precPitch [[buffer(6)]],
                       constant int& true_priv [[buffer(7)]],
                       constant ulong& round [[buffer(8)]],
                       device RandomStateData& rngState [[buffer(9)]],
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
                       device uint* foundDerivations2 [[buffer(24)]],
                       device char* foundPass [[buffer(25)]],
                       device ushort* foundPassSize [[buffer(26)]],
                       device long* foundRound [[buffer(27)]],
                       device ulong* foundSeed [[buffer(28)]],
                       device atomic_uint* resultsCount [[buffer(29)]],
                       const device SubstratePathDevice* substratePaths [[buffer(30)]],
                       uint tid [[thread_position_in_grid]]) {
    if (tid >= indexes_size) {
        return;
    }

    FoundBuffers found;
    worker_priv_found(foundStrings, foundPrvKeys, foundHash160, foundLen, foundType,
                      foundDerivations, foundDerivations2, foundPass, foundPassSize,
                      foundRound, foundSeed, resultsCount, config, found);

    uchar pubKeys[PRIV_THREAD_STEPS * 65u];
    uchar prvKeys[PRIV_THREAD_STEPS * 32u];
    uchar pubKeysED[PRIV_THREAD_STEPS * 32u];

    const int prepare_mode = is_function_constant_defined(WORKER_PRIV_FC_MODE)
        ? WORKER_PRIV_FC_MODE
        : true_priv;
    int privKeyIx = worker_priv_prepare_keys(prvKeys, lines, indexes, indexes_size,
                                             prepare_mode, rngState, config, tid);
    if (privKeyIx == 0) {
        return;
    }

    if (round > 0ul) {
        bump_all_keys(prvKeys, privKeyIx, round, false, nullptr);
    }

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
    const bool ton = TFC_TON && config.ton != 0u;
    const bool ton_all = TFC_TON_ALL && config.tonAll != 0u;
    const bool dot = TFC_DOT && config.dot != 0u;
    const bool aptos_ed = TFC_APTOS_ED && config.aptos != 0u;
    const bool sui_ed = TFC_SUI_ED && config.sui != 0u;
    const bool xrp_ed = TFC_XRP_ED && config.xrp != 0u;
    const bool iota_ed = TFC_IOTA_ED && config.iota != 0u;
    const bool ada = TFC_ADA && config.ada != 0u;
    const bool icp_ed = TFC_ICP_ED && config.icp != 0u;
    const bool xtz_ed = TFC_XTZ_ED && config.xtz != 0u;
    const bool ed_common_pub_needed = priv_ed_common_pub_needed(solana, dot, ton, ton_all,
                                                                xrp_ed, aptos_ed, sui_ed,
                                                                iota_ed, icp_ed, xtz_ed,
                                                                config);

    for (ulong i = 0ul; i <= 2ul * round; ++i) {
        const long current_round = long(i) - long(round);

        if (secp256_dev) {
            uchar tap_hash[32u * PRIV_THREAD_STEPS];
            if (i == 0ul) {
                secp256k1_ec_pubkey_create_serialized_batch_myunsafe(pubKeys,
                                                                     prvKeys,
                                                                     privKeyIx,
                                                                     precPtr,
                                                                     size_t(precPitch));
            }
            if (taproot) {
                TweakTaproot_batch(tap_hash, pubKeys, privKeyIx, precPtr, size_t(precPitch));
            }
            for (uint pkField = 0u; pkField < PRIV_THREAD_STEPS && pkField < uint(privKeyIx); ++pkField) {
                worker_priv_emit_secp_round(isResult, buffResult, prvKeys, pubKeys, tap_hash,
                                            pkField, current_round, compressed, uncompressed, segwit,
                                            p2wsh, taproot, ethereum, xpoint, xrp_secp, sui_secp,
                                            aptos_secp, iota_secp, icp_secp, fil_secp, xtz_secp,
                                            config, filters, filter_storage,
                                            bloom_storage, xor_storage, xor_un_storage,
                                            xor_uc_storage, xor_hc_storage, found);
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
                worker_priv_emit_ed_round(isResult, buffResult, pkey, next_key, publ,
                                          current_round, solana, dot, ton, ton_all, xrp_ed,
                                          aptos_ed, sui_ed, iota_ed, ada, icp_ed, xtz_ed, substratePaths,
                                          config, filters, filter_storage, bloom_storage,
                                          xor_storage, xor_un_storage, xor_uc_storage,
                                          xor_hc_storage, found);
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
                                dst[k] = WORKER_PRIV_SECP_G65[k];
                            }
                        }
                    }
                }
                worker_priv_pub_add_basepoint_batch(pubKeys, privKeyIx, +1, precPtr);
            }
        }
    }
}
