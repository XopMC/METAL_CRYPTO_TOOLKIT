#include "WorkerDerThreadCommon.metalh"

kernel void workerDerThread_bip32_compressed(device bool* isResult [[buffer(0)]],
                                             device bool* buffResult [[buffer(1)]],
                                             constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                             constant ulong& precPitch [[buffer(3)]],
                                             const device uchar* d_master_secp [[buffer(4)]],
                                             const device char* d_save_str [[buffer(5)]],
                                             const device char* d_passphrase [[buffer(6)]],
                                             const device uint* d_derivations [[buffer(7)]],
                                             const device uint* d_deriv_offsets [[buffer(8)]],
                                             const device uint* derindex [[buffer(9)]],
                                             constant DerThreadRunParams& params [[buffer(10)]],
                                             device RuntimeConfig& config [[buffer(11)]],
                                             device XorFilterState& filters [[buffer(12)]],
                                             device FilterStorageState& filter_storage [[buffer(13)]],
                                             const device uchar* bloom_storage [[buffer(14)]],
                                             const device uchar* xor_storage [[buffer(15)]],
                                             const device uchar* xor_un_storage [[buffer(16)]],
                                             const device uchar* xor_uc_storage [[buffer(17)]],
                                             const device uchar* xor_hc_storage [[buffer(18)]],
                                             device char* foundStrings [[buffer(19)]],
                                             device uchar* foundPrvKeys [[buffer(20)]],
                                             device uint* foundHash160 [[buffer(21)]],
                                             device uint* foundLen [[buffer(22)]],
                                             device uchar* foundType [[buffer(23)]],
                                             device uint* foundDerivations [[buffer(24)]],
                                             device char* foundPass [[buffer(25)]],
                                             device ushort* foundPassSize [[buffer(26)]],
                                             device long* foundRound [[buffer(27)]],
                                             device ulong* foundSeed [[buffer(28)]],
                                             device atomic_uint* resultsCount [[buffer(29)]],
                                             uint tid [[thread_position_in_grid]]) {
    const uint global_path = tid + params.der_offset;
    if (global_path >= params.der_indexes_size || d_master_secp == nullptr ||
        d_derivations == nullptr || d_deriv_offsets == nullptr || derindex == nullptr) {
        return;
    }

    FoundBuffers found;
    der_make_found_buffers(foundStrings, foundPrvKeys, foundHash160, foundLen, nullptr,
                           foundType, foundDerivations, nullptr, foundPass,
                           foundPassSize, foundRound, foundSeed, resultsCount,
                           config.maxFounds, found);

    const uint path_offset = d_deriv_offsets[global_path];
    const uint path_len = derindex[global_path];

    extended_private_key_t master_private;
    der_load_master_extended(d_master_secp, &master_private);

    uchar pubKeys[65];
    uchar prvKeys[32];
    uint hash160[8] = { 0 };
    der_get_child_key_secp256k1(precPtr, size_t(precPitch), &master_private,
                                d_derivations + path_offset, path_len, prvKeys);

    const bool store_seed = params.store_seed != 0u;
    if (params.round > 0ul) {
        bump_key_256(prvKeys, params.round, false);
    }

    for (ulong s = 0ul; s <= (2ul * params.round); ++s) {
        const long current_round = long(s) - long(params.round);

        pubKeys[0] = 0x04u;
        secp256k1_ec_pubkey_create(reinterpret_cast<thread secp256k1_pubkey*>(pubKeys + 1),
                                   prvKeys,
                                   precPtr,
                                   size_t(precPitch));

        int keylenskip = 0;
        _GetHash160Comp(pubKeys, keylenskip, reinterpret_cast<thread uchar*>(hash160));
        der_check_and_store_words(isResult, buffResult, prvKeys, hash160, 20u, hash160,
                                  0x02u, global_path, d_save_str, params.d_save_len, d_passphrase,
                                  params.pass_len, store_seed, params.seed_value, current_round, config,
                                  filters, filter_storage, bloom_storage, xor_storage,
                                  xor_un_storage, xor_uc_storage, xor_hc_storage, found);

        if (config.p2wsh != 0u) {
            uchar p2wsh_hash[32];
            uint p2wsh_rmd[8] = { 0 };
            _GetP2WSHComp(pubKeys, p2wsh_hash, p2wsh_rmd);
            der_check_and_store_words(isResult, buffResult, prvKeys, p2wsh_hash, 32u, p2wsh_rmd,
                                      0x07u, global_path, d_save_str, params.d_save_len, d_passphrase,
                                      params.pass_len, store_seed, params.seed_value, current_round, config,
                                      filters, filter_storage, bloom_storage, xor_storage,
                                      xor_un_storage, xor_uc_storage, xor_hc_storage, found);
        }

        if (s < (2ul * params.round)) {
            const bool wrapped = bump_key_256(prvKeys, 1ul, true);
            if (wrapped) {
                s += 2ul;
            }
        }
    }
}
