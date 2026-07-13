#include "WorkerDerThreadCommon.metalh"

kernel void workerDerThread_slip0010_solana(device bool* isResult [[buffer(0)]],
                                            device bool* buffResult [[buffer(1)]],
                                            const device uchar* d_master_ed [[buffer(2)]],
                                            const device hmac_sha512_precomp_t* d_master_ed_hmac_precomp [[buffer(3)]],
                                            const device char* d_save_str [[buffer(4)]],
                                            const device char* d_passphrase [[buffer(5)]],
                                            const device uint* d_derivations [[buffer(6)]],
                                            const device uint* d_deriv_offsets [[buffer(7)]],
                                            const device uint* derindex [[buffer(8)]],
                                            constant DerThreadRunParams& params [[buffer(9)]],
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
    const uint global_path = tid + params.der_offset;
    if (global_path >= params.der_indexes_size || d_master_ed == nullptr ||
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
    der_load_master_extended(d_master_ed, &master_private);

    uchar sol_priv[32];
    if (path_len != 0u && d_master_ed_hmac_precomp != nullptr) {
        hmac_sha512_precomp_t local_precomp = d_master_ed_hmac_precomp[0];
        der_get_child_key_ed25519_precomp_first(&master_private,
                                                d_derivations + path_offset,
                                                path_len,
                                                &local_precomp,
                                                sol_priv);
    } else {
        der_get_child_key_ed25519(&master_private,
                                  d_derivations + path_offset,
                                  path_len,
                                  sol_priv);
    }

    const bool store_seed = params.store_seed != 0u;
    if (params.round > 0ul) {
        bump_key_256(sol_priv, params.round, false);
    }

    for (ulong s = 0ul; s <= (2ul * params.round); ++s) {
        const long current_round = long(s) - long(params.round);

        uchar publ[32];
        priv_ed25519_key_to_pub_one_config(sol_priv, publ, config);
        uint hash_words[8] = { 0 };
        priv_hash_words_from_bytes(publ, hash_words, 32u);
        der_check_and_store_words(isResult, buffResult, sol_priv, publ, 32u, hash_words,
                                  0x60u, global_path, d_save_str, params.d_save_len, d_passphrase,
                                  params.pass_len, store_seed, params.seed_value, current_round, config,
                                  filters, filter_storage, bloom_storage, xor_storage,
                                  xor_un_storage, xor_uc_storage, xor_hc_storage, found);

        if (s < (2ul * params.round)) {
            bump_key_256(sol_priv, 1ul, true);
        }
    }
}
