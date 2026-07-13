#include "ElectrumWalletCommon.metalh"

kernel void workerElectrumWallet(device bool* isResult [[buffer(0)]],
                                 device bool* buffResult [[buffer(1)]],
                                 const constant ElectrumWalletTarget* targets [[buffer(2)]],
                                 const constant ElectrumWalletEcdhPrecomp* ecdh_precomp [[buffer(3)]],
                                 const device uchar* ciphertext_pool [[buffer(4)]],
                                 constant uint& target_count [[buffer(5)]],
                                 const device uchar* solved_flags [[buffer(6)]],
                                 constant uint& solved_count [[buffer(7)]],
                                 constant uchar& candidate_kind [[buffer(8)]],
                                 const device char* pass_data [[buffer(9)]],
                                 const device uchar* pass_lens [[buffer(10)]],
                                 constant uint& pass_count [[buffer(11)]],
                                 const device WalletMaskSpec* mask_spec [[buffer(12)]],
                                 const device WalletRangeSpec* range_spec [[buffer(13)]],
                                 constant ulong& candidate_start [[buffer(14)]],
                                 constant ulong& candidate_count [[buffer(15)]],
                                 device WalletModeResult* wallet_results [[buffer(16)]],
                                 device atomic_uint* wallet_count [[buffer(17)]],
                                 constant uint& max_founds [[buffer(18)]],
                                 uint tid [[thread_position_in_grid]],
                                 uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || target_count == 0u) {
        return;
    }
    const ulong stride = ulong(threads);
    for (ulong candidate_idx = ulong(tid); candidate_idx < candidate_count; candidate_idx += stride) {
        uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (!walletdat_load_candidate_pass(candidate_kind, pass_data, pass_lens, pass_count,
                                           mask_spec, range_spec, candidate_start + candidate_idx,
                                           pass_local, &pass_len)) {
            continue;
        }
        uchar seed64[64];
        uchar secret32[32];
        bool seed64_ready = false;
        bool secret32_ready = false;

        for (uint target_idx = 0u; target_idx < target_count; ++target_idx) {
            const constant ElectrumWalletTarget& target = targets[target_idx];
            if (solved_flags != nullptr && target.target_index < solved_count && solved_flags[target.target_index] != 0u) {
                continue;
            }
            if (target.kind == ELECTRUMWALLET_TARGET_BIE1) {
                if (target.ciphertext_len == 0u || target.ciphertext_len > ELECTRUMWALLET_MAX_BLOB_LEN ||
                    ciphertext_pool == nullptr) {
                    continue;
                }
                const device uchar* ciphertext = ciphertext_pool + target.ciphertext_offset;
                if (!seed64_ready) {
                    uchar empty_salt[1] = {};
                    fastpbkdf2_hmac_sha512(pass_local, ulong(pass_len), empty_salt, 0ul, 1024ul, seed64, 64ul);
                    seed64_ready = true;
                }
                uchar shared_pub33[33];
                const constant ElectrumWalletEcdhPrecomp* precomp =
                    (ecdh_precomp != nullptr) ? &ecdh_precomp[target.precomp_index] : nullptr;
                if (!wallet_electrum_ecdh_compressed33(seed64, target, precomp, shared_pub33)) {
                    continue;
                }
                uchar key64[64];
                SHA512(shared_pub33, 33ul, key64);
                if (!wallet_aes128_cbc_check_electrum_storage_edges(key64 + 16, key64,
                                                                    ciphertext,
                                                                    target.ciphertext_len)) {
                    continue;
                }
                uchar mac[32];
                wallet_hmac_sha256_electrum_bie1(key64 + 32, target, ciphertext, mac);
                if (wallet_bytes_equal_const(mac, target.mac, 32u)) {
                    wallet_emit_electrumwallet_result(isResult, buffResult, pass_local, pass_len,
                                                      target, wallet_results, wallet_count,
                                                      max_founds);
                }
            } else if (target.kind == ELECTRUMWALLET_TARGET_FIELD_V1) {
                if (target.ciphertext_len == 0u || target.ciphertext_len > WALLETDAT_MAX_CRYPTED_KEY_LEN ||
                    ciphertext_pool == nullptr) {
                    continue;
                }
                const device uchar* ciphertext = ciphertext_pool + target.ciphertext_offset;
                if (!secret32_ready) {
                    wallet_electrum_sha256d_password(pass_local, pass_len, secret32);
                    secret32_ready = true;
                }
                if (wallet_electrum_field_v1_check(secret32, target, ciphertext)) {
                    wallet_emit_electrumwallet_result(isResult, buffResult, pass_local, pass_len,
                                                      target, wallet_results, wallet_count,
                                                      max_founds);
                }
            }
        }
    }
}
