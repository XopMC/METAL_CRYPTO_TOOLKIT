#include "WorkerKeystoreCommon.metalh"

kernel void workerKeystoreV3(device bool* isResult [[buffer(0)]],
                             device bool* buffResult [[buffer(1)]],
                             constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                             constant ulong& precPitch [[buffer(3)]],
                             const device WalletKeystoreTarget* targets [[buffer(4)]],
                             constant uint& target_count [[buffer(5)]],
                             const device uchar* solved_flags [[buffer(6)]],
                             constant uint& solved_count [[buffer(7)]],
                             constant uchar& candidate_kind [[buffer(8)]],
                             const device char* pass_data [[buffer(9)]],
                             const device uchar* pass_lens [[buffer(10)]],
                             constant uint& pass_count [[buffer(11)]],
                             const device WalletMaskSpec* mask_spec [[buffer(12)]],
                             const device WalletRangeSpec* range_spec [[buffer(13)]],
	                             device uchar* scrypt_scratch [[buffer(14)]],
	                             constant ulong& scrypt_scratch_stride [[buffer(15)]],
	                             constant ulong& candidate_start [[buffer(16)]],
	                             constant ulong& candidate_count [[buffer(17)]],
	                             device WalletModeResult* wallet_results [[buffer(18)]],
	                             device atomic_uint* wallet_count [[buffer(19)]],
	                             constant uint& max_founds [[buffer(20)]],
	                             uint tid [[thread_position_in_grid]],
	                             uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || target_count == 0u || threads == 0u) {
        return;
    }
    const ulong stride = ulong(threads);
    for (ulong lane = ulong(tid); lane < candidate_count; lane += stride) {
        thread uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (!walletks_load_candidate_pass(candidate_kind, pass_data, pass_lens, pass_count,
                                          mask_spec, range_spec, candidate_start + lane,
                                          pass_local, &pass_len)) {
            continue;
        }

        for (uint target_idx = 0u; target_idx < target_count; ++target_idx) {
            const device WalletKeystoreTarget& target = targets[target_idx];
            if (solved_flags != nullptr && target.target_index < solved_count &&
                solved_flags[target.target_index] != 0u) {
                continue;
            }
            if (target.ciphertext_len == 0u ||
                target.ciphertext_len > WALLET_MAX_CIPHERTEXT_LEN ||
                target.dklen < 32u) {
                continue;
            }

            thread uchar dk[32];
            if (target.kdf_type == WALLET_KDF_PBKDF2_SHA256) {
                wallet_pbkdf2_sha256_32(pass_local, pass_len, target.salt, target.salt_len,
                                        target.iterations, dk);
            } else if (target.kdf_type == WALLET_KDF_SCRYPT) {
                if (!walletks_scrypt_sha256_32(pass_local, pass_len, target,
                                               scrypt_scratch, scrypt_scratch_stride,
                                               lane, dk)) {
                    continue;
                }
            } else {
                continue;
            }

            thread uchar mac[32];
            walletks_keystore_mac_generic(dk, target, mac);
            if (!wallet_bytes_equal(mac, target.mac, 32u)) {
                continue;
            }
	            if (target.has_address == 0u) {
	                walletks_emit_keystore_maconly_result(isResult, buffResult, pass_local, pass_len,
	                                                      target.target_index, target.vault_hash,
	                                                      wallet_results, wallet_count, max_founds);
	                continue;
	            }

            thread uchar priv[WALLET_MAX_CIPHERTEXT_LEN];
            walletks_aes128_ctr_xor(dk, target.iv, target.ciphertext,
                                    target.ciphertext_len, priv);
            if (target.ciphertext_len < 32u) {
                continue;
            }
            thread uchar eth20[20];
            if (!walletks_eth_address_from_private(precPtr, precPitch, priv, eth20)) {
                continue;
            }
	            if (!wallet_bytes_equal(eth20, target.address, 20u)) {
	                continue;
	            }
	            walletks_emit_keystore_priv_result(isResult, buffResult, pass_local, pass_len,
	                                               target.target_index, priv, eth20,
	                                               wallet_results, wallet_count, max_founds);
	        }
	    }
}
