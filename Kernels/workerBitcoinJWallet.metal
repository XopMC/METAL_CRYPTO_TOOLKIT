#include "WorkerKeystoreCommon.metalh"

kernel void workerBitcoinJWallet(device bool* isResult [[buffer(0)]],
                                 device bool* buffResult [[buffer(1)]],
                                 constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                 constant ulong& precPitch [[buffer(3)]],
                                 const device BitcoinJWalletTarget* targets [[buffer(4)]],
                                 constant uint& target_count [[buffer(5)]],
                                 constant uchar& result_mode [[buffer(6)]],
                                 const device uchar* solved_flags [[buffer(7)]],
                                 constant uint& solved_count [[buffer(8)]],
                                 constant uchar& candidate_kind [[buffer(9)]],
                                 const device char* pass_data [[buffer(10)]],
                                 const device uchar* pass_lens [[buffer(11)]],
                                 constant uint& pass_count [[buffer(12)]],
                                 const device WalletMaskSpec* mask_spec [[buffer(13)]],
                                 const device WalletRangeSpec* range_spec [[buffer(14)]],
	                                 device uchar* scrypt_scratch [[buffer(15)]],
	                                 constant ulong& scrypt_scratch_stride [[buffer(16)]],
	                                 constant ulong& candidate_start [[buffer(17)]],
	                                 constant ulong& candidate_count [[buffer(18)]],
	                                 device WalletModeResult* wallet_results [[buffer(19)]],
	                                 device atomic_uint* wallet_count [[buffer(20)]],
	                                 constant uint& max_founds [[buffer(21)]],
	                                 uint tid [[thread_position_in_grid]],
	                                 uint threads [[threads_per_grid]]) {
    (void)result_mode;
    if (candidate_count == 0ul || target_count == 0u || threads == 0u) {
        return;
    }
    if (wallet_mul_overflows_u32_by_u32(candidate_count, target_count)) {
        return;
    }
    const uint total_jobs = uint(candidate_count * ulong(target_count));
    const uint stride = threads;
    for (uint job = tid; job < total_jobs; job += stride) {
        const uint candidate_idx32 = job / target_count;
        const uint target_idx = job - candidate_idx32 * target_count;
        const ulong candidate_idx = ulong(candidate_idx32);

        thread uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (!walletks_load_candidate_pass(candidate_kind, pass_data, pass_lens, pass_count,
                                          mask_spec, range_spec, candidate_start + candidate_idx,
                                          pass_local, &pass_len)) {
            continue;
        }

        const device BitcoinJWalletTarget& target = targets[target_idx];
        if (solved_flags != nullptr && target.target_index < solved_count &&
            solved_flags[target.target_index] != 0u) {
            continue;
        }
        if (target.salt_len == 0u || target.salt_len > WALLET_MAX_SALT_LEN ||
            target.encrypted_key_len == 0u ||
            target.encrypted_key_len > WALLETDAT_MAX_CRYPTED_KEY_LEN ||
            (target.encrypted_key_len & 15u) != 0u ||
            (target.pubkey_len != 33u && target.pubkey_len != 65u)) {
            continue;
        }

        thread uchar pass_utf16[WALLET_MAX_PASSWORD_LEN * 2u];
        const uint pass_utf16_len = walletks_password_to_utf16be_ascii(pass_local, pass_len,
                                                                       pass_utf16);
        thread uchar dk[32];
        if (!walletks_scrypt_sha256_32_params(pass_utf16, pass_utf16_len,
                                              target.salt, target.salt_len,
                                              target.scrypt_n, target.scrypt_r,
                                              target.scrypt_p, scrypt_scratch,
                                              scrypt_scratch_stride, ulong(tid), dk)) {
            continue;
        }

        thread uchar iv16[16];
        for (int i = 0; i < 16; ++i) {
            iv16[i] = target.iv[i];
        }
        thread uchar plain[WALLETDAT_MAX_CRYPTED_KEY_LEN];
        uint plain_len = 0u;
        if (!wallet_aes256_cbc_decrypt_pkcs7(dk, iv16, target.encrypted_key,
                                             target.encrypted_key_len, plain, &plain_len)) {
            continue;
        }
        if (plain_len == 0u || plain_len > 33u) {
            continue;
        }
        thread uchar priv32[32];
        for (int i = 0; i < 32; ++i) {
            priv32[i] = 0u;
        }
        const uint copy_len = plain_len >= 32u ? 32u : plain_len;
        const uint src_off = plain_len >= 32u ? (plain_len - 32u) : 0u;
        const uint dst_off = 32u - copy_len;
        for (uint i = 0u; i < copy_len; ++i) {
            priv32[dst_off + i] = plain[src_off + i];
        }

        thread uchar pub[65];
        if (!walletks_pubkey_from_private(precPtr, precPitch, priv32, pub, target.pubkey_len)) {
            continue;
        }
	        if (!wallet_bytes_equal(pub, target.pubkey, target.pubkey_len)) {
	            continue;
	        }
	        walletks_emit_bitcoinjwallet_result(isResult, buffResult, pass_local, pass_len,
	                                            target.target_index, result_mode, priv32,
	                                            target.pubkey, target.pubkey_len, wallet_results,
	                                            wallet_count, max_founds);
	    }
}
