#include "WorkerKeystoreCommon.metalh"

kernel void workerExodusSeco(device bool* isResult [[buffer(0)]],
                             device bool* buffResult [[buffer(1)]],
                             const device ExodusSecoTarget* targets [[buffer(2)]],
                             constant uint& target_count [[buffer(3)]],
                             const device uchar* solved_flags [[buffer(4)]],
                             constant uint& solved_count [[buffer(5)]],
                             constant uchar& candidate_kind [[buffer(6)]],
                             const device char* pass_data [[buffer(7)]],
                             const device uchar* pass_lens [[buffer(8)]],
                             constant uint& pass_count [[buffer(9)]],
                             const device WalletMaskSpec* mask_spec [[buffer(10)]],
                             const device WalletRangeSpec* range_spec [[buffer(11)]],
	                             device uchar* scrypt_scratch [[buffer(12)]],
	                             constant ulong& scrypt_scratch_stride [[buffer(13)]],
	                             constant ulong& candidate_start [[buffer(14)]],
	                             constant ulong& candidate_count [[buffer(15)]],
	                             device WalletModeResult* wallet_results [[buffer(16)]],
	                             device atomic_uint* wallet_count [[buffer(17)]],
	                             constant uint& max_founds [[buffer(18)]],
	                             uint tid [[thread_position_in_grid]],
	                             uint threads [[threads_per_grid]]) {
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

        const device ExodusSecoTarget& target = targets[target_idx];
        if (solved_flags != nullptr && target.target_index < solved_count &&
            solved_flags[target.target_index] != 0u) {
            continue;
        }
        thread uchar dk[32];
        if (!walletks_scrypt_sha256_32_params(pass_local, pass_len, target.salt, target.salt_len,
                                              target.scrypt_n, target.scrypt_r, target.scrypt_p,
                                              scrypt_scratch, scrypt_scratch_stride, ulong(tid),
                                              dk)) {
            continue;
	        }
	        if (wallet_aes256_gcm_verify(dk, target.key_iv, 12u, target.encrypted_key,
	                                     32u, target.key_tag)) {
	            walletks_emit_exodusseco_result(isResult, buffResult, pass_local, pass_len,
	                                            target.target_index, target.vault_hash,
	                                            wallet_results, wallet_count, max_founds);
	        }
	    }
}
