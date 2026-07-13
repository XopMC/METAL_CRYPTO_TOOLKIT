#include "WorkerKeystoreCommon.metalh"

kernel void workerArmoryWallet(device bool* isResult [[buffer(0)]],
                               device bool* buffResult [[buffer(1)]],
                               constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                               constant ulong& precPitch [[buffer(3)]],
                               const device ArmoryWalletTarget* targets [[buffer(4)]],
                               constant uint& target_count [[buffer(5)]],
                               const device uchar* solved_flags [[buffer(6)]],
                               constant uint& solved_count [[buffer(7)]],
                               constant uchar& candidate_kind [[buffer(8)]],
                               const device char* pass_data [[buffer(9)]],
                               const device uchar* pass_lens [[buffer(10)]],
                               constant uint& pass_count [[buffer(11)]],
                               const device WalletMaskSpec* mask_spec [[buffer(12)]],
                               const device WalletRangeSpec* range_spec [[buffer(13)]],
	                               device uchar* romix_scratch [[buffer(14)]],
	                               constant ulong& romix_scratch_stride [[buffer(15)]],
	                               constant ulong& candidate_start [[buffer(16)]],
	                               constant ulong& candidate_count [[buffer(17)]],
	                               device WalletModeResult* wallet_results [[buffer(18)]],
	                               device atomic_uint* wallet_count [[buffer(19)]],
	                               constant uint& max_founds [[buffer(20)]],
	                               uint tid [[thread_position_in_grid]],
	                               uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || target_count == 0u ||
        romix_scratch == nullptr || romix_scratch_stride == 0ul || threads == 0u) {
        return;
    }
    if (wallet_mul_overflows_u64_by_u32(candidate_count, target_count)) {
        return;
    }
    const ulong total_jobs = candidate_count * ulong(target_count);
    const ulong stride = ulong(threads);
    for (ulong job = ulong(tid); job < total_jobs; job += stride) {
        const ulong candidate_idx = job % candidate_count;
        const uint target_idx = uint(job / candidate_count);
        const device ArmoryWalletTarget& target = targets[target_idx];
        if (solved_flags != nullptr && target.target_index < solved_count &&
            solved_flags[target.target_index] != 0u) {
            continue;
        }

        thread uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (!walletks_load_candidate_pass(candidate_kind, pass_data, pass_lens, pass_count,
                                          mask_spec, range_spec, candidate_start + candidate_idx,
                                          pass_local, &pass_len)) {
            continue;
        }
        thread uchar key32[32];
        if (!walletks_armory_kdf_romix(pass_local, pass_len, target, romix_scratch,
                                       romix_scratch_stride, job, key32)) {
            continue;
        }
        thread uchar priv32[32];
        walletks_aes256_cfb_decrypt32(key32, target.iv, target.encrypted_priv, priv32);
        thread uchar pub[65];
        if (!walletks_pubkey_from_private(precPtr, precPitch, priv32, pub, 65u)) {
            continue;
        }
	        if (!wallet_bytes_equal(pub, target.pubkey, 65u)) {
	            continue;
	        }
	        walletks_emit_armorywallet_result(isResult, buffResult, pass_local, pass_len,
	                                          target.target_index, priv32, target.pubkey,
	                                          wallet_results, wallet_count, max_founds);
	    }
}
