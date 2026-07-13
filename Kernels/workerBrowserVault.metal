#include "BrowserVaultCommon.metalh"

kernel void workerBrowserVault(device bool* isResult [[buffer(0)]],
                               device bool* buffResult [[buffer(1)]],
                               const device BrowserVaultDeviceTarget* targets [[buffer(2)]],
                               const device uchar* ciphertext_pool [[buffer(3)]],
                               constant uint& target_count [[buffer(4)]],
                               const device uchar* solved_flags [[buffer(5)]],
                               constant uint& solved_count [[buffer(6)]],
                               constant uchar& candidate_kind [[buffer(7)]],
                               const device char* pass_data [[buffer(8)]],
                               const device uchar* pass_lens [[buffer(9)]],
                               constant uint& pass_count [[buffer(10)]],
                               const device WalletMaskSpec* mask_spec [[buffer(11)]],
                               const device WalletRangeSpec* range_spec [[buffer(12)]],
                               constant ulong& candidate_start [[buffer(13)]],
                               constant ulong& candidate_count [[buffer(14)]],
                               device WalletModeResult* wallet_results [[buffer(15)]],
                               device atomic_uint* wallet_count [[buffer(16)]],
                               constant uint& max_founds [[buffer(17)]],
                               uint tid [[thread_position_in_grid]],
                               uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || target_count == 0u) {
        return;
    }
    if (wallet_mul_overflows_u64_by_u32(candidate_count, target_count)) {
        return;
    }
    const ulong total_jobs = candidate_count * ulong(target_count);
    const ulong stride = ulong(threads);
    for (ulong job = ulong(tid); job < total_jobs; job += stride) {
        const ulong candidate_idx = job / ulong(target_count);
        const uint target_idx = uint(job - candidate_idx * ulong(target_count));

        uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (candidate_kind == WALLET_CANDIDATE_DICTIONARY) {
            const ulong dict_idx = candidate_start + candidate_idx;
            if (dict_idx >= ulong(pass_count)) {
                continue;
            }
            pass_len = pass_lens[dict_idx];
            if (pass_len > WALLET_MAX_PASSWORD_LEN) {
                pass_len = WALLET_MAX_PASSWORD_LEN;
            }
            const device char* src = pass_data + dict_idx * ulong(WALLET_PASS_STRIDE);
            for (uint i = 0u; i < pass_len; ++i) {
                pass_local[i] = uchar(src[i]);
            }
        } else if (candidate_kind == WALLET_CANDIDATE_MASK) {
            if (!wallet_candidate_from_mask(mask_spec, candidate_start + candidate_idx, pass_local, &pass_len)) {
                continue;
            }
        } else if (candidate_kind == WALLET_CANDIDATE_RANGE) {
            if (!wallet_candidate_from_range(range_spec, candidate_start + candidate_idx, pass_local, &pass_len)) {
                continue;
            }
        } else {
            continue;
        }

        const device BrowserVaultDeviceTarget& target = targets[target_idx];
        if (solved_flags != nullptr && target.target_index < solved_count && solved_flags[target.target_index] != 0u) {
            continue;
        }
        if (ciphertext_pool == nullptr || target.ciphertext_len == 0u ||
            target.ciphertext_len > BROWSERVAULT_MAX_BLOB_LEN) {
            continue;
        }
        const device uchar* ciphertext = ciphertext_pool + target.ciphertext_offset;
        uchar key32[32];
        wallet_pbkdf2_sha256_32(pass_local, pass_len, target.salt, target.salt_len, target.iterations, key32);
        if (wallet_aes256_gcm_verify(key32, target.iv, target.iv_len, ciphertext,
                                     target.ciphertext_len, target.tag)) {
            wallet_emit_browservault_result(isResult, buffResult, pass_local, pass_len,
                                            target.target_index, uchar(target.profile),
                                            target.vault_hash, wallet_results,
                                            wallet_count, max_founds);
        }
    }
}
