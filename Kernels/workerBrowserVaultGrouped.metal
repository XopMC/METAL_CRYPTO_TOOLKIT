#include "WorkerKeystoreCommon.metalh"

#ifndef ENABLE_BIP38_BROWSER_GPU
#define ENABLE_BIP38_BROWSER_GPU 0
#endif

constant uint browser_vault_profile_specialization [[function_constant(92)]];
static constant uint BROWSERVAULT_PROFILE_DYNAMIC = 0xffffffffu;

__attribute__((noinline)) static bool wallet_browservault_scrypt_sha256_32(
    const thread uchar* pass,
    uint pass_len,
    const device uchar* salt,
    uint salt_len,
    uint n,
    uint r,
    uint p,
    device uchar* scratch,
    ulong scratch_stride,
    ulong lane,
    thread uchar out32[32]) {
    return walletks_scrypt_sha256_32_params(pass, pass_len, salt, salt_len, n, r, p,
                                            scratch, scratch_stride, lane, out32);
}

__attribute__((noinline)) static bool wallet_ethpresale_verify(const constant secp256k1_ge_storage* precPtr,
                                            ulong precPitch,
                                            const thread uchar key32[32],
                                            const device BrowserVaultDeviceTarget& target,
                                            const device uchar* ciphertext,
                                            thread uchar priv32[32],
                                            thread uchar eth20[20]) {
    uchar bkp32[32];
    if (!wallet_ethpresale_priv_from_encseed(key32, target.iv, ciphertext,
                                             target.ciphertext_len, priv32, bkp32)) {
        return false;
    }
    for (int i = 0; i < 16; ++i) {
        if (bkp32[i] != target.tag[i]) {
            return false;
        }
    }
    if (precPtr == nullptr || !walletks_eth_address_from_private(precPtr, precPitch, priv32, eth20)) {
        return false;
    }
    for (int i = 0; i < 20; ++i) {
        if (eth20[i] != target.salt[i]) {
            return false;
        }
    }
    return true;
}

static inline void wallet_emit_ethpresale_result(device bool* isResult,
                                                 device bool* buffResult,
                                                 const thread uchar* pass,
                                                 uint pass_len,
                                                 uint target_index,
                                                 const thread uchar priv32[32],
                                                 const thread uchar eth20[20],
                                                 device WalletModeResult* wallet_results,
                                                 device atomic_uint* wallet_count,
                                                 uint max_founds) {
    walletks_mark_hit(isResult, buffResult);
    if (wallet_results == nullptr || wallet_count == nullptr) {
        return;
    }
    const ulong ridx = wallet_atomic_add_count(wallet_count, 1u);
    if (ridx >= ulong(max_founds)) {
        return;
    }
    device WalletModeResult& out = wallet_results[ridx];
    wallet_zero_result(out);
    out.mode = WALLET_MODE_ETHPRESALE;
    out.type = BROWSERVAULT_PROFILE_ETHPRESALE_PBKDF2_AES_CBC;
    out.target_index = target_index;
    walletks_copy_password(out, pass, pass_len);
    for (int i = 0; i < 32; ++i) out.priv[i] = priv32[i];
    for (int i = 0; i < 20; ++i) out.payload[i] = eth20[i];
    out.payload_len = 20u;
}

kernel void workerBrowserVaultGrouped(device bool* isResult [[buffer(0)]],
                                      device bool* buffResult [[buffer(1)]],
                                      constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                      constant ulong& precPitch [[buffer(3)]],
                                      const device BrowserVaultDeviceTarget* targets [[buffer(4)]],
                                      const device BrowserVaultGroup* groups [[buffer(5)]],
                                      const device uchar* ciphertext_pool [[buffer(6)]],
                                      constant uint& group_count [[buffer(7)]],
                                      const device uchar* solved_flags [[buffer(8)]],
                                      constant uint& solved_count [[buffer(9)]],
                                      constant uchar& candidate_kind [[buffer(10)]],
                                      const device char* pass_data [[buffer(11)]],
                                      const device uchar* pass_lens [[buffer(12)]],
                                      constant uint& pass_count [[buffer(13)]],
                                      const device WalletMaskSpec* mask_spec [[buffer(14)]],
                                      const device WalletRangeSpec* range_spec [[buffer(15)]],
                                      device uchar* scrypt_scratch [[buffer(16)]],
                                      constant ulong& scrypt_scratch_stride [[buffer(17)]],
                                      constant ulong& candidate_start [[buffer(18)]],
                                      constant ulong& candidate_count [[buffer(19)]],
                                      device WalletModeResult* wallet_results [[buffer(20)]],
                                      device atomic_uint* wallet_count [[buffer(21)]],
                                      constant uint& max_founds [[buffer(22)]],
                                      uint tid [[thread_position_in_grid]],
                                      uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || group_count == 0u || groups == nullptr ||
        targets == nullptr || threads == 0u) {
        return;
    }
    if (wallet_mul_overflows_u64_by_u32(candidate_count, group_count)) {
        return;
    }
    const ulong total_jobs = candidate_count * ulong(group_count);
    const ulong stride = ulong(threads);
    for (ulong job = ulong(tid); job < total_jobs; job += stride) {
        const ulong candidate_idx = job / ulong(group_count);
        const uint group_idx = uint(job - candidate_idx * ulong(group_count));
        const device BrowserVaultGroup& group = groups[group_idx];
        const uint group_profile = browser_vault_profile_specialization == BROWSERVAULT_PROFILE_DYNAMIC
            ? group.profile
            : browser_vault_profile_specialization;
        if (browser_vault_profile_specialization != BROWSERVAULT_PROFILE_DYNAMIC &&
            group.profile != browser_vault_profile_specialization) {
            continue;
        }
        if (group.target_count == 0u || group.salt_len > WALLET_MAX_SALT_LEN ||
            (group.salt_len == 0u && group_profile != BROWSERVAULT_PROFILE_ETHPRESALE_PBKDF2_AES_CBC)) {
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
        thread uchar atomic_iv16[16];
        bool atomic_key_ready = false;
        if (group_profile == BROWSERVAULT_PROFILE_PHANTOM_SECRETBOX_SCRYPT ||
            group_profile == BROWSERVAULT_PROFILE_MULTIBIT_HD_SCRYPT_AES ||
            group_profile == BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_SCRYPT_AES ||
            group_profile == BROWSERVAULT_PROFILE_BISQ_SCRYPT_AES) {
            if (group_profile == BROWSERVAULT_PROFILE_MULTIBIT_HD_SCRYPT_AES ||
                group_profile == BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_SCRYPT_AES ||
                group_profile == BROWSERVAULT_PROFILE_BISQ_SCRYPT_AES) {
                thread uchar pass_utf16[WALLET_MAX_PASSWORD_LEN * 2u];
                const uint pass_utf16_len = walletks_password_to_utf16be_ascii(
                    pass_local, pass_len, pass_utf16);
                if (!wallet_browservault_scrypt_sha256_32(pass_utf16, pass_utf16_len,
                        group.salt, group.salt_len, group.scrypt_n, group.scrypt_r,
                        group.scrypt_p, scrypt_scratch, scrypt_scratch_stride,
                        ulong(tid), key32)) {
                    continue;
                }
            } else if (!wallet_browservault_scrypt_sha256_32(pass_local, pass_len,
                    group.salt, group.salt_len, group.scrypt_n, group.scrypt_r,
                    group.scrypt_p, scrypt_scratch, scrypt_scratch_stride,
                    ulong(tid), key32)) {
                continue;
            }
        } else if (group_profile == BROWSERVAULT_PROFILE_ATOMIC_CRYPTOJS_AES) {
            if (group.salt_len != 8u) {
                continue;
            }
            wallet_cryptojs_evp_bytes_to_key_md5(pass_local, pass_len, group.salt,
                                                 key32, atomic_iv16);
            atomic_key_ready = true;
        } else if (group_profile == BROWSERVAULT_PROFILE_BLOCKCHAIN_V2_PBKDF2_AES_CBC) {
            wallet_pbkdf2_sha1_32(pass_local, pass_len, group.salt, group.salt_len,
                                  group.iterations, key32);
        } else if (group_profile == BROWSERVAULT_PROFILE_ANDROID_BACKUP_PBKDF2_SHA1_AES_CBC) {
            wallet_pbkdf2_sha1_32(pass_local, pass_len, group.salt, group.salt_len,
                                  group.iterations, key32);
        } else if (group_profile == BROWSERVAULT_PROFILE_DOGECHAIN_PBKDF2_AES_CBC) {
            thread uchar pass_sha[32];
            thread uchar pass_b64[44];
            SHA256(pass_local, size_t(pass_len), pass_sha);
            wallet_base64_encode_32_device(pass_sha, pass_b64);
            wallet_pbkdf2_sha256_32(pass_b64, 44u, group.salt, group.salt_len,
                                    group.iterations, key32);
        } else if (group_profile == BROWSERVAULT_PROFILE_ETHPRESALE_PBKDF2_AES_CBC) {
            wallet_pbkdf2_sha256_32_thread_salt(pass_local, pass_len, pass_local,
                                                pass_len, group.iterations, key32);
        } else if (group_profile == BROWSERVAULT_PROFILE_BIP38_NON_EC) {
#if ENABLE_BIP38_BROWSER_GPU
#error ENABLE_BIP38_BROWSER_GPU requires the BIP38 Metal verifier implementation
#else
            continue;
#endif
        } else if (group_profile == BROWSERVAULT_PROFILE_BIP38_EC) {
#if ENABLE_BIP38_BROWSER_GPU
#error ENABLE_BIP38_BROWSER_GPU requires the BIP38 Metal verifier implementation
#else
            continue;
#endif
        } else if (group_profile == BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_MD5_AES) {
            if (group.salt_len != 8u) {
                continue;
            }
            wallet_cryptojs_evp_bytes_to_key_md5(pass_local, pass_len, group.salt,
                                                 key32, atomic_iv16);
            atomic_key_ready = true;
        } else {
            wallet_pbkdf2_sha256_32(pass_local, pass_len, group.salt, group.salt_len,
                                    group.iterations, key32);
        }

        const uint end = group.target_offset + group.target_count;
        for (uint target_idx = group.target_offset; target_idx < end; ++target_idx) {
            const device BrowserVaultDeviceTarget& target = targets[target_idx];
            const uint target_profile = browser_vault_profile_specialization == BROWSERVAULT_PROFILE_DYNAMIC
                ? target.profile
                : browser_vault_profile_specialization;
            if (browser_vault_profile_specialization != BROWSERVAULT_PROFILE_DYNAMIC &&
                target.profile != browser_vault_profile_specialization) {
                continue;
            }
            if (solved_flags != nullptr && target.target_index < solved_count &&
                solved_flags[target.target_index] != 0u) {
                continue;
            }
            if (ciphertext_pool == nullptr || target.ciphertext_len == 0u ||
                target.ciphertext_len > BROWSERVAULT_MAX_BLOB_LEN) {
                continue;
            }
            const device uchar* ciphertext = ciphertext_pool + target.ciphertext_offset;
            bool ok = false;
            if (target_profile == BROWSERVAULT_PROFILE_METAMASK_AES_GCM ||
                target_profile == BROWSERVAULT_PROFILE_STELLAR_AES_GCM) {
                ok = wallet_aes256_gcm_verify(key32, target.iv, target.iv_len, ciphertext,
                                              target.ciphertext_len, target.tag);
            } else if (target_profile == BROWSERVAULT_PROFILE_ATOMIC_CRYPTOJS_AES) {
                if (!atomic_key_ready) continue;
                ok = wallet_aes256_cbc_check_cryptojs_atomic(key32, atomic_iv16, ciphertext,
                                                             target.ciphertext_len);
            } else if (target_profile == BROWSERVAULT_PROFILE_BLOCKCHAIN_V2_PBKDF2_AES_CBC) {
                ok = wallet_aes256_cbc_check_blockchain_printable(key32, target.iv, ciphertext,
                                                                  target.ciphertext_len);
            } else if (target_profile == BROWSERVAULT_PROFILE_ANDROID_BACKUP_PBKDF2_SHA1_AES_CBC) {
                ok = wallet_aes256_cbc_check_android_backup_tail(key32, target.iv, ciphertext,
                                                                 target.ciphertext_len);
            } else if (target_profile == BROWSERVAULT_PROFILE_DOGECHAIN_PBKDF2_AES_CBC) {
                ok = wallet_aes256_cbc_check_dogechain_ascii(key32, target.iv, ciphertext,
                                                             target.ciphertext_len);
            } else if (target_profile == BROWSERVAULT_PROFILE_ETHPRESALE_PBKDF2_AES_CBC) {
                thread uchar priv32[32];
                thread uchar eth20[20];
                if (wallet_ethpresale_verify(precPtr, precPitch, key32, target, ciphertext,
                                             priv32, eth20)) {
                    wallet_emit_ethpresale_result(isResult, buffResult, pass_local, pass_len,
                        target.target_index, priv32, eth20, wallet_results, wallet_count,
                        max_founds);
                }
                continue;
            } else if (target_profile == BROWSERVAULT_PROFILE_BIP38_NON_EC) {
                continue;
            } else if (target_profile == BROWSERVAULT_PROFILE_BIP38_EC) {
                continue;
            } else if (target_profile == BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_MD5_AES) {
                if (!atomic_key_ready) continue;
                ok = wallet_aes256_cbc_check_multibit_classic_md5(key32, atomic_iv16,
                                                                  ciphertext, target.ciphertext_len);
            } else if (target_profile == BROWSERVAULT_PROFILE_MULTIBIT_HD_SCRYPT_AES) {
                ok = wallet_aes256_cbc_check_multibit_hd_scrypt(key32, target.iv, ciphertext,
                                                                target.ciphertext_len);
            } else if (target_profile == BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_SCRYPT_AES) {
                ok = wallet_aes256_cbc_check_multibit_classic_scrypt(key32, target.iv,
                                                                     ciphertext, target.ciphertext_len);
            } else if (target_profile == BROWSERVAULT_PROFILE_BISQ_SCRYPT_AES) {
                ok = wallet_aes256_cbc_check_multibit_classic_scrypt(key32, target.iv,
                                                                     ciphertext, target.ciphertext_len);
            } else {
                ok = wallet_xsalsa20poly1305_secretbox_verify(key32, target.iv, target.tag,
                                                              ciphertext, target.ciphertext_len);
            }
            if (ok) {
                wallet_emit_browservault_result(isResult, buffResult, pass_local, pass_len,
                                                target.target_index, uchar(target.profile),
                                                target.vault_hash, wallet_results,
                                                wallet_count, max_founds);
            }
        }
    }
}
