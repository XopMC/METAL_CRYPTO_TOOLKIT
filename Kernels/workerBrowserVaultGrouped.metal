#define METAL_CRYPTO_BROWSER_VAULT_SUBSTRATE 1
#include "WorkerKeystoreCommon.metalh"

#ifndef ENABLE_BIP38_BROWSER_GPU
#define ENABLE_BIP38_BROWSER_GPU 1
#endif

#define WALLET_MODE_BIP38 15u
#define BROWSERVAULT_PROFILE_TERRA_STATION_AES_CBC 34u
#define BROWSERVAULT_PROFILE_BITSHARES_0X_AES_CBC 35u
#define BROWSERVAULT_PROFILE_YOROI_EMIP3 36u

constant uint browser_vault_profile_specialization [[function_constant(92)]];
static constant uint BROWSERVAULT_PROFILE_DYNAMIC = 0xffffffffu;

__attribute__((noinline)) static void wallet_dogechain_hmac_sha256_32(
    const thread WalletHmacSha256Precomp* ctx,
    const thread uchar msg[32],
    thread uchar out_mac[32]) {
    uint s[8];
    uint w[16];
    for (int i = 0; i < 8; ++i) {
        s[i] = ctx->istate[i];
        const thread uchar* q = msg + (uint(i) << 2u);
        w[i] = (uint(q[0]) << 24u) | (uint(q[1]) << 16u) |
               (uint(q[2]) << 8u) | uint(q[3]);
    }
    w[8] = 0x80000000u;
    for (int i = 9; i < 15; ++i) {
        w[i] = 0u;
    }
    w[15] = 96u * 8u;
    SHA256Transform(s, w);

    for (int i = 0; i < 8; ++i) {
        w[i] = s[i];
        s[i] = ctx->ostate[i];
    }
    w[8] = 0x80000000u;
    for (int i = 9; i < 15; ++i) {
        w[i] = 0u;
    }
    w[15] = 96u * 8u;
    SHA256Transform(s, w);
    for (int i = 0; i < 8; ++i) {
        wallet_store_be32(out_mac + (uint(i) << 2u), s[i]);
    }
}

__attribute__((noinline)) static void wallet_dogechain_pbkdf2_sha256_32(
    const thread uchar pass_b64[44],
    const device uchar* salt_in,
    uint salt_len,
    uint iterations,
    thread uchar out32[32]) {
    uchar salt_block[WALLET_MAX_SALT_LEN + 4u];
    uchar u[32];
    uchar u_next[32];
    if (salt_len > WALLET_MAX_SALT_LEN) {
        salt_len = WALLET_MAX_SALT_LEN;
    }
    for (uint i = 0u; i < salt_len; ++i) {
        salt_block[i] = salt_in[i];
    }
    wallet_store_be32(salt_block + salt_len, 1u);

    WalletHmacSha256Precomp hmac_ctx;
    wallet_hmac_sha256_precompute(pass_b64, 44u, &hmac_ctx);
    wallet_hmac_sha256_from_precomp(&hmac_ctx, salt_block, salt_len + 4u, u);
    for (int i = 0; i < 32; ++i) {
        out32[i] = u[i];
    }

    uint iter = 1u;
    for (; iter + 1u < iterations; iter += 2u) {
        wallet_dogechain_hmac_sha256_32(&hmac_ctx, u, u_next);
        for (int i = 0; i < 32; ++i) {
            out32[i] = uchar(out32[i] ^ u_next[i]);
        }
        wallet_dogechain_hmac_sha256_32(&hmac_ctx, u_next, u);
        for (int i = 0; i < 32; ++i) {
            out32[i] = uchar(out32[i] ^ u[i]);
        }
    }
    if (iter < iterations) {
        wallet_dogechain_hmac_sha256_32(&hmac_ctx, u, u_next);
        for (int i = 0; i < 32; ++i) {
            out32[i] = uchar(out32[i] ^ u_next[i]);
        }
    }
}

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

__attribute__((noinline)) static bool wallet_bip38_scrypt_sha256_64(
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
    thread uchar out64[64]) {
    if (p == 0u || r == 0u || r > WALLET_SCRYPT_MAX_R ||
        n < 2u || ((n & (n - 1u)) != 0u)) {
        return false;
    }
    const uint block_size = 128u * r;
    const ulong b_len = ulong(p) * ulong(block_size);
    if (b_len / ulong(p) != ulong(block_size)) {
        return false;
    }
    const ulong need = ulong(n) * ulong(block_size) + b_len + 4ul + ulong(block_size);
    if (scratch == nullptr || scratch_stride < need) {
        return false;
    }

    device uchar* v = scratch + lane * scratch_stride;
    device uchar* final_b = v + ulong(n) * ulong(block_size);
    device uchar* y = final_b + b_len + 4ul;
    WalletHmacSha256Precomp hmac_ctx;
    const bool use_fast_hmac = wallet_hmac_sha256_precompute(pass, pass_len, &hmac_ctx);
    walletks_pbkdf2_sha256_with_hmac_device_salt(pass, pass_len, salt, salt_len, 1u,
                                                 &hmac_ctx, use_fast_hmac, final_b, uint(b_len));

    device uint* v_words = reinterpret_cast<device uint*>(v);
    device uint* y_words = reinterpret_cast<device uint*>(y);
    const uint block_words = block_size >> 2u;
    for (uint part = 0u; part < p; ++part) {
        device uchar* b = final_b + ulong(part) * ulong(block_size);
        device uint* b_words = reinterpret_cast<device uint*>(b);
        for (uint i = 0u; i < n; ++i) {
            device uint* vi = v_words + ulong(i) * ulong(block_words);
            if (r == 8u) {
                walletks_copy_words_r8_block(vi, b_words);
                walletks_scrypt_blockmix_words_r8_fast(b_words, y_words);
            } else {
                for (uint j = 0u; j < block_words; ++j) {
                    vi[j] = b_words[j];
                }
                walletks_scrypt_blockmix_words(b_words, y_words, r);
            }
        }
        for (uint i = 0u; i < n; ++i) {
            const uint j = b_words[(2u * r - 1u) * 16u] & (n - 1u);
            const device uint* vj = v_words + ulong(j) * ulong(block_words);
            if (r == 8u) {
                walletks_scrypt_blockmix_xor_words_r8_fused(b_words, vj, y_words);
            } else {
                for (uint k = 0u; k < block_words; ++k) {
                    b_words[k] ^= vj[k];
                }
                walletks_scrypt_blockmix_words(b_words, y_words, r);
            }
        }
    }

    walletks_store_be32(final_b + b_len, 1u);
    if (use_fast_hmac) {
        walletks_hmac_sha256_from_precomp_device(&hmac_ctx, final_b, uint(b_len) + 4u, out64);
    } else {
        walletks_hmac_sha256_device(pass, pass_len, final_b, uint(b_len) + 4u, out64);
    }
    walletks_store_be32(final_b + b_len, 2u);
    if (use_fast_hmac) {
        walletks_hmac_sha256_from_precomp_device(&hmac_ctx, final_b, uint(b_len) + 4u, out64 + 32u);
    } else {
        walletks_hmac_sha256_device(pass, pass_len, final_b, uint(b_len) + 4u, out64 + 32u);
    }
    return true;
}

static inline void wallet_bip38_aes256_decrypt_thread(
    const thread uint round_keys[60],
    const thread uchar in[16],
    thread uchar out[16]) {
    uchar state[16];
    for (int i = 0; i < 16; ++i) state[i] = in[i];
    wallet_aes_add_round_key256(state, round_keys, 14);
    for (int round = 13; round >= 1; --round) {
        wallet_aes_inv_shift_rows(state);
        wallet_aes_inv_sub_bytes(state);
        wallet_aes_add_round_key256(state, round_keys, round);
        wallet_aes_inv_mix_columns(state);
    }
    wallet_aes_inv_shift_rows(state);
    wallet_aes_inv_sub_bytes(state);
    wallet_aes_add_round_key256(state, round_keys, 0);
    for (int i = 0; i < 16; ++i) out[i] = state[i];
}

static inline char wallet_bip38_base58_char(uint v) {
    if (v < 9u) return char('1' + v);
    if (v < 17u) return char('A' + (v - 9u));
    if (v < 22u) return char('J' + (v - 17u));
    if (v < 33u) return char('P' + (v - 22u));
    if (v < 44u) return char('a' + (v - 33u));
    if (v < 57u) return char('m' + (v - 44u));
    return 'z';
}

static inline uint wallet_bip38_base58check_p2pkh_address(
    const thread uchar hash160[20],
    thread uchar out[40]) {
    uchar payload[25];
    payload[0] = 0u;
    for (int i = 0; i < 20; ++i) payload[1 + i] = hash160[i];
    uchar h1[32];
    uchar h2[32];
    SHA256(payload, 21u, h1);
    SHA256(h1, 32u, h2);
    for (int i = 0; i < 4; ++i) payload[21 + i] = h2[i];

    uchar digits[40] = {};
    uint digit_len = 1u;
    uint leading_zeroes = 0u;
    while (leading_zeroes < 25u && payload[leading_zeroes] == 0u) ++leading_zeroes;
    for (uint i = 0u; i < 25u; ++i) {
        uint carry = uint(payload[i]);
        for (uint j = 0u; j < digit_len; ++j) {
            carry += uint(digits[j]) << 8u;
            digits[j] = uchar(carry % 58u);
            carry /= 58u;
        }
        while (carry != 0u && digit_len < 40u) {
            digits[digit_len++] = uchar(carry % 58u);
            carry /= 58u;
        }
    }
    uint out_len = 0u;
    for (uint i = 0u; i < leading_zeroes && out_len < 40u; ++i) out[out_len++] = uchar('1');
    for (int i = int(digit_len) - 1; i >= 0 && out_len < 40u; --i) {
        out[out_len++] = uchar(wallet_bip38_base58_char(uint(digits[i])));
    }
    return out_len;
}

static inline bool wallet_bip38_addresshash_matches(
    const thread uchar hash160[20],
    const device uchar* address_hash4) {
    uchar address[40];
    const uint address_len = wallet_bip38_base58check_p2pkh_address(hash160, address);
    if (address_len == 0u || address_len > 40u) return false;
    uchar h1[32];
    uchar h2[32];
    SHA256(address, size_t(address_len), h1);
    SHA256(h1, 32u, h2);
    uchar diff = 0u;
    for (int i = 0; i < 4; ++i) diff |= uchar(h2[i] ^ address_hash4[i]);
    return diff == 0u;
}

static inline void wallet_bip38_double_sha256(
    const thread uchar* data,
    uint len,
    thread uchar out32[32]) {
    uchar h1[32];
    SHA256(data, size_t(len), h1);
    SHA256(h1, 32u, out32);
}

static inline bool wallet_bip38_hash160_from_private(
    const constant secp256k1_ge_storage* precPtr,
    ulong precPitch,
    const thread uchar priv32[32],
    bool compressed,
    thread uchar out20[20]) {
    uchar pubkey65[65];
    ulong px[4];
    ulong py[4];
    if (!walletks_priv_to_xy(precPtr, precPitch, priv32, pubkey65, px, py)) return false;
    if (compressed) {
        _GetHash160Comp_fast(px, uchar(py[0] & 1ul), out20);
    } else {
        _GetHash160Uncomp_fast(px, py, out20);
    }
    return true;
}

static inline bool wallet_bip38_passpoint_from_factor(
    const constant secp256k1_ge_storage* precPtr,
    ulong precPitch,
    const thread uchar factor32[32],
    thread uchar passpoint33[33]) {
    return walletks_pubkey_from_private(precPtr, precPitch, factor32, passpoint33, 33u);
}

__attribute__((noinline)) static bool wallet_bip38_non_ec_verify(
    const constant secp256k1_ge_storage* precPtr,
    ulong precPitch,
    const thread uchar* pass,
    uint pass_len,
    const device BrowserVaultDeviceTarget& target,
    const device uchar* ciphertext,
    device uchar* scratch,
    ulong scratch_stride,
    ulong scratch_lane,
    thread uchar priv32[32],
    thread uchar hash160[20],
    thread uchar* result_type) {
    if (precPtr == nullptr || ciphertext == nullptr || target.ciphertext_len != 32u ||
        target.salt_len != 4u || target.iv_len == 0u) return false;
    const uchar flag = target.iv[0];
    if (flag != 0xc0u && flag != 0xe0u) return false;
    uchar derived[64];
    if (!wallet_bip38_scrypt_sha256_64(pass, pass_len, target.salt, 4u,
                                       16384u, 8u, 8u, scratch, scratch_stride,
                                       scratch_lane, derived)) return false;
    uint round_keys[60];
    provider_aes_expand_key(derived + 32u, round_keys);
    uchar plain[32];
    wallet_aes256_decrypt_block(round_keys, ciphertext, plain);
    wallet_aes256_decrypt_block(round_keys, ciphertext + 16u, plain + 16u);
    for (int i = 0; i < 32; ++i) priv32[i] = uchar(plain[i] ^ derived[i]);

    const bool compressed = (flag & 0x20u) != 0u;
    if (!wallet_bip38_hash160_from_private(precPtr, precPitch, priv32, compressed, hash160) ||
        !wallet_bip38_addresshash_matches(hash160, target.salt)) return false;
    *result_type = compressed ? 0x02u : 0x01u;
    return true;
}

__attribute__((noinline)) static bool wallet_bip38_ec_verify(
    const constant secp256k1_ge_storage* precPtr,
    ulong precPitch,
    const thread uchar* pass,
    uint pass_len,
    const device BrowserVaultDeviceTarget& target,
    const device uchar* ciphertext,
    device uchar* scratch,
    ulong scratch_stride,
    ulong scratch_lane,
    thread uchar priv32[32],
    thread uchar hash160[20],
    thread uchar* result_type) {
    if (precPtr == nullptr || ciphertext == nullptr || target.ciphertext_len != 24u ||
        target.salt_len != 12u || target.iv_len == 0u) return false;
    const uchar flag = target.iv[0];
    if ((flag & ~(0x20u | 0x04u)) != 0u) return false;
    const bool compressed = (flag & 0x20u) != 0u;
    const bool has_lot_sequence = (flag & 0x04u) != 0u;
    const device uchar* address_hash4 = target.salt;
    const device uchar* owner_entropy = target.salt + 4u;
    const uint owner_salt_len = has_lot_sequence ? 4u : 8u;

    uchar prefactor[32];
    if (!walletks_scrypt_sha256_32_params(pass, pass_len, owner_entropy, owner_salt_len,
                                          16384u, 8u, 8u, scratch, scratch_stride,
                                          scratch_lane, prefactor)) return false;
    uchar passfactor[32];
    if (has_lot_sequence) {
        uchar passfactor_input[40];
        for (int i = 0; i < 32; ++i) passfactor_input[i] = prefactor[i];
        for (int i = 0; i < 8; ++i) passfactor_input[32 + i] = owner_entropy[i];
        wallet_bip38_double_sha256(passfactor_input, 40u, passfactor);
    } else {
        for (int i = 0; i < 32; ++i) passfactor[i] = prefactor[i];
    }

    uchar passpoint[33];
    if (!wallet_bip38_passpoint_from_factor(precPtr, precPitch, passfactor, passpoint)) return false;
    uchar derived[64];
    if (!wallet_bip38_scrypt_sha256_64(passpoint, 33u, target.salt, 12u,
                                       1024u, 1u, 1u, scratch, scratch_stride,
                                       scratch_lane, derived)) return false;

    uint round_keys[60];
    provider_aes_expand_key(derived + 32u, round_keys);
    uchar decrypted_part2[16];
    wallet_aes256_decrypt_block(round_keys, ciphertext + 8u, decrypted_part2);
    for (int i = 0; i < 16; ++i) decrypted_part2[i] ^= derived[16 + i];

    uchar encrypted_part1[16];
    for (int i = 0; i < 8; ++i) {
        encrypted_part1[i] = ciphertext[i];
        encrypted_part1[8 + i] = decrypted_part2[i];
    }
    uchar seedb[24];
    uchar decrypted_part1[16];
    wallet_bip38_aes256_decrypt_thread(round_keys, encrypted_part1, decrypted_part1);
    for (int i = 0; i < 16; ++i) seedb[i] = uchar(decrypted_part1[i] ^ derived[i]);
    for (int i = 0; i < 8; ++i) seedb[16 + i] = decrypted_part2[8 + i];

    uchar factorb[32];
    wallet_bip38_double_sha256(seedb, 24u, factorb);
    secp256k1_scalar pass_scalar;
    secp256k1_scalar factor_scalar;
    secp256k1_scalar private_scalar;
    int overflow_a = 0;
    int overflow_b = 0;
    secp256k1_scalar_set_b32(&pass_scalar, passfactor, &overflow_a);
    secp256k1_scalar_set_b32(&factor_scalar, factorb, &overflow_b);
    if (overflow_a != 0 || overflow_b != 0 ||
        secp256k1_scalar_is_zero(&pass_scalar) ||
        secp256k1_scalar_is_zero(&factor_scalar)) return false;
    secp256k1_scalar_mul(&private_scalar, &pass_scalar, &factor_scalar);
    if (secp256k1_scalar_is_zero(&private_scalar)) return false;
    secp256k1_scalar_get_b32(priv32, &private_scalar);
    if (!wallet_bip38_hash160_from_private(precPtr, precPitch, priv32, compressed, hash160) ||
        !wallet_bip38_addresshash_matches(hash160, address_hash4)) return false;
    *result_type = compressed ? 0x02u : 0x01u;
    return true;
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

static inline void wallet_emit_bip38_result(device bool* isResult,
                                            device bool* buffResult,
                                            const thread uchar* pass,
                                            uint pass_len,
                                            uint target_index,
                                            uchar source_profile,
                                            uchar result_type,
                                            const thread uchar priv32[32],
                                            const thread uchar hash160[20],
                                            device WalletModeResult* wallet_results,
                                            device atomic_uint* wallet_count,
                                            uint max_founds) {
    walletks_mark_hit(isResult, buffResult);
    if (wallet_results == nullptr || wallet_count == nullptr) return;
    const ulong ridx = wallet_atomic_add_count(wallet_count, 1u);
    if (ridx >= ulong(max_founds)) return;
    device WalletModeResult& out = wallet_results[ridx];
    wallet_zero_result(out);
    out.mode = WALLET_MODE_BIP38;
    out.type = result_type;
    out.reserved[0] = source_profile;
    out.target_index = target_index;
    walletks_copy_password(out, pass, pass_len);
    for (int i = 0; i < 32; ++i) out.priv[i] = priv32[i];
    for (int i = 0; i < 20; ++i) out.payload[i] = hash160[i];
    out.payload_len = 20u;
}

static inline bool wallet_terra_hash160_from_private(
    const constant secp256k1_ge_storage* precPtr,
    ulong precPitch,
    const thread uchar priv32[32],
    thread uchar out20[20]) {
    uchar pubkey65[65];
    ulong px[4];
    ulong py[4];
    if (!walletks_priv_to_xy(
            precPtr, precPitch, priv32, pubkey65, px, py)) {
        return false;
    }
    int key_len = 0;
    _GetHash160Comp(pubkey65, key_len, out20);
    return true;
}

static inline int wallet_terra_hex_nibble(uchar c) {
    if (c >= uchar('0') && c <= uchar('9')) return int(c - uchar('0'));
    if (c >= uchar('a') && c <= uchar('f')) return int(c - uchar('a')) + 10;
    if (c >= uchar('A') && c <= uchar('F')) return int(c - uchar('A')) + 10;
    return -1;
}

__attribute__((noinline)) static bool wallet_terra_station_verify(
    const constant secp256k1_ge_storage* precPtr,
    ulong precPitch,
    const thread uchar key32[32],
    const device BrowserVaultDeviceTarget& target,
    const device uchar* ciphertext,
    thread uchar priv32[32],
    thread uchar hash160[20]) {
    if (precPtr == nullptr || ciphertext == nullptr ||
        target.iv_len != 16u || target.ciphertext_len != 80u ||
        target.expected_public_len != 20u) {
        return false;
    }
    uint round_keys[60];
    provider_aes_expand_key(key32, round_keys);
    uchar plain[80];
    for (uint block = 0u; block < 5u; ++block) {
        const uint off = block * 16u;
        wallet_aes256_decrypt_block(round_keys, ciphertext + off, plain + off);
        for (uint i = 0u; i < 16u; ++i) {
            const uchar previous = block == 0u
                ? target.iv[i]
                : ciphertext[off - 16u + i];
            plain[off + i] = uchar(plain[off + i] ^ previous);
        }
    }
    for (uint i = 64u; i < 80u; ++i) {
        if (plain[i] != 16u) return false;
    }
    for (uint i = 0u; i < 32u; ++i) {
        const int hi = wallet_terra_hex_nibble(plain[i * 2u]);
        const int lo = wallet_terra_hex_nibble(plain[i * 2u + 1u]);
        if (hi < 0 || lo < 0) return false;
        priv32[i] = uchar((uint(hi) << 4u) | uint(lo));
    }
    if (!wallet_terra_hash160_from_private(
            precPtr, precPitch, priv32, hash160)) {
        return false;
    }
    uchar diff = 0u;
    for (uint i = 0u; i < 20u; ++i) {
        diff |= uchar(hash160[i] ^ target.expected_public[i]);
    }
    return diff == 0u;
}

static inline void wallet_emit_terra_result(
    device bool* isResult,
    device bool* buffResult,
    const thread uchar* pass,
    uint pass_len,
    uint target_index,
    const thread uchar priv32[32],
    const thread uchar hash160[20],
    device WalletModeResult* wallet_results,
    device atomic_uint* wallet_count,
    uint max_founds) {
    walletks_mark_hit(isResult, buffResult);
    if (wallet_results == nullptr || wallet_count == nullptr) return;
    const ulong ridx = wallet_atomic_add_count(wallet_count, 1u);
    if (ridx >= ulong(max_founds)) return;
    device WalletModeResult& out = wallet_results[ridx];
    wallet_zero_result(out);
    out.mode = WALLET_MODE_BROWSERVAULT;
    out.type = BROWSERVAULT_PROFILE_TERRA_STATION_AES_CBC;
    out.target_index = target_index;
    walletks_copy_password(out, pass, pass_len);
    for (uint i = 0u; i < 32u; ++i) out.priv[i] = priv32[i];
    for (uint i = 0u; i < 20u; ++i) out.payload[i] = hash160[i];
    out.payload_len = 20u;
}

__attribute__((noinline)) static bool wallet_bitshares_0x_verify(
    const constant secp256k1_ge_storage* precPtr,
    ulong precPitch,
    const thread uchar key32[32],
    const thread uchar iv16[16],
    const device BrowserVaultDeviceTarget& target,
    const device uchar* ciphertext,
    thread uchar priv32[32],
    thread uchar public33[33]) {
    if (precPtr == nullptr || ciphertext == nullptr ||
        target.iv_len != 0u || target.ciphertext_len != 48u ||
        target.expected_public_len != 33u) {
        return false;
    }
    uint round_keys[60];
    provider_aes_expand_key(key32, round_keys);
    uchar plain[48];
    for (uint block = 0u; block < 3u; ++block) {
        const uint off = block * 16u;
        wallet_aes256_decrypt_block(
            round_keys, ciphertext + off, plain + off);
        for (uint i = 0u; i < 16u; ++i) {
            const uchar previous = block == 0u
                ? iv16[i]
                : ciphertext[off - 16u + i];
            plain[off + i] = uchar(plain[off + i] ^ previous);
        }
    }
    for (uint i = 32u; i < 48u; ++i) {
        if (plain[i] != 16u) return false;
    }
    for (uint i = 0u; i < 32u; ++i) priv32[i] = plain[i];
    if (!walletks_pubkey_from_private(
            precPtr, precPitch, priv32, public33, 33u)) {
        return false;
    }
    uchar diff = 0u;
    for (uint i = 0u; i < 33u; ++i) {
        diff |= uchar(public33[i] ^ target.expected_public[i]);
    }
    return diff == 0u;
}

static inline void wallet_emit_bitshares_result(
    device bool* isResult,
    device bool* buffResult,
    const thread uchar* pass,
    uint pass_len,
    uint target_index,
    const thread uchar priv32[32],
    const thread uchar public33[33],
    device WalletModeResult* wallet_results,
    device atomic_uint* wallet_count,
    uint max_founds) {
    walletks_mark_hit(isResult, buffResult);
    if (wallet_results == nullptr || wallet_count == nullptr) return;
    const ulong ridx = wallet_atomic_add_count(wallet_count, 1u);
    if (ridx >= ulong(max_founds)) return;
    device WalletModeResult& out = wallet_results[ridx];
    wallet_zero_result(out);
    out.mode = WALLET_MODE_BROWSERVAULT;
    out.type = BROWSERVAULT_PROFILE_BITSHARES_0X_AES_CBC;
    out.target_index = target_index;
    walletks_copy_password(out, pass, pass_len);
    for (uint i = 0u; i < 32u; ++i) out.priv[i] = priv32[i];
    for (uint i = 0u; i < 33u; ++i) out.payload[i] = public33[i];
    out.payload_len = 33u;
}

struct YoroiCardanoXprv {
    uchar key[64];
    uchar chain_code[32];
};

static inline void wallet_yoroi_store_le32(
    thread uchar out[4],
    uint value) {
    out[0] = uchar(value);
    out[1] = uchar(value >> 8u);
    out[2] = uchar(value >> 16u);
    out[3] = uchar(value >> 24u);
}

static inline void wallet_yoroi_add_256_le(
    thread uchar out[32],
    const thread uchar a[32],
    const thread uchar b[32]) {
    ushort carry = 0u;
    for (uint i = 0u; i < 32u; ++i) {
        const ushort value =
            ushort(a[i]) + ushort(b[i]) + carry;
        out[i] = uchar(value);
        carry = ushort(value >> 8u);
    }
}

static inline void wallet_yoroi_add_8mul_zl_le(
    thread uchar out[32],
    const thread uchar kl[32],
    const thread uchar zl[32]) {
    ushort carry = 0u;
    for (uint i = 0u; i < 32u; ++i) {
        ushort shifted = 0u;
        if (i < 28u) {
            shifted |= ushort((ushort(zl[i]) << 3u) & 0xffu);
        }
        if (i > 0u && (i - 1u) < 28u) {
            shifted |= ushort(zl[i - 1u] >> 5u);
        }
        const ushort value = ushort(kl[i]) + shifted + carry;
        out[i] = uchar(value);
        carry = ushort(value >> 8u);
    }
}

static inline void wallet_yoroi_ckd_hardened(
    const thread YoroiCardanoXprv& parent,
    thread YoroiCardanoXprv& child,
    uint index) {
    thread uchar index_le[4];
    wallet_yoroi_store_le32(index_le, index);

    thread uchar message[69];
    message[0] = 0x00u;
    for (uint i = 0u; i < 64u; ++i) {
        message[1u + i] = parent.key[i];
    }
    for (uint i = 0u; i < 4u; ++i) {
        message[65u + i] = index_le[i];
    }
    thread uchar z[64];
    HMAC_SHA512(
        parent.chain_code, 32ul, message, 69ul, z);

    message[0] = 0x01u;
    thread uchar next_chain[64];
    HMAC_SHA512(
        parent.chain_code, 32ul, message, 69ul, next_chain);

    wallet_yoroi_add_8mul_zl_le(child.key, parent.key, z);
    wallet_yoroi_add_256_le(
        child.key + 32u, parent.key + 32u, z + 32u);
    for (uint i = 0u; i < 32u; ++i) {
        child.chain_code[i] = next_chain[32u + i];
    }
}

__attribute__((noinline)) static bool wallet_yoroi_emip3_verify(
    const thread uchar key32[32],
    const device BrowserVaultDeviceTarget& target,
    const device uchar* ciphertext,
    thread uchar root_xprv[96]) {
    if (ciphertext == nullptr ||
        target.iv_len != 12u ||
        target.ciphertext_len != 96u ||
        target.expected_public_len != 32u ||
        (target.key_kind & 0x80000000u) == 0u) {
        return false;
    }

    thread uchar nonce[12];
    thread uchar encrypted[96];
    for (uint i = 0u; i < 12u; ++i) nonce[i] = target.iv[i];
    for (uint i = 0u; i < 96u; ++i) encrypted[i] = ciphertext[i];

    thread uchar block0[64];
    thread uchar actual_tag[16];
    chacha20_block(key32, nonce, 0u, block0);
    poly1305_aead_mac_empty_aad(
        block0, encrypted, 96u, actual_tag);
    uchar tag_diff = 0u;
    for (uint i = 0u; i < 16u; ++i) {
        tag_diff |= uchar(actual_tag[i] ^ target.tag[i]);
    }
    if (tag_diff != 0u) return false;

    chacha20_encrypt(
        key32, nonce, 1u, encrypted, root_xprv, 96u);
    if ((root_xprv[0] & 0x07u) != 0u ||
        (root_xprv[31] & 0x80u) != 0u ||
        (root_xprv[31] & 0x40u) == 0u) {
        return false;
    }

    thread YoroiCardanoXprv root;
    thread YoroiCardanoXprv purpose;
    thread YoroiCardanoXprv coin;
    thread YoroiCardanoXprv account;
    for (uint i = 0u; i < 64u; ++i) root.key[i] = root_xprv[i];
    for (uint i = 0u; i < 32u; ++i) {
        root.chain_code[i] = root_xprv[64u + i];
    }
    wallet_yoroi_ckd_hardened(root, purpose, 0x8000073cu);
    wallet_yoroi_ckd_hardened(purpose, coin, 0x80000717u);
    wallet_yoroi_ckd_hardened(coin, account, target.key_kind);

    thread uchar account_public[32];
    cardano_ed25519_publickey_from_scalar(
        account.key, account_public);
    uchar identity_diff = 0u;
    for (uint i = 0u; i < 32u; ++i) {
        identity_diff |= uchar(
            account_public[i] ^ target.expected_public[i]);
        identity_diff |= uchar(
            account.chain_code[i] ^ target.salt[32u + i]);
    }
    return identity_diff == 0u;
}

static inline void wallet_emit_yoroi_result(
    device bool* isResult,
    device bool* buffResult,
    const thread uchar* pass,
    uint pass_len,
    uint target_index,
    const thread uchar root_xprv[96],
    device WalletModeResult* wallet_results,
    device atomic_uint* wallet_count,
    uint max_founds) {
    walletks_mark_hit(isResult, buffResult);
    if (wallet_results == nullptr || wallet_count == nullptr) return;
    const ulong result_index = wallet_atomic_add_count(
        wallet_count, 1u);
    if (result_index >= ulong(max_founds)) return;
    device WalletModeResult& out = wallet_results[result_index];
    wallet_zero_result(out);
    out.mode = WALLET_MODE_BROWSERVAULT;
    out.type = BROWSERVAULT_PROFILE_YOROI_EMIP3;
    out.target_index = target_index;
    walletks_copy_password(out, pass, pass_len);
    for (uint i = 0u; i < 32u; ++i) out.priv[i] = root_xprv[i];
    for (uint i = 0u; i < 64u; ++i) {
        out.payload[i] = root_xprv[32u + i];
    }
    out.payload_len = 64u;
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
            (group.salt_len == 0u &&
             group_profile !=
                 BROWSERVAULT_PROFILE_ETHPRESALE_PBKDF2_AES_CBC &&
             group_profile !=
                 BROWSERVAULT_PROFILE_SUBSTRATE_LEGACY_PKCS8)) {
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
            group_profile == BROWSERVAULT_PROFILE_SUBSTRATE_SCRYPT_PKCS8 ||
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
        } else if (group_profile ==
                   BROWSERVAULT_PROFILE_SUBSTRATE_LEGACY_PKCS8) {
            for (uint i = 0u; i < 32u; ++i) {
                key32[i] = i < pass_len ? pass_local[i] : 0u;
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
        } else if (group_profile == BROWSERVAULT_PROFILE_TERRA_STATION_AES_CBC) {
            wallet_pbkdf2_sha1_32(pass_local, pass_len, group.salt, group.salt_len,
                                  group.iterations, key32);
        } else if (group_profile ==
                   BROWSERVAULT_PROFILE_BITSHARES_0X_AES_CBC) {
            if (group.salt_len != 64u) continue;
            thread uchar digest64[64];
            thread uchar checksum64[64];
            SHA512(pass_local, ulong(pass_len), digest64);
            SHA512(digest64, 64ul, checksum64);
            uchar diff = 0u;
            for (uint i = 0u; i < 64u; ++i) {
                diff |= uchar(checksum64[i] ^ group.salt[i]);
            }
            if (diff != 0u) continue;
            for (uint i = 0u; i < 32u; ++i) key32[i] = digest64[i];
            for (uint i = 0u; i < 16u; ++i) {
                atomic_iv16[i] = digest64[32u + i];
            }
            atomic_key_ready = true;
        } else if (group_profile ==
                   BROWSERVAULT_PROFILE_YOROI_EMIP3) {
            if (group.salt_len != 32u ||
                group.iterations != 19162u) {
                continue;
            }
            fastpbkdf2_hmac_sha512(
                pass_local, ulong(pass_len),
                group.salt, 32ul, 19162ul, key32, 32ul);
        } else if (group_profile == BROWSERVAULT_PROFILE_DOGECHAIN_PBKDF2_AES_CBC) {
            thread uchar pass_sha[32];
            thread uchar pass_b64[44];
            SHA256(pass_local, size_t(pass_len), pass_sha);
            wallet_base64_encode_32_device(pass_sha, pass_b64);
            wallet_dogechain_pbkdf2_sha256_32(pass_b64, group.salt, group.salt_len,
                                              group.iterations, key32);
        } else if (group_profile == BROWSERVAULT_PROFILE_ETHPRESALE_PBKDF2_AES_CBC) {
            wallet_pbkdf2_sha256_32_thread_salt(pass_local, pass_len, pass_local,
                                                pass_len, group.iterations, key32);
        } else if (group_profile == BROWSERVAULT_PROFILE_BIP38_NON_EC) {
#if !ENABLE_BIP38_BROWSER_GPU
            continue;
#endif
        } else if (group_profile == BROWSERVAULT_PROFILE_BIP38_EC) {
#if !ENABLE_BIP38_BROWSER_GPU
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
            } else if (target_profile == BROWSERVAULT_PROFILE_COPAY_SJCL_AES_CCM) {
                ok = wallet_aes128_ccm_l2_tag8_verify(
                    key32, target.iv, target.iv_len, ciphertext,
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
            } else if (target_profile == BROWSERVAULT_PROFILE_TERRA_STATION_AES_CBC) {
                thread uchar priv32[32];
                thread uchar hash160[20];
                if (wallet_terra_station_verify(
                        precPtr, precPitch, key32, target, ciphertext,
                        priv32, hash160)) {
                    wallet_emit_terra_result(
                        isResult, buffResult, pass_local, pass_len,
                        target.target_index, priv32, hash160,
                        wallet_results, wallet_count, max_founds);
                }
                continue;
            } else if (target_profile ==
                       BROWSERVAULT_PROFILE_BITSHARES_0X_AES_CBC) {
                if (!atomic_key_ready) continue;
                thread uchar priv32[32];
                thread uchar public33[33];
                if (wallet_bitshares_0x_verify(
                        precPtr, precPitch, key32, atomic_iv16,
                        target, ciphertext, priv32, public33)) {
                    wallet_emit_bitshares_result(
                        isResult, buffResult, pass_local, pass_len,
                        target.target_index, priv32, public33,
                        wallet_results, wallet_count, max_founds);
                }
                continue;
            } else if (target_profile ==
                       BROWSERVAULT_PROFILE_YOROI_EMIP3) {
                thread uchar root_xprv[96];
                if (wallet_yoroi_emip3_verify(
                        key32, target, ciphertext, root_xprv)) {
                    wallet_emit_yoroi_result(
                        isResult, buffResult,
                        pass_local, pass_len,
                        target.target_index, root_xprv,
                        wallet_results, wallet_count, max_founds);
                }
                continue;
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
#if ENABLE_BIP38_BROWSER_GPU
                thread uchar priv32[32];
                thread uchar hash160[20];
                uchar result_type = 0u;
                if (wallet_bip38_non_ec_verify(precPtr, precPitch, pass_local, pass_len,
                                               target, ciphertext, scrypt_scratch,
                                               scrypt_scratch_stride, ulong(tid),
                                               priv32, hash160, &result_type)) {
                    wallet_emit_bip38_result(isResult, buffResult, pass_local, pass_len,
                                             target.target_index, uchar(target.profile),
                                             result_type, priv32, hash160, wallet_results,
                                             wallet_count, max_founds);
                }
#endif
                continue;
            } else if (target_profile == BROWSERVAULT_PROFILE_BIP38_EC) {
#if ENABLE_BIP38_BROWSER_GPU
                thread uchar priv32[32];
                thread uchar hash160[20];
                uchar result_type = 0u;
                if (wallet_bip38_ec_verify(precPtr, precPitch, pass_local, pass_len,
                                           target, ciphertext, scrypt_scratch,
                                           scrypt_scratch_stride, ulong(tid),
                                           priv32, hash160, &result_type)) {
                    wallet_emit_bip38_result(isResult, buffResult, pass_local, pass_len,
                                             target.target_index, uchar(target.profile),
                                             result_type, priv32, hash160, wallet_results,
                                             wallet_count, max_founds);
                }
#endif
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
            } else if (
                target_profile ==
                    BROWSERVAULT_PROFILE_SUBSTRATE_SCRYPT_PKCS8 ||
                target_profile ==
                    BROWSERVAULT_PROFILE_SUBSTRATE_LEGACY_PKCS8) {
                ok = wallet_substrate_secretbox_pkcs8_verify(
                    precPtr, precPitch, key32, target, ciphertext);
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
