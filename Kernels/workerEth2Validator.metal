#include "Eth2ValidatorCommon.metalh"

kernel void workerEth2Validator(
    const device Eth2ValidatorTarget* targets [[buffer(0)]],
    constant ulong& target_window [[buffer(1)]],
    const device uchar* solved_flags [[buffer(2)]],
    const device char* password_data [[buffer(3)]],
    const device uchar* password_lengths [[buffer(4)]],
    constant ulong& candidate_base [[buffer(5)]],
    constant ulong& candidate_count [[buffer(6)]],
    device uchar* scrypt_scratch [[buffer(7)]],
    constant ulong& scrypt_scratch_stride [[buffer(8)]],
    device Eth2ValidatorHit* hits [[buffer(9)]],
    device atomic_uint* hit_count [[buffer(10)]],
    constant uint& hit_capacity [[buffer(11)]],
    uint tid [[thread_position_in_grid]],
    uint threads [[threads_per_grid]]) {
    const uint target_begin = uint(target_window);
    const uint target_end = uint(target_window >> 32u);
    if (target_begin >= target_end || candidate_count == 0ul ||
        threads == 0u) {
        return;
    }
    for (ulong lane = ulong(tid); lane < candidate_count;
         lane += ulong(threads)) {
        const uint password_len =
            uint(password_lengths[lane]);
        if (password_len >= ETH2_PASSWORD_STRIDE) continue;
        uchar password[ETH2_PASSWORD_STRIDE];
        for (uint i = 0u; i < password_len; ++i) {
            password[i] =
                uchar(password_data[
                    lane * ETH2_PASSWORD_STRIDE + i]);
        }
        for (uint target_index = target_begin;
             target_index < target_end; ++target_index) {
            if (solved_flags != nullptr &&
                solved_flags[target_index] != 0u) {
                continue;
            }
            const device Eth2ValidatorTarget& target =
                targets[target_index];
            uchar derived_key[32];
            if (target.kdf_type == ETH2_KDF_PBKDF2_SHA256) {
                wallet_pbkdf2_sha256_32(
                    password, password_len,
                    target.salt, target.salt_len,
                    target.iterations, derived_key);
            } else if (target.kdf_type == ETH2_KDF_SCRYPT) {
                if (!walletks_scrypt_sha256_32_params(
                        password, password_len,
                        target.salt, target.salt_len,
                        target.scrypt_n, target.scrypt_r,
                        target.scrypt_p, scrypt_scratch,
                        scrypt_scratch_stride, lane,
                        derived_key)) {
                    continue;
                }
            } else {
                continue;
            }

            uchar preimage[48];
            for (uint i = 0u; i < 16u; ++i) {
                preimage[i] = derived_key[16u + i];
            }
            for (uint i = 0u; i < 32u; ++i) {
                preimage[16u + i] = target.ciphertext[i];
            }
            uchar checksum[32];
            SHA256(preimage, 48u, checksum);
            if (!eth2_equal_32(checksum, target.checksum)) {
                continue;
            }

            uchar secret[32];
            walletks_aes128_ctr_xor(
                derived_key, target.iv,
                target.ciphertext, 32u, secret);
            eth2_emit_hit(
                candidate_base + lane, target.target_index,
                password, password_len, derived_key, secret,
                hits, hit_count, hit_capacity);
        }
    }
}

kernel void workerEth2Mnemonic(
    const device char* mnemonic_data [[buffer(0)]],
    const device ushort* mnemonic_lengths [[buffer(1)]],
    constant ulong& mnemonic_count [[buffer(2)]],
    const device uchar* salt [[buffer(3)]],
    constant uint& salt_length [[buffer(4)]],
    device uchar* seeds [[buffer(5)]],
    uint tid [[thread_position_in_grid]],
    uint threads [[threads_per_grid]]) {
    if (mnemonic_count == 0ul || threads == 0u ||
        salt_length >= ETH2_MNEMONIC_STRIDE) {
        return;
    }
    for (ulong lane = ulong(tid); lane < mnemonic_count;
         lane += ulong(threads)) {
        const uint mnemonic_length =
            uint(mnemonic_lengths[lane]);
        if (mnemonic_length >= ETH2_MNEMONIC_STRIDE) continue;
        const device uchar* mnemonic =
            reinterpret_cast<const device uchar*>(
                mnemonic_data +
                lane * ETH2_MNEMONIC_STRIDE);
        device uchar* output = seeds + lane * 64ul;
        uchar seed[64];
        fastpbkdf2_hmac_sha512(
            mnemonic, ulong(mnemonic_length),
            salt, ulong(salt_length), 2048ul,
            seed, 64ul);
        for (uint i = 0u; i < 64u; ++i) {
            output[i] = seed[i];
        }
    }
}
