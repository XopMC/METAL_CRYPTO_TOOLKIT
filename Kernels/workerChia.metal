#include "ChiaCommon.metalh"

kernel void workerChiaSeed(
    const device char* mnemonic_data [[buffer(0)]],
    const device ushort* mnemonic_lengths [[buffer(1)]],
    const device uchar* salt_data [[buffer(2)]],
    const device ushort* salt_lengths [[buffer(3)]],
    constant ulong& candidate_count [[buffer(4)]],
    device uchar* seeds [[buffer(5)]],
    uint tid [[thread_position_in_grid]],
    uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || threads == 0u) return;
    for (ulong lane = ulong(tid); lane < candidate_count;
         lane += ulong(threads)) {
        const uint mnemonic_length =
            uint(mnemonic_lengths[lane]);
        const uint salt_length = uint(salt_lengths[lane]);
        if (mnemonic_length >= CHIA_MNEMONIC_STRIDE ||
            salt_length >= CHIA_SALT_STRIDE) {
            continue;
        }
        const device uchar* mnemonic =
            reinterpret_cast<const device uchar*>(
                mnemonic_data +
                lane * CHIA_MNEMONIC_STRIDE);
        const device uchar* salt =
            salt_data + lane * CHIA_SALT_STRIDE;
        uchar seed[64];
        fastpbkdf2_hmac_sha512(
            mnemonic, ulong(mnemonic_length),
            salt, ulong(salt_length), 2048ul,
            seed, 64ul);
        device uchar* output = seeds + lane * 64ul;
        for (uint index = 0u; index < 64u; ++index) {
            output[index] = seed[index];
        }
    }
}
