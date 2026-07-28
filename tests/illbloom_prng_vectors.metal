#include "../Kernels/PrngCommon.metalh"

constant int kIllBloomMaxEntropyBytes = 64;
constant int kIllBloomTestGen [[function_constant(0)]];
constant int kIllBloomTestMode [[function_constant(1)]];
constant int kIllBloomTestEntropyLen [[function_constant(2)]];
constant int kIllBloomTestPackedFamily [[function_constant(3)]];

struct IllBloomTestInput {
    uint seed;
    int gen_public;
    int mode_public;
    int entropy_len;
};

struct IllBloomTestOutput {
    int ok;
    uchar entropy[kIllBloomMaxEntropyBytes];
};

struct IllBloomPackedTestInput {
    ulong packed_index;
    uint seed;
    int legacy_gen_public;
    int legacy_mode_public;
    int entropy_len;
    int packed_gen_public;
    int padding;
};

struct IllBloomPackedTestOutput {
    int legacy_ok;
    int packed_ok;
    uchar legacy_entropy[kIllBloomMaxEntropyBytes];
    uchar packed_entropy[kIllBloomMaxEntropyBytes];
};

struct IllBloomPackedBehaviorOutput {
    int direct16_ok;
    int direct32_ok;
    int mode1_16_ok;
    int mode1_32_ok;
    int mode8_16_ok;
    int mode217_16_ok;
    int shifted16_ok;
    uchar direct16[kIllBloomMaxEntropyBytes];
    uchar direct32[kIllBloomMaxEntropyBytes];
    uchar mode1_16[kIllBloomMaxEntropyBytes];
    uchar mode1_32[kIllBloomMaxEntropyBytes];
    uchar mode8_16[kIllBloomMaxEntropyBytes];
    uchar mode217_16[kIllBloomMaxEntropyBytes];
    uchar shifted16[kIllBloomMaxEntropyBytes];
};

static inline bool illbloom_fill_exhaustive_raw_mask(
    thread uchar* entropy,
    uint seed,
    int gen_public,
    int mode_public,
    int entropy_len) {
    if (gen_public < 340 || gen_public > 467 ||
        mode_public < 251 || mode_public > 762 ||
        entropy_len <= 0 || entropy_len > kIllBloomMaxEntropyBytes) {
        return false;
    }

    const uint chain_sign_mask = uint(gen_public - 340);
    const int encoded = mode_public - 251;
    const bool big_endian = encoded < 256;
    const uint output_sign_mask = uint(encoded & 255);
    Prng32IllBloomRawChainMask gen(seed, chain_sign_mask);
    int byte_index = 0;
    uint word_index = 0u;
    while (byte_index < entropy_len) {
        uint word = gen.next();
        if (((output_sign_mask >> (word_index & 7u)) & 1u) == 0u) {
            word = 0u - word;
        }
        ++word_index;
        if (big_endian) {
            for (int byte = 3; byte >= 0 && byte_index < entropy_len; --byte) {
                entropy[byte_index++] = uchar(word >> uint(byte * 8));
            }
        } else {
            for (int byte = 0; byte < 4 && byte_index < entropy_len; ++byte) {
                entropy[byte_index++] = uchar(word >> uint(byte * 8));
            }
        }
    }
    return true;
}

static inline void illbloom_write_packed_behavior(
    device IllBloomPackedBehaviorOutput* output) {
    uchar direct16[kIllBloomMaxEntropyBytes] = {};
    uchar direct32[kIllBloomMaxEntropyBytes] = {};
    uchar mode1_16[kIllBloomMaxEntropyBytes] = {};
    uchar mode1_32[kIllBloomMaxEntropyBytes] = {};
    uchar mode8_16[kIllBloomMaxEntropyBytes] = {};
    uchar mode217_16[kIllBloomMaxEntropyBytes] = {};
    uchar shifted16[kIllBloomMaxEntropyBytes] = {};
    const ulong selector = 3ul | (0xa5ul << 7u);
    const ulong packed_index = (selector << 32u) | 0x12345678ul;
    const int family = 0;

    output->direct16_ok = prng64_illbloom_packed_fill(
        16, direct16, packed_index, 218 - 1, family, 0ul) ? 1 : 0;
    output->direct32_ok = prng64_illbloom_packed_fill(
        32, direct32, packed_index, 218 - 1, family, 0ul) ? 1 : 0;
    output->mode1_16_ok = prng64_illbloom_packed_fill(
        16, mode1_16, packed_index, 1 - 1, family, 0ul) ? 1 : 0;
    output->mode1_32_ok = prng64_illbloom_packed_fill(
        32, mode1_32, packed_index, 1 - 1, family, 0ul) ? 1 : 0;
    output->mode8_16_ok = prng64_illbloom_packed_fill(
        16, mode8_16, packed_index, 8 - 1, family, 0ul) ? 1 : 0;
    output->mode217_16_ok = prng64_illbloom_packed_fill(
        16, mode217_16, packed_index, 217 - 1, family, 0ul) ? 1 : 0;
    output->shifted16_ok = prng64_illbloom_packed_fill(
        16, shifted16, packed_index, 218 - 1, family, 1ul) ? 1 : 0;

    for (int byte = 0; byte < kIllBloomMaxEntropyBytes; ++byte) {
        output->direct16[byte] = direct16[byte];
        output->direct32[byte] = direct32[byte];
        output->mode1_16[byte] = mode1_16[byte];
        output->mode1_32[byte] = mode1_32[byte];
        output->mode8_16[byte] = mode8_16[byte];
        output->mode217_16[byte] = mode217_16[byte];
        output->shifted16[byte] = shifted16[byte];
    }
}

kernel void illbloom_generate_vectors(
    const device IllBloomTestInput* inputs [[buffer(0)]],
    device IllBloomTestOutput* outputs [[buffer(1)]],
    constant uint& count [[buffer(2)]],
    uint index [[thread_position_in_grid]]) {
    if (index >= count) {
        return;
    }

    uchar entropy[kIllBloomMaxEntropyBytes] = {};
    const IllBloomTestInput input = inputs[index];
    outputs[index].ok = prng32_entropy_fill(
        kIllBloomTestEntropyLen,
        entropy,
        input.seed,
        kIllBloomTestMode,
        kIllBloomTestGen,
        0ul) ? 1 : 0;
    for (int byte = 0; byte < kIllBloomMaxEntropyBytes; ++byte) {
        outputs[index].entropy[byte] = entropy[byte];
    }
}

kernel void illbloom_generate_exhaustive_masks(
    const device IllBloomTestInput* inputs [[buffer(0)]],
    device IllBloomTestOutput* outputs [[buffer(1)]],
    constant uint& count [[buffer(2)]],
    uint index [[thread_position_in_grid]]) {
    if (index >= count) {
        return;
    }

    uchar entropy[kIllBloomMaxEntropyBytes] = {};
    const IllBloomTestInput input = inputs[index];
    outputs[index].ok = illbloom_fill_exhaustive_raw_mask(
        entropy,
        input.seed,
        input.gen_public,
        input.mode_public,
        input.entropy_len) ? 1 : 0;
    for (int byte = 0; byte < kIllBloomMaxEntropyBytes; ++byte) {
        outputs[index].entropy[byte] = entropy[byte];
    }
}

kernel void illbloom_compare_packed_vectors(
    const device IllBloomPackedTestInput* inputs [[buffer(0)]],
    device IllBloomPackedTestOutput* outputs [[buffer(1)]],
    constant uint& count [[buffer(2)]],
    device IllBloomPackedBehaviorOutput* behavior [[buffer(3)]],
    uint index [[thread_position_in_grid]]) {
    if (index >= count) {
        return;
    }

    uchar legacy_entropy[kIllBloomMaxEntropyBytes] = {};
    uchar packed_entropy[kIllBloomMaxEntropyBytes] = {};
    const IllBloomPackedTestInput input = inputs[index];
    outputs[index].legacy_ok = prng32_entropy_fill(
        kIllBloomTestEntropyLen,
        legacy_entropy,
        input.seed,
        kIllBloomTestMode,
        kIllBloomTestGen,
        0ul) ? 1 : 0;
    outputs[index].packed_ok = prng64_illbloom_packed_fill(
        kIllBloomTestEntropyLen,
        packed_entropy,
        input.packed_index,
        218 - 1,
        kIllBloomTestPackedFamily,
        0ul) ? 1 : 0;
    for (int byte = 0; byte < kIllBloomMaxEntropyBytes; ++byte) {
        outputs[index].legacy_entropy[byte] = legacy_entropy[byte];
        outputs[index].packed_entropy[byte] = packed_entropy[byte];
    }
    if (index == 0u) {
        illbloom_write_packed_behavior(behavior);
    }
}
