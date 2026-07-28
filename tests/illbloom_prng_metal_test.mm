#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace {

constexpr int kMaxEntropyBytes = 64;

struct TestInput {
    uint32_t seed;
    int32_t gen_public;
    int32_t mode_public;
    int32_t entropy_len;
};

struct TestOutput {
    int32_t ok;
    uint8_t entropy[kMaxEntropyBytes];
};

struct TestVector {
    TestInput input;
    const char* expected_hex;
};

struct PackedTestInput {
    uint64_t packed_index;
    uint32_t seed;
    int32_t legacy_gen_public;
    int32_t legacy_mode_public;
    int32_t entropy_len;
    int32_t packed_gen_public;
    int32_t padding;
};

struct PackedTestOutput {
    int32_t legacy_ok;
    int32_t packed_ok;
    uint8_t legacy_entropy[kMaxEntropyBytes];
    uint8_t packed_entropy[kMaxEntropyBytes];
};

struct PackedBehaviorOutput {
    int32_t direct16_ok;
    int32_t direct32_ok;
    int32_t mode1_16_ok;
    int32_t mode1_32_ok;
    int32_t mode8_16_ok;
    int32_t mode217_16_ok;
    int32_t shifted16_ok;
    uint8_t direct16[kMaxEntropyBytes];
    uint8_t direct32[kMaxEntropyBytes];
    uint8_t mode1_16[kMaxEntropyBytes];
    uint8_t mode1_32[kMaxEntropyBytes];
    uint8_t mode8_16[kMaxEntropyBytes];
    uint8_t mode217_16[kMaxEntropyBytes];
    uint8_t shifted16[kMaxEntropyBytes];
};

struct PipelineConstants {
    int32_t gen;
    int32_t mode;
    int32_t entropy_len;
    int32_t packed_family;
};

static_assert(sizeof(TestInput) == 16);
static_assert(sizeof(TestOutput) == 68);
static_assert(sizeof(PackedTestInput) == 32);
static_assert(sizeof(PackedTestOutput) == 136);
static_assert(sizeof(PackedBehaviorOutput) == 476);

class MetalHarness {
public:
    bool open(const char* metallib_path) {
        device_ = MTLCreateSystemDefaultDevice();
        if (device_ == nil) {
            std::cerr << "No Metal device is available\n";
            return false;
        }
        NSError* error = nil;
        NSString* path = [NSString stringWithUTF8String:metallib_path];
        NSURL* url = [NSURL fileURLWithPath:path];
        library_ = [device_ newLibraryWithURL:url error:&error];
        if (library_ == nil) {
            std::cerr << "newLibraryWithURL: "
                      << (error ? [[error localizedDescription] UTF8String] : "unknown error")
                      << "\n";
            return false;
        }
        queue_ = [device_ newCommandQueue];
        if (queue_ == nil) {
            std::cerr << "newCommandQueue failed\n";
            return false;
        }
        return true;
    }

    id<MTLBuffer> buffer(const void* bytes, std::size_t size) {
        return [device_ newBufferWithBytes:bytes
                                    length:size
                                   options:MTLResourceStorageModeShared];
    }

    id<MTLBuffer> empty_buffer(std::size_t size) {
        id<MTLBuffer> result = [device_ newBufferWithLength:size
                                                    options:MTLResourceStorageModeShared];
        if (result != nil) {
            std::memset([result contents], 0, size);
        }
        return result;
    }

    bool run(const char* function_name,
             const std::vector<id<MTLBuffer>>& buffers,
             std::size_t threads,
             const PipelineConstants* constants = nullptr) {
        id<MTLComputePipelineState> pipeline =
            constants == nullptr ? exhaustive_pipeline_ : nil;
        if (pipeline == nil) {
            NSError* error = nil;
            NSString* name = [NSString stringWithUTF8String:function_name];
            id<MTLFunction> function = nil;
            if (constants != nullptr) {
                MTLFunctionConstantValues* values =
                    [[MTLFunctionConstantValues alloc] init];
                int32_t value = constants->gen;
                [values setConstantValue:&value type:MTLDataTypeInt atIndex:0];
                value = constants->mode;
                [values setConstantValue:&value type:MTLDataTypeInt atIndex:1];
                value = constants->entropy_len;
                [values setConstantValue:&value type:MTLDataTypeInt atIndex:2];
                value = constants->packed_family;
                [values setConstantValue:&value type:MTLDataTypeInt atIndex:3];
                function = [library_ newFunctionWithName:name
                                          constantValues:values
                                                   error:&error];
            } else {
                function = [library_ newFunctionWithName:name];
            }
            if (function == nil) {
                std::cerr << "Missing/specialization failure for Metal function "
                          << function_name << ": "
                          << (error ? [[error localizedDescription] UTF8String]
                                    : "unknown error")
                          << "\n";
                return false;
            }
            pipeline =
                [device_ newComputePipelineStateWithFunction:function error:&error];
            if (pipeline == nil) {
                std::cerr << "newComputePipelineState(" << function_name << "): "
                          << (error ? [[error localizedDescription] UTF8String] : "unknown error")
                          << "\n";
                return false;
            }
            if (constants == nullptr) {
                exhaustive_pipeline_ = pipeline;
            }
        }
        id<MTLCommandBuffer> command = [queue_ commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (command == nil || encoder == nil) {
            std::cerr << "Metal command allocation failed\n";
            return false;
        }
        [encoder setComputePipelineState:pipeline];
        for (NSUInteger index = 0; index < buffers.size(); ++index) {
            [encoder setBuffer:buffers[index] offset:0 atIndex:index];
        }
        const NSUInteger width =
            std::min<NSUInteger>(pipeline.maxTotalThreadsPerThreadgroup, 256u);
        [encoder dispatchThreads:MTLSizeMake(threads, 1, 1)
          threadsPerThreadgroup:MTLSizeMake(width, 1, 1)];
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            std::cerr << "Metal command failed: "
                      << (command.error
                              ? [[command.error localizedDescription] UTF8String]
                              : "unknown error")
                      << "\n";
            return false;
        }
        return true;
    }

private:
    id<MTLDevice> device_ = nil;
    id<MTLLibrary> library_ = nil;
    id<MTLCommandQueue> queue_ = nil;
    id<MTLComputePipelineState> exhaustive_pipeline_ = nil;
};

int hex_digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

std::vector<uint8_t> parse_hex(const char* text) {
    const std::string value(text);
    if ((value.size() & 1u) != 0u) return {};
    std::vector<uint8_t> result(value.size() / 2);
    for (std::size_t i = 0; i < result.size(); ++i) {
        const int high = hex_digit(value[i * 2]);
        const int low = hex_digit(value[i * 2 + 1]);
        if (high < 0 || low < 0) return {};
        result[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return result;
}

bool generate_on_metal(MetalHarness& metal,
                       const std::vector<TestInput>& inputs,
                       std::vector<TestOutput>& outputs,
                       bool exhaustive = false) {
    outputs.resize(inputs.size());
    const uint32_t count = static_cast<uint32_t>(inputs.size());
    id<MTLBuffer> input_buffer =
        metal.buffer(inputs.data(), inputs.size() * sizeof(TestInput));
    id<MTLBuffer> output_buffer =
        metal.empty_buffer(outputs.size() * sizeof(TestOutput));
    id<MTLBuffer> count_buffer = metal.buffer(&count, sizeof(count));
    if (input_buffer == nil || output_buffer == nil || count_buffer == nil) {
        std::cerr << "Metal test buffer allocation failed\n";
        return false;
    }
    PipelineConstants constants{};
    const PipelineConstants* constants_ptr = nullptr;
    const char* function_name = "illbloom_generate_exhaustive_masks";
    if (!exhaustive) {
        if (inputs.empty()) {
            return true;
        }
        constants = {
            inputs.front().gen_public - 1,
            inputs.front().mode_public - 1,
            inputs.front().entropy_len,
            0,
        };
        constants_ptr = &constants;
        function_name = "illbloom_generate_vectors";
    }
    if (!metal.run(function_name,
                   {input_buffer, output_buffer, count_buffer},
                   inputs.size(),
                   constants_ptr)) {
        return false;
    }
    std::memcpy(outputs.data(), [output_buffer contents],
                outputs.size() * sizeof(TestOutput));
    return true;
}

bool compare_packed_on_metal(MetalHarness& metal,
                             const std::vector<PackedTestInput>& inputs,
                             std::vector<PackedTestOutput>& outputs,
                             PackedBehaviorOutput& behavior) {
    outputs.resize(inputs.size());
    const uint32_t count = static_cast<uint32_t>(inputs.size());
    id<MTLBuffer> input_buffer =
        metal.buffer(inputs.data(), inputs.size() * sizeof(PackedTestInput));
    id<MTLBuffer> output_buffer =
        metal.empty_buffer(outputs.size() * sizeof(PackedTestOutput));
    id<MTLBuffer> count_buffer = metal.buffer(&count, sizeof(count));
    id<MTLBuffer> behavior_buffer = metal.empty_buffer(sizeof(behavior));
    if (input_buffer == nil || output_buffer == nil || count_buffer == nil
        || behavior_buffer == nil) {
        std::cerr << "Metal packed-test buffer allocation failed\n";
        return false;
    }
    if (inputs.empty()) {
        return true;
    }
    const PipelineConstants constants = {
        inputs.front().legacy_gen_public - 1,
        inputs.front().legacy_mode_public - 1,
        inputs.front().entropy_len,
        inputs.front().packed_gen_public - 221,
    };
    if (!metal.run("illbloom_compare_packed_vectors",
                   {input_buffer, output_buffer, count_buffer, behavior_buffer},
                   inputs.size(),
                   &constants)) {
        return false;
    }
    std::memcpy(outputs.data(), [output_buffer contents],
                outputs.size() * sizeof(PackedTestOutput));
    std::memcpy(&behavior, [behavior_buffer contents], sizeof(behavior));
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    @autoreleasepool {
        const char* metallib_path =
            argc > 1 ? argv[1] : "build/tests/illbloom_prng_vectors.metallib";
        MetalHarness metal;
        if (!metal.open(metallib_path)) {
            return EXIT_FAILURE;
        }

        const std::array<TestVector, 40> vectors = {{
            {{0u, 332, 247, 16}, "7123000046089b516efdc72c6af30279"},
            {{0u, 332, 248, 16}, "00002371519b08462cc7fd6e7902f36a"},
            {{0u, 333, 247, 16}, "8edd0000aa129b50c76d6f74c362aac2"},
            {{0u, 334, 247, 32}, "6a339bff3f4a0cef6faed87c3c173a113250512a43378f266b70ca944a723d4a"},
            {{0u, 335, 247, 32}, "6a339bff3f4a0cef6faed87c3c173a113250512a43378f26948f356cae7c3d49"},
            {{0u, 336, 247, 16}, "c658849831c1c9a56388100338ac98db"},
            {{0u, 337, 247, 16}, "00000004020000040400000404004000"},
            {{0u, 337, 249, 16}, "00020404020214181610141a08092bc0"},
            {{0u, 337, 250, 16}, "04040400204c34303430452645bd9864"},
            {{0x12345678u, 338, 247, 32}, "48d17e0c8cd867b459eb85e6f4eba926d863bada017f9f7d7c6259741d3cb37d"},
            {{0u, 339, 247, 16}, "49616e42010525e5b9ad036e50e3bf84"},
            {{0u, 340, 251, 16}, "7123000046089b516efdc72c6af30279"},
            {{0u, 347, 266, 16}, "8edd0000aa129b50c76d6f74c362aac2"},
            {{0u, 340, 507, 16}, "00002371519b08462cc7fd6e7902f36a"},
            {{0u, 468, 247, 16}, "7123000046089b516efdc72c6af30279"},
            {{0u, 469, 247, 16}, "6a339bff3f4a0cef6faed87c3c173a11"},
            {{0u, 470, 247, 16}, "7123000046089b516efdc72c6af30279"},
            {{0u, 471, 247, 16}, "7123000046089b516efdc72c6af30279"},
            {{0u, 472, 247, 16}, "6a339bff3f4a0cef6faed87c3c173a11"},
            {{0u, 473, 247, 16}, "7123000046089b516efdc72c6af30279"},
            {{0u, 474, 247, 16}, "00000000000000000000400000008000"},
            {{0u, 475, 247, 16}, "00000004000000040200000404000004"},
            {{0u, 476, 247, 16}, "00000000000040000000800000008008"},
            {{0u, 477, 247, 16}, "00000000000000000000400000008000"},
            {{0u, 478, 247, 16}, "00000004000000040200000404000004"},
            {{0u, 479, 247, 16}, "00000000000040000000800000008008"},
            {{0u, 480, 247, 16}, "6d2ef87ac5b332b794d4662199a12f31"},
            {{0u, 481, 247, 16}, "15c4afc2e440a2fc308f824665e3e0b2"},
            {{0u, 482, 247, 16}, "949fef90b98d42895d4241509ebae88a"},
            {{0u, 483, 247, 16}, "638a13cbb680383d9dd57291a7110718"},
            {{0u, 484, 247, 16}, "b5e6ac80d482adbba779d239357ecc7d"},
            {{0u, 485, 247, 16}, "ae41db26b63ba2ff9cbc0faa6a3cadab"},
            {{0u, 486, 247, 16}, "6e59971dbf96d6e2b3cdf5df474f6229"},
            {{0u, 487, 247, 16}, "64b5720b64b5721205a5f1a76823da19"},
            {{0u, 488, 247, 16}, "2b16f8bc3142d1c53b656bc99cbd1df3"},
            {{0u, 489, 247, 16}, "2f5885df1a0a4c095455aacf44e679aa"},
            // Independent ECMAScript binary64 checks for the integer Metal
            // emulation of Hermes minstd_rand/generate_canonical.
            {{0x12345678u, 480, 247, 32}, "61bb3d51ce43e9573419639a5bf4ceea35e168df383a1f19b026a571cb8b0d11"},
            {{0x12345678u, 481, 247, 32}, "c626cb33844acc8e62289e3d86f2d4719eeb34dfa01b82830a04a975a4bac884"},
            {{0x7ffffffeu, 480, 247, 32}, "bde91f7952a1d0a253b645765804a9ddc23acc442d10d7b1b6da897252cc1d95"},
            {{0x7ffffffeu, 481, 247, 32}, "ea3b503d1bbf5d03cf707db99a1c1f4d41a92b00708a492130c03d637d0067f8"},
        }};

        bool passed = true;
        for (std::size_t index = 0; index < vectors.size(); ++index) {
            const std::vector<TestInput> single_input{vectors[index].input};
            std::vector<TestOutput> output;
            if (!generate_on_metal(metal, single_input, output)) {
                return EXIT_FAILURE;
            }
            const std::vector<uint8_t> expected =
                parse_hex(vectors[index].expected_hex);
            const TestInput& input = vectors[index].input;
            bool match = output.front().ok != 0
                && expected.size() == static_cast<std::size_t>(input.entropy_len);
            for (int byte = 0; match && byte < input.entropy_len; ++byte) {
                match = output.front().entropy[byte]
                    == expected[static_cast<std::size_t>(byte)];
            }
            if (!match) {
                passed = false;
                std::cerr << "vector failed: gen=" << input.gen_public
                          << " mode=" << input.mode_public
                          << " seed=0x" << std::hex << input.seed << std::dec
                          << " actual=";
                for (int byte = 0; byte < input.entropy_len; ++byte) {
                    std::cerr << std::hex << std::setw(2) << std::setfill('0')
                              << static_cast<unsigned>(output.front().entropy[byte]);
                }
                std::cerr << std::dec << "\n";
            }
        }

        struct ExhaustiveProfile {
            int entropy_len;
            int last_gen;
            int last_mode;
            std::size_t expected;
        };
        const std::array<ExhaustiveProfile, 5> profiles = {{
            {16, 347, 266, 128u},
            {20, 355, 282, 512u},
            {24, 371, 314, 2048u},
            {28, 403, 378, 8192u},
            {32, 467, 506, 32768u},
        }};
        std::size_t largest_unique_count = 0;
        for (const ExhaustiveProfile& profile : profiles) {
            std::vector<TestInput> exhaustive_inputs;
            exhaustive_inputs.reserve(profile.expected);
            for (int gen = 340; gen <= profile.last_gen; ++gen) {
                for (int mode = 251; mode <= profile.last_mode; ++mode) {
                    exhaustive_inputs.push_back(
                        {0u, gen, mode, profile.entropy_len});
                }
            }
            std::vector<TestOutput> exhaustive_outputs;
            if (!generate_on_metal(
                    metal, exhaustive_inputs, exhaustive_outputs, true)) {
                return EXIT_FAILURE;
            }

            std::set<std::array<uint8_t, kMaxEntropyBytes>> unique_entropy;
            for (const TestOutput& output : exhaustive_outputs) {
                if (output.ok == 0) {
                    passed = false;
                    break;
                }
                std::array<uint8_t, kMaxEntropyBytes> value{};
                for (int byte = 0; byte < profile.entropy_len; ++byte) {
                    value[static_cast<std::size_t>(byte)] =
                        output.entropy[byte];
                }
                unique_entropy.insert(value);
            }
            if (unique_entropy.size() != profile.expected) {
                passed = false;
                std::cerr << "exhaustive mask uniqueness failed for "
                          << profile.entropy_len << " bytes: expected "
                          << profile.expected << ", got "
                          << unique_entropy.size() << "\n";
            }
            largest_unique_count = unique_entropy.size();
        }

        const std::array<PackedTestInput, 13> packed_vectors = {{
            {0x0000000000000000ull, 0u, 340, 251, 16, 221, 0},
            {0x0000800000000000ull, 0u, 340, 507, 16, 221, 0},
            {(32640ull << 32), 0u, 340, 247, 16, 221, 0},
            {(65408ull << 32), 0u, 340, 248, 16, 221, 0},
            {(5393ull << 32) | 0x12345678ull, 0x12345678u, 357, 293, 24, 221, 0},
            {0x0000ffffffffffffull, 0xffffffffu, 467, 762, 32, 221, 0},
            {0x0000ffff31415926ull, 0x31415926u, 467, 762, 40, 221, 0},
            {0x0000000000000000ull, 0u, 332, 247, 16, 222, 0},
            {(31ull << 32) | 0x89abcdefull, 0x89abcdefu, 339, 250, 24, 222, 0},
            {(34ull << 32) | 0x10203040ull, 0x10203040u, 468, 249, 20, 222, 0},
            {(117ull << 32) | 0x76543210ull, 0x76543210u, 489, 248, 28, 222, 0},
            {0x0000000000000000ull, 0u, 340, 249, 16, 223, 0},
            {(255ull << 32) | 0x55aa55aaull, 0x55aa55aau, 467, 250, 32, 223, 0},
        }};
        PackedBehaviorOutput behavior{};
        for (std::size_t index = 0; index < packed_vectors.size(); ++index) {
            const PackedTestInput& input = packed_vectors[index];
            const std::vector<PackedTestInput> packed_input{input};
            std::vector<PackedTestOutput> packed_output;
            if (!compare_packed_on_metal(
                    metal, packed_input, packed_output, behavior)) {
                return EXIT_FAILURE;
            }
            bool match = packed_output.front().legacy_ok != 0
                && packed_output.front().packed_ok != 0;
            for (int byte = 0; match && byte < input.entropy_len; ++byte) {
                match = packed_output.front().legacy_entropy[byte]
                    == packed_output.front().packed_entropy[byte];
            }
            if (!match) {
                passed = false;
                std::cerr << "packed vector failed: packed-gen="
                          << input.packed_gen_public
                          << " legacy-gen=" << input.legacy_gen_public
                          << " legacy-mode=" << input.legacy_mode_public
                          << " index=0x" << std::hex << input.packed_index
                          << std::dec << "\n";
            }
        }

        bool behavior_ok = behavior.direct16_ok != 0
            && behavior.direct32_ok != 0
            && behavior.mode1_16_ok != 0
            && behavior.mode1_32_ok != 0
            && behavior.mode8_16_ok != 0
            && behavior.mode217_16_ok != 0
            && behavior.shifted16_ok != 0;
        bool modes_differ = false;
        bool mode217_nonzero = false;
        for (int byte = 0; behavior_ok && byte < 16; ++byte) {
            behavior_ok = behavior.direct16[byte] == behavior.direct32[byte]
                && behavior.mode1_16[byte] == behavior.mode1_32[byte]
                && behavior.shifted16[byte] == behavior.direct32[byte + 8];
            modes_differ = modes_differ
                || behavior.mode1_16[byte] != behavior.mode8_16[byte];
            mode217_nonzero = mode217_nonzero
                || behavior.mode217_16[byte] != 0;
        }
        behavior_ok = behavior_ok && modes_differ && mode217_nonzero;
        if (!behavior_ok) {
            passed = false;
            std::cerr << "packed byte-prefix/mode/shift behavior failed\n";
        }

        if (!passed) {
            return EXIT_FAILURE;
        }
        std::cout << "Ill Bloom Metal vectors passed: " << vectors.size()
                  << "; exhaustive 32-byte masks: " << largest_unique_count
                  << "; packed equivalence vectors: " << packed_vectors.size()
                  << "; packed prefix/mode/shift: passed\n";
        return EXIT_SUCCESS;
    }
}
