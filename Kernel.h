#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#ifndef BASE
#define BASE 1626
#endif

#ifndef MAX_WORDS
#define MAX_WORDS 128
#endif

namespace metal_crypto {

constexpr std::size_t kFoundStringBytes = 512;
constexpr std::size_t kFoundPrivateKeyBytes = 64;
constexpr std::size_t kFoundHashWords = 20;
constexpr std::size_t kFoundPassBytes = 128;
constexpr std::size_t kMaxPendingSaveTasksPerGpu = 64;
constexpr std::size_t kMnemonicWordCount = 2048;
constexpr std::size_t kMnemonicWordStride = 34;
constexpr std::size_t kMnemonicDictBytes = kMnemonicWordCount * kMnemonicWordStride;
constexpr std::size_t kBloomFilterSlots = 100;
constexpr std::size_t kXorFilterSlots = 25;
constexpr std::size_t kHashTargetWords = 8;
constexpr std::size_t kSubstrateMaxPaths = 128;
constexpr std::size_t kSubstrateMaxJunctions = 16;
constexpr std::size_t kSubstrateMaxPasswordLen = 64;

struct RuntimeConfig {
    uint32_t maxFounds = 0;
    uint32_t deep = 0;
    uint32_t useBloom = 0;
    uint32_t useXor = 0;
    uint32_t useXorUn = 0;
    uint32_t useXorUc = 0;
    uint32_t useXorHc = 0;
    uint32_t isHex = 0;
    uint32_t isPass = 0;
    uint32_t full = 0;
    uint32_t utf8 = 0;
    uint32_t isLittleEndian = 0;
    uint32_t isEd25519Scalar = 0;
    uint32_t isEd25519Hash = 0;
    uint32_t secp256 = 0;
    uint32_t ed25519 = 0;
    uint32_t electrum = 0;
    uint32_t electrumSegwit = 0;
    uint32_t electrum128 = 0;
    uint32_t electrumCakeWallet = 0;
    uint32_t dictLang = 0;
    uint32_t useCustomDict = 0;
    uint32_t tonMnemonic = 0;
    uint32_t tonOnly = 0;
    uint32_t oldElectrum = 0;
    uint32_t compressed = 0;
    uint32_t uncompressed = 0;
    uint32_t segwit = 0;
    uint32_t p2wsh = 0;
    uint32_t taproot = 0;
    uint32_t ethereum = 0;
    uint32_t xpoint = 0;
    uint32_t solana = 0;
    uint32_t ton = 0;
    uint32_t tonAll = 0;
    uint32_t dot = 0;
    uint32_t aptos = 0;
    uint32_t sui = 0;
    uint32_t xrp = 0;
    uint32_t exodus = 0;
    uint32_t iota = 0;
    uint32_t ada = 0;
    uint32_t icp = 0;
    uint32_t fil = 0;
    uint32_t xtz = 0;
    uint32_t endomorphism = 0;
    uint32_t secpTargetsAny = 0;
    uint32_t edTargetsAny = 0;
    uint32_t substratePathCount = 0;
    uint32_t bipDerivationsEnabled = 1;
    uint32_t adaPointerEnabled = 0;
    uint32_t adaTypeMask = 0x000003ffu;
    uint32_t tonTypeMask = 0x00001fffu;
    uint32_t dotTypeMask = 0x00000003u;
    uint32_t aptosTypeMask = 0x00000007u;
    uint32_t suiTypeMask = 0x00000003u;
    uint32_t xrpTypeMask = 0x00000003u;
    uint32_t iotaTypeMask = 0x00000003u;
    uint32_t icpTypeMask = 0x00000003u;
    uint32_t filTypeMask = 0x00000003u;
    uint32_t xtzTypeMask = 0x00000003u;
    uint32_t iteration = 0;
    uint32_t shaLevel = 0;
    uint32_t shaPre[kHashTargetWords] = {};
    uint32_t hashTargetWords[kHashTargetWords] = {};
    uint32_t hashTargetMasks[kHashTargetWords] = {};
    uint32_t hashTargetLen = 0;
    uint32_t hashTargetEnabled = 0;
    uint32_t derivationTypeMask = 0;
    uint64_t adaPointerSlot = 0;
    uint64_t adaPointerTx = 0;
    uint64_t adaPointerCert = 0;
    uint64_t pbkdf2Iterations = 2048;
    uint64_t seqStep = 1;
    uint64_t skip = 0;
    uint64_t skip64 = 0;
    uint64_t seed = 0;
    uint8_t flags[32] = {};
};

struct XorFilterMetadata {
    uint64_t size[kXorFilterSlots] = {};
    uint64_t arrayLength[kXorFilterSlots] = {};
    uint64_t segmentCount[kXorFilterSlots] = {};
    uint64_t segmentCountLength[kXorFilterSlots] = {};
    uint64_t segmentLength[kXorFilterSlots] = {};
    uint64_t segmentLengthMask[kXorFilterSlots] = {};
};

struct XorFilterState {
    XorFilterMetadata x;
    XorFilterMetadata uncompressed;
    XorFilterMetadata uc;
    XorFilterMetadata hc;
};

struct FilterStorageState {
    uint32_t bloomCount = 0;
    uint32_t xorCount = 0;
    uint32_t xorUnCount = 0;
    uint32_t xorUcCount = 0;
    uint32_t xorHcCount = 0;
    uint32_t reserved[3] = {};
    uint64_t bloomOffsets[kBloomFilterSlots] = {};
    uint64_t bloomSizes[kBloomFilterSlots] = {};
    uint64_t xorOffsets[kXorFilterSlots] = {};
    uint64_t xorUnOffsets[kXorFilterSlots] = {};
    uint64_t xorUcOffsets[kXorFilterSlots] = {};
    uint64_t xorHcOffsets[kXorFilterSlots] = {};
};

struct SubstrateJunctionDevice {
    uint8_t chain_code[32];
    uint8_t is_hard = 0;
    uint8_t reserved[3] = {};
};

struct SubstratePathDevice {
    uint32_t junction_count = 0;
    uint32_t password_len = 0;
    uint32_t save_index = 0;
    uint32_t reserved = 0;
    uint8_t password[kSubstrateMaxPasswordLen] = {};
    SubstrateJunctionDevice junctions[kSubstrateMaxJunctions] = {};
};

struct FoundBufferLayout {
    uint64_t resultsCount = 0;
    uint32_t maxFounds = 0;
    uint32_t reserved = 0;
};

struct RandomStateData {
    uint32_t counter = 0;
    uint32_t counterHigh = 0;
    uint64_t seed = 0;
    uint32_t initialized = 0;
    uint32_t reserved = 0;
};

struct ProfanityUint128 {
    uint64_t m_lo = 0;
    uint64_t m_hi = 0;
};

struct ProfanitySeedWords {
    uint64_t s[4] = {};
};

struct ProfanityXKeys {
    uint64_t key64 = 0;
    ProfanityUint128 key128;
};

struct ProfanityRecoveryHit {
    uint8_t x32[32] = {};
    uint64_t offset = 0;
    uint64_t lane_id = 0;
    uint8_t filter_type = 0;
    uint8_t reserved[7] = {};
};

struct ProfanityVerifiedResult {
    uint8_t priv[32] = {};
    uint8_t x32[32] = {};
    uint8_t payload[32] = {};
    uint64_t lane_id = 0;
    uint64_t round = 0;
    uint32_t seed32 = 0;
    uint8_t type = 0;
    uint8_t payload_len = 0;
    uint8_t reserved[2] = {};
};

using ProfanityRecoveryVerifiedResult = ProfanityVerifiedResult;

struct ProfanityWalkState {
    uint64_t x[4] = {};
    uint64_t y[4] = {};
};

static_assert(kFoundStringBytes == 512, "METAL d_foundStrings row size must remain 512 bytes");
static_assert(kFoundPrivateKeyBytes == 64, "METAL d_foundPrvKeys row size must remain 64 bytes");
static_assert(kFoundHashWords == 20, "METAL d_foundHash160 row size must remain 20 uint32_t words");
static_assert(kFoundPassBytes == 128, "METAL d_pass row size must remain 128 bytes");
static_assert(kMaxPendingSaveTasksPerGpu == 64, "Async save queue depth must remain 64");
static_assert(kSubstrateMaxPaths == 128, "METAL SUBSTRATE_MAX_PATHS must remain 128");
static_assert(kSubstrateMaxJunctions == 16, "METAL SUBSTRATE_MAX_JUNCTIONS must remain 16");
static_assert(kSubstrateMaxPasswordLen == 64, "METAL SUBSTRATE_MAX_PASSWORD_LEN must remain 64");
static_assert(sizeof(SubstrateJunctionDevice) == 36, "SubstrateJunctionDevice must match METAL layout");
static_assert(sizeof(SubstratePathDevice) == 656, "SubstratePathDevice must match METAL layout");
static_assert(alignof(RuntimeConfig) >= alignof(uint64_t), "RuntimeConfig must keep 64-bit alignment");
static_assert(sizeof(RandomStateData) == 24, "RandomStateData host/device layout must remain stable");
static_assert(sizeof(ProfanityRecoveryHit) == 56, "ProfanityRecoveryHit must match METAL layout");
static_assert(sizeof(ProfanityVerifiedResult) == 120, "ProfanityVerifiedResult must match METAL layout");
static_assert(sizeof(ProfanityWalkState) == 64, "ProfanityWalkState must match METAL layout");

} // namespace metal_crypto

extern uint32_t Founds;
extern bool save;
extern FILE* OUT_FILE;

void wait_for_current_gpu_async_save_queue();
void flush_all_async_save_queues();
void shutdown_async_save_queues();
