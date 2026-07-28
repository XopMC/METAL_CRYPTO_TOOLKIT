#include "MetalBackend.h"
#include "Kernel.h"
#include "MetalRuntime.h"
#include "RecoveryWordlistsEmbedded.h"
#include "host_secp/secp256k1_common.h"
#include "Kernels/WalletModesHost.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cinttypes>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iomanip>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

bool UTF8 = false;

namespace {

struct MetalStreamState;

uint64_t host_rng_splitmix64(uint64_t& seed) {
    uint64_t z = (seed += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

struct AllocationRecord {
    void* base = nullptr;
    size_t size = 0;
    metal_crypto::Buffer buffer;
};

struct ResourceDependencies {
    bool defaultPending = false;
    std::unordered_map<uint64_t, std::shared_ptr<MetalStreamState>> streams;
};

struct ResolvedBuffer {
    metal_crypto::Buffer buffer;
    NSUInteger offset = 0;
    size_t available = 0;
};

bool find_allocation(const void* ptr, ResolvedBuffer& out);

template <typename T>
bool read_launch_value_arg(const MetalLaunchArg* args,
                           size_t count,
                           size_t index,
                           T& out);

struct LaunchBinding {
    metal_crypto::Buffer buffer;
    NSUInteger offset = 0;
    bool is_nil = false;
    bool track_dependency = false;
};

struct FoundPointers {
    void* foundStrings = nullptr;
    void* foundPrvKeys = nullptr;
    void* foundHash160 = nullptr;
    void* foundLen = nullptr;
    void* foundIter = nullptr;
    void* foundType = nullptr;
    void* foundDerivations = nullptr;
    void* foundDerivations2 = nullptr;
    void* pass = nullptr;
    void* passSize = nullptr;
    void* round = nullptr;
    void* seed = nullptr;
    void* substratePaths = nullptr;
    void* customDict = nullptr;
    void* profanityResults = nullptr;
    void* profanityCount = nullptr;
    void* walletResults = nullptr;
    void* walletCount = nullptr;
    void* xpResults = nullptr;
    void* xpCount = nullptr;
};

struct RuntimePointersHost {
    void* config = nullptr;
    void* filters = nullptr;
    void* filterStorage = nullptr;
    void* bloomStorage = nullptr;
    void* xorStorage = nullptr;
    void* xorUnStorage = nullptr;
    void* xorUcStorage = nullptr;
    void* xorHcStorage = nullptr;
    void* foundStrings = nullptr;
    void* foundPrvKeys = nullptr;
    void* foundHash160 = nullptr;
    void* foundLen = nullptr;
    void* foundIter = nullptr;
    void* foundType = nullptr;
    void* foundDerivations = nullptr;
    void* foundDerivations2 = nullptr;
    void* foundPass = nullptr;
    void* foundPassSize = nullptr;
    void* foundRound = nullptr;
    void* foundSeed = nullptr;
    void* resultsCount = nullptr;
    void* substratePaths = nullptr;
};

struct RecoveryRuntimePointersHost {
    void* config = nullptr;
    void* filters = nullptr;
    void* filterStorage = nullptr;
    void* bloomStorage = nullptr;
    void* xorStorage = nullptr;
    void* xorUnStorage = nullptr;
    void* xorUcStorage = nullptr;
    void* xorHcStorage = nullptr;
    void* foundStrings = nullptr;
    void* foundPrvKeys = nullptr;
    void* foundHash160 = nullptr;
    void* foundLen = nullptr;
    void* foundIter = nullptr;
    void* foundType = nullptr;
    void* foundDerivations = nullptr;
    void* foundDerivations2 = nullptr;
    void* foundPass = nullptr;
    void* foundPassSize = nullptr;
    void* foundRound = nullptr;
    void* foundSeed = nullptr;
    void* resultsCount = nullptr;
    void* customDict = nullptr;
};

struct XpRuntimePointersHost {
    void* config = nullptr;
    void* filters = nullptr;
    void* filterStorage = nullptr;
    void* bloomStorage = nullptr;
    void* xorStorage = nullptr;
    void* xorUnStorage = nullptr;
    void* xorUcStorage = nullptr;
    void* xorHcStorage = nullptr;
    void* xpResults = nullptr;
    void* xpCount = nullptr;
    uint32_t randstormSeedEvents = 0;
    uint32_t randstormScreenSeedX = 0;
    uint32_t randstormScreenSeedY = 0;
    uint32_t randstormTimeMode = 0;
    uint32_t randstormMileageStart = 0;
    uint32_t _pad0 = 0;
    uint64_t randstormMileageCount = 1;
};

struct XpRuntimeParamsHost {
    uint32_t randstormSeedEvents = 0;
    uint32_t randstormScreenSeedX = 0;
    uint32_t randstormScreenSeedY = 0;
    uint32_t randstormTimeMode = 0;
    uint32_t randstormMileageStart = 0;
    uint32_t _pad0 = 0;
    uint64_t randstormMileageCount = 1;
};

struct DerThreadRunParamsHost {
    uint32_t d_save_len = 0;
    uint32_t pass_len = 0;
    uint32_t der_indexes_size = 0;
    uint32_t der_offset = 0;
    uint64_t seed_value = 0;
    uint64_t round = 0;
    uint8_t store_seed = 0;
    uint8_t _pad0 = 0;
    uint8_t _pad1 = 0;
    uint8_t _pad2 = 0;
    uint8_t _tail[4] = {};
};

static_assert(sizeof(DerThreadRunParamsHost) == 40, "DerThreadRunParams host layout must match Metal");

constexpr size_t kSecpWalkStateBytes = 4096;

static constexpr NSUInteger kSecpEcmultWindowSizeFunctionConstantIndex = 90;
static constexpr NSUInteger kSecpWindowsSizeFunctionConstantIndex = 91;
static constexpr NSUInteger kBrowserVaultProfileFunctionConstantIndex = 92;
static constexpr NSUInteger kPoetryHasRoundsFunctionConstantIndex = 71;
static constexpr uint32_t kBrowserVaultDynamicProfile = UINT32_MAX;

struct XorFilterUploadMetadata {
    std::vector<void*> ptrs = std::vector<void*>(metal_crypto::kXorFilterSlots, nullptr);
    std::vector<size_t> bytes = std::vector<size_t>(metal_crypto::kXorFilterSlots, 0);
    std::vector<size_t> size = std::vector<size_t>(metal_crypto::kXorFilterSlots, 0);
    std::vector<size_t> arrayLength = std::vector<size_t>(metal_crypto::kXorFilterSlots, 0);
    std::vector<size_t> segmentCount = std::vector<size_t>(metal_crypto::kXorFilterSlots, 0);
    std::vector<size_t> segmentCountLength = std::vector<size_t>(metal_crypto::kXorFilterSlots, 0);
    std::vector<size_t> segmentLength = std::vector<size_t>(metal_crypto::kXorFilterSlots, 0);
    std::vector<size_t> segmentLengthMask = std::vector<size_t>(metal_crypto::kXorFilterSlots, 0);
};

struct DeviceState {
    std::mutex allocMutex;
    std::vector<AllocationRecord> allocations;
    std::unordered_map<const void*, ResourceDependencies> resourceDependencies;
    size_t allocatedBytes = 0;
    std::mutex symbolMutex;
    std::unordered_map<std::string, std::vector<uint8_t>> symbolBytes;
    std::mutex runtimeMutex;
    std::recursive_mutex snapshotMutex;
    metal_crypto::Runtime runtime;
    metal_crypto::RuntimeConfig runtimeConfig{};
    metal_crypto::XorFilterState filterState{};
    metal_crypto::FilterStorageState filterStorage{};
    metal_crypto::Buffer configBuffer;
    metal_crypto::Buffer filtersBuffer;
    metal_crypto::Buffer filterStorageBuffer;
    metal_crypto::Buffer emptyBloomBuffer;
    metal_crypto::Buffer emptyXorBuffer;
    metal_crypto::Buffer emptyXorUnBuffer;
    metal_crypto::Buffer emptyXorUcBuffer;
    metal_crypto::Buffer emptyXorHcBuffer;
    metal_crypto::Buffer bloomStorageBuffer;
    metal_crypto::Buffer xorStorageBuffer;
    metal_crypto::Buffer xorUnStorageBuffer;
    metal_crypto::Buffer xorUcStorageBuffer;
    metal_crypto::Buffer xorHcStorageBuffer;
    metal_crypto::Buffer resultsCountBuffer;
    metal_crypto::Buffer rngStateBuffer;
    metal_crypto::Buffer secpWalkStateBuffer;
    uint64_t* vanityGx = nullptr;
    uint64_t* vanityGy = nullptr;
    uint64_t* vanity2gnx = nullptr;
    uint64_t* vanity2gny = nullptr;
    uint32_t ecmultWindowBits = 18;
    uint32_t ecmultWindows = (256u / 18u) + 1u;
    void* builtinDictDev = nullptr;
    int builtinDictLang = -1;
    FoundPointers found;
    std::vector<uint8_t*> bloomPtrs = std::vector<uint8_t*>(metal_crypto::kBloomFilterSlots, nullptr);
    XorFilterUploadMetadata xorMetadata;
    XorFilterUploadMetadata xorUnMetadata;
    XorFilterUploadMetadata xorUcMetadata;
    XorFilterUploadMetadata xorHcMetadata;
    std::mutex defaultSequenceMutex;
    std::mutex streamsMutex;
    std::unordered_map<MetalStreamState*, std::shared_ptr<MetalStreamState>> streams;
    uint64_t nextStreamId = 1;
};

thread_local metalError_t g_last_error = metalSuccess;
thread_local int g_current_device = 0;
thread_local int g_cached_device = -1;
thread_local DeviceState* g_cached_device_state = nullptr;
std::mutex g_devices_mutex;
std::unordered_map<int, std::unique_ptr<DeviceState>> g_devices;
std::mutex g_host_alloc_mutex;
std::unordered_map<void*, size_t> g_host_allocations;

using SnapshotLock = std::lock_guard<std::recursive_mutex>;

DeviceState& device_state_for(int device) {
    std::lock_guard<std::mutex> lock(g_devices_mutex);
    std::unique_ptr<DeviceState>& state = g_devices[device];
    if (!state) {
        state = std::make_unique<DeviceState>();
    }
    return *state;
}

DeviceState& device_state() {
    if (g_cached_device_state == nullptr || g_cached_device != g_current_device) {
        g_cached_device_state = &device_state_for(g_current_device);
        g_cached_device = g_current_device;
    }
    return *g_cached_device_state;
}

struct MetalStreamState {
    int device = 0;
    uint64_t id = 0;
    std::shared_ptr<metal_crypto::Stream> stream;
    mutable std::shared_mutex lifecycleMutex;
    std::mutex sequenceMutex;
};

struct MetalStreamLease {
    std::shared_ptr<MetalStreamState> owner;
    std::shared_lock<std::shared_mutex> operationLock;
};

thread_local std::shared_ptr<MetalStreamState> g_dispatch_stream;
thread_local unsigned g_deferred_runtime_state_depth = 0;
thread_local bool g_runtime_state_upload_pending = false;

class DispatchStreamScope {
public:
    explicit DispatchStreamScope(std::shared_ptr<MetalStreamState> stream) : previous_(std::move(g_dispatch_stream)) {
        g_dispatch_stream = std::move(stream);
    }
    ~DispatchStreamScope() {
        g_dispatch_stream = previous_;
    }

private:
    std::shared_ptr<MetalStreamState> previous_;
};

#define g_alloc_mutex (device_state().allocMutex)
#define g_allocations (device_state().allocations)
#define g_resource_dependencies (device_state().resourceDependencies)
#define g_symbol_mutex (device_state().symbolMutex)
#define g_symbol_bytes (device_state().symbolBytes)
#define g_runtime_mutex (device_state().runtimeMutex)
#define g_runtime (device_state().runtime)
#define g_runtime_config (device_state().runtimeConfig)
#define g_filter_state (device_state().filterState)
#define g_filter_storage (device_state().filterStorage)
#define g_config_buffer (device_state().configBuffer)
#define g_filters_buffer (device_state().filtersBuffer)
#define g_filter_storage_buffer (device_state().filterStorageBuffer)
#define g_empty_bloom_buffer (device_state().emptyBloomBuffer)
#define g_empty_xor_buffer (device_state().emptyXorBuffer)
#define g_empty_xor_un_buffer (device_state().emptyXorUnBuffer)
#define g_empty_xor_uc_buffer (device_state().emptyXorUcBuffer)
#define g_empty_xor_hc_buffer (device_state().emptyXorHcBuffer)
#define g_bloom_storage_buffer (device_state().bloomStorageBuffer)
#define g_xor_storage_buffer (device_state().xorStorageBuffer)
#define g_xor_un_storage_buffer (device_state().xorUnStorageBuffer)
#define g_xor_uc_storage_buffer (device_state().xorUcStorageBuffer)
#define g_xor_hc_storage_buffer (device_state().xorHcStorageBuffer)
#define g_results_count_buffer (device_state().resultsCountBuffer)
#define g_rng_state_buffer (device_state().rngStateBuffer)
#define g_secp_walk_state_buffer (device_state().secpWalkStateBuffer)
#define g_vanity_gx (device_state().vanityGx)
#define g_vanity_gy (device_state().vanityGy)
#define g_vanity_2gnx (device_state().vanity2gnx)
#define g_vanity_2gny (device_state().vanity2gny)
#define g_ecmult_window_bits (device_state().ecmultWindowBits)
#define g_ecmult_windows (device_state().ecmultWindows)
#define g_builtin_dict_dev (device_state().builtinDictDev)
#define g_builtin_dict_lang (device_state().builtinDictLang)
#define g_found (device_state().found)
#define g_bloom_ptrs (device_state().bloomPtrs)
#define g_xor (device_state().xorMetadata)
#define g_xor_un (device_state().xorUnMetadata)
#define g_xor_uc (device_state().xorUcMetadata)
#define g_xor_hc (device_state().xorHcMetadata)

metalError_t remember(metalError_t error) {
    g_last_error = error;
    return error;
}

metalError_t remember_status(const metal_crypto::Status& status) {
    if (status.ok) {
        return remember(metalSuccess);
    }
    std::fprintf(stderr, "[!] Metal runtime error: %s [!]\n", status.message.c_str());
    return remember(metalErrorUnknown);
}

bool starts_with(const std::string& s, const char* prefix) {
    return s.rfind(prefix, 0) == 0;
}

bool contains(const std::string& s, const char* needle) {
    return s.find(needle) != std::string::npos;
}

template <typename T>
void copy_symbol_value(const void* src, T& dst, size_t bytes) {
    if (src != nullptr && bytes >= sizeof(T)) {
        std::memcpy(&dst, src, sizeof(T));
    }
}

template <typename T>
T read_symbol_or_default(const char* symbol, T fallback) {
    std::lock_guard<std::mutex> lock(g_symbol_mutex);
    auto it = g_symbol_bytes.find(std::string(symbol));
    if (it == g_symbol_bytes.end() || it->second.empty()) {
        return fallback;
    }
    T out = fallback;
    std::memcpy(&out, it->second.data(), std::min(sizeof(T), it->second.size()));
    return out;
}

void* read_pointer_value(const void* src, size_t bytes) {
    void* value = nullptr;
    if (src != nullptr && bytes >= sizeof(value)) {
        std::memcpy(&value, src, sizeof(value));
    }
    return value;
}

bool metal_type_enabled(uint32_t mask, uint32_t coin_type, uint32_t first, uint32_t last) {
    if (coin_type < first || coin_type > last) {
        return true;
    }
    return (mask & (1u << (coin_type - first))) != 0u;
}

const RecoveryEmbeddedWordlistView* embedded_wordlist_for_metal_lang(int lang) {
    const char* id = "bip39-en";
    switch (lang) {
    default:
    case 0: id = "bip39-en"; break;
    case 1: id = "bip39-es"; break;
    case 2: id = "bip39-ja"; break;
    case 3: id = "bip39-it"; break;
    case 4: id = "bip39-fr"; break;
    case 5: id = "bip39-cs"; break;
    case 6: id = "bip39-pt"; break;
    case 7: id = "bip39-ko"; break;
    case 8: id = "bip39-zh-hans"; break;
    case 9: id = "bip39-zh-hant"; break;
    }
    for (std::size_t i = 0; i < kRecoveryEmbeddedWordlistsCount; ++i) {
        if (std::strcmp(kRecoveryEmbeddedWordlists[i].id, id) == 0) {
            return &kRecoveryEmbeddedWordlists[i];
        }
    }
    return nullptr;
}

metalError_t ensure_builtin_dict_for_lang(int lang) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (lang < 0 || lang > 9) {
        lang = 0;
    }
    if (g_builtin_dict_dev != nullptr && g_builtin_dict_lang == lang) {
        g_found.customDict = g_builtin_dict_dev;
        return remember(metalSuccess);
    }
    const RecoveryEmbeddedWordlistView* view = embedded_wordlist_for_metal_lang(lang);
    if (view == nullptr || view->words == nullptr || view->count != metal_crypto::kMnemonicWordCount) {
        return remember(metalErrorInvalidValue);
    }
    if (g_builtin_dict_dev == nullptr) {
        metalError_t st = metalMalloc(&g_builtin_dict_dev, metal_crypto::kMnemonicDictBytes);
        if (st != metalSuccess) {
            return st;
        }
    }
    std::vector<char> packed(metal_crypto::kMnemonicDictBytes, 0);
    for (std::size_t i = 0; i < metal_crypto::kMnemonicWordCount; ++i) {
        const char* word = view->words[i] != nullptr ? view->words[i] : "";
        const std::size_t len = std::min<std::size_t>(std::strlen(word), metal_crypto::kMnemonicWordStride - 1u);
        std::memcpy(packed.data() + i * metal_crypto::kMnemonicWordStride, word, len);
    }
    metalError_t st = metalMemcpy(g_builtin_dict_dev, packed.data(), packed.size(), metalMemcpyHostToDevice);
    if (st != metalSuccess) {
        return st;
    }
    g_builtin_dict_lang = lang;
    g_found.customDict = g_builtin_dict_dev;
    return remember(metalSuccess);
}

struct WorkerFunctionConstants {
    bool compressed = false;
    bool uncompressed = false;
    bool segwit = false;
    bool p2wsh = false;
    bool taproot = false;
    bool ethereum = false;
    bool xpoint = false;
    bool xrpSecp = false;
    bool suiSecp = false;
    bool iotaSecp = false;
    bool aptosSecp = false;
    bool icpSecp = false;
    bool filSecp = false;
    bool xtzSecp = false;
    bool secpAny = false;
    bool edAny = false;
    bool solana = false;
    bool dot = false;
    bool ada = false;
    bool ton = false;
    bool tonAll = false;
    bool xrpEd = false;
    bool aptosEd = false;
    bool suiEd = false;
    bool iotaEd = false;
    bool icpEd = false;
    bool xtzEd = false;
    bool edScalar = false;
    bool edHash = false;
    bool edLittleEndian = false;
    uint32_t adaTypeMask = 0x000003ffu;
};

struct DerThreadFunctionConstants {
    WorkerFunctionConstants targets;
    uint32_t substratePathCount = 0u;
    bool dotEnabled = false;
};

struct EcmultWindowFunctionConstants {
    uint32_t windowBits = 18u;
    uint32_t windows = (256u / 18u) + 1u;
    uint32_t adaTypeMask = 0x000003ffu;
    uint32_t dotTypeMask = 0x00000003u;
    uint32_t derivationTypeMask = 0u;
};

EcmultWindowFunctionConstants make_ecmult_window_function_constants() {
    EcmultWindowFunctionConstants c{};
    c.windowBits = g_ecmult_window_bits == 0u ? 18u : g_ecmult_window_bits;
    c.windows = g_ecmult_windows == 0u ? ((256u / c.windowBits) + 1u) : g_ecmult_windows;
    c.adaTypeMask = g_runtime_config.adaTypeMask;
    c.dotTypeMask = g_runtime_config.dotTypeMask;
    c.derivationTypeMask = g_runtime_config.derivationTypeMask;
    return c;
}

std::string ecmult_window_function_constants_key(const EcmultWindowFunctionConstants& c) {
    return "ecmult-window:" + std::to_string(c.windowBits) + ":" +
           std::to_string(c.windows) + ":ada:" + std::to_string(c.adaTypeMask) +
           ":dot:" + std::to_string(c.dotTypeMask) +
           ":der:" + std::to_string(c.derivationTypeMask);
}

void bind_ecmult_window_function_constants(MTLFunctionConstantValues* values,
                                           const EcmultWindowFunctionConstants& c) {
    uint32_t uintValue = c.windowBits;
    [values setConstantValue:&uintValue type:MTLDataTypeUInt atIndex:kSecpEcmultWindowSizeFunctionConstantIndex];
    uintValue = c.windows;
    [values setConstantValue:&uintValue type:MTLDataTypeUInt atIndex:kSecpWindowsSizeFunctionConstantIndex];
    uintValue = c.adaTypeMask;
    [values setConstantValue:&uintValue type:MTLDataTypeUInt atIndex:32];
    uintValue = c.dotTypeMask;
    [values setConstantValue:&uintValue type:MTLDataTypeUInt atIndex:33];
    uintValue = c.derivationTypeMask;
    [values setConstantValue:&uintValue type:MTLDataTypeUInt atIndex:34];
}

struct BrowserVaultFunctionConstants {
    uint32_t profile = kBrowserVaultDynamicProfile;
};

BrowserVaultFunctionConstants make_browser_vault_function_constants(
    const MetalLaunchArg* args,
    const size_t count) {
    BrowserVaultFunctionConstants constants{};
    uint32_t groupCount = 0u;
    if (args == nullptr || count <= 7u ||
        args[5].kind != MetalLaunchArg::Kind::Pointer || args[5].data == nullptr ||
        !read_launch_value_arg(args, count, 7u, groupCount) || groupCount == 0u) {
        return constants;
    }

    ResolvedBuffer resolved;
    if (!find_allocation(args[5].data, resolved) || !resolved.buffer.valid() ||
        resolved.buffer.contents() == nullptr ||
        groupCount > resolved.available / sizeof(BrowserVaultGroup)) {
        return constants;
    }

    const auto* bytes = static_cast<const uint8_t*>(resolved.buffer.contents()) + resolved.offset;
    BrowserVaultGroup group{};
    std::memcpy(&group, bytes, sizeof(group));
    const uint32_t profile = group.profile;
    for (uint32_t i = 1u; i < groupCount; ++i) {
        std::memcpy(&group, bytes + size_t(i) * sizeof(BrowserVaultGroup), sizeof(group));
        if (group.profile != profile) {
            return constants;
        }
    }
    constants.profile = profile;
    return constants;
}

std::string browser_vault_function_constants_key(const BrowserVaultFunctionConstants& c) {
    return "browser-vault-profile:" + std::to_string(c.profile);
}

void bind_browser_vault_function_constants(MTLFunctionConstantValues* values,
                                           const BrowserVaultFunctionConstants& c) {
    uint32_t profile = c.profile;
    [values setConstantValue:&profile
                        type:MTLDataTypeUInt
                     atIndex:kBrowserVaultProfileFunctionConstantIndex];
}

WorkerFunctionConstants make_worker_function_constants() {
    WorkerFunctionConstants c{};
    c.compressed = g_runtime_config.compressed != 0u;
    c.uncompressed = g_runtime_config.uncompressed != 0u;
    c.segwit = g_runtime_config.segwit != 0u;
    c.p2wsh = g_runtime_config.p2wsh != 0u;
    c.taproot = g_runtime_config.taproot != 0u;
    c.ethereum = g_runtime_config.ethereum != 0u;
    c.xpoint = g_runtime_config.xpoint != 0u;
    c.xrpSecp = g_runtime_config.xrp != 0u &&
                metal_type_enabled(g_runtime_config.xrpTypeMask, 0x90u, 0x90u, 0x91u);
    c.suiSecp = g_runtime_config.sui != 0u &&
                metal_type_enabled(g_runtime_config.suiTypeMask, 0x70u, 0x70u, 0x71u);
    c.iotaSecp = g_runtime_config.iota != 0u &&
                 metal_type_enabled(g_runtime_config.iotaTypeMask, 0x50u, 0x50u, 0x51u);
    c.aptosSecp = g_runtime_config.aptos != 0u &&
                  metal_type_enabled(g_runtime_config.aptosTypeMask, 0x22u, 0x20u, 0x22u);
    c.icpSecp = g_runtime_config.icp != 0u &&
                metal_type_enabled(g_runtime_config.icpTypeMask, 0x53u, 0x52u, 0x53u);
    c.filSecp = g_runtime_config.fil != 0u &&
                (metal_type_enabled(g_runtime_config.filTypeMask, 0x41u, 0x41u, 0x42u) ||
                 metal_type_enabled(g_runtime_config.filTypeMask, 0x42u, 0x41u, 0x42u));
    c.xtzSecp = g_runtime_config.xtz != 0u &&
                metal_type_enabled(g_runtime_config.xtzTypeMask, 0x92u, 0x92u, 0x93u);
    c.secpAny = g_runtime_config.secpTargetsAny != 0u;
    c.edAny = g_runtime_config.edTargetsAny != 0u;
    c.solana = g_runtime_config.solana != 0u;
    c.dot = g_runtime_config.dot != 0u &&
            (metal_type_enabled(g_runtime_config.dotTypeMask, 0x30u, 0x30u, 0x31u) ||
             metal_type_enabled(g_runtime_config.dotTypeMask, 0x31u, 0x30u, 0x31u));
    c.ada = g_runtime_config.ada != 0u;
    c.ton = g_runtime_config.ton != 0u && g_runtime_config.tonTypeMask != 0u;
    c.tonAll = g_runtime_config.tonAll != 0u && g_runtime_config.tonTypeMask != 0u;
    c.xrpEd = g_runtime_config.xrp != 0u &&
              metal_type_enabled(g_runtime_config.xrpTypeMask, 0x91u, 0x90u, 0x91u);
    c.aptosEd = g_runtime_config.aptos != 0u &&
                (metal_type_enabled(g_runtime_config.aptosTypeMask, 0x20u, 0x20u, 0x22u) ||
                 metal_type_enabled(g_runtime_config.aptosTypeMask, 0x21u, 0x20u, 0x22u));
    c.suiEd = g_runtime_config.sui != 0u &&
              metal_type_enabled(g_runtime_config.suiTypeMask, 0x71u, 0x70u, 0x71u);
    c.iotaEd = g_runtime_config.iota != 0u &&
               metal_type_enabled(g_runtime_config.iotaTypeMask, 0x51u, 0x50u, 0x51u);
    c.icpEd = g_runtime_config.icp != 0u &&
              metal_type_enabled(g_runtime_config.icpTypeMask, 0x52u, 0x52u, 0x53u);
    c.xtzEd = g_runtime_config.xtz != 0u &&
              metal_type_enabled(g_runtime_config.xtzTypeMask, 0x93u, 0x92u, 0x93u);
    c.edScalar = g_runtime_config.isEd25519Scalar != 0u;
    c.edHash = g_runtime_config.isEd25519Hash != 0u;
    c.edLittleEndian = g_runtime_config.isLittleEndian != 0u;
    c.adaTypeMask = g_runtime_config.adaTypeMask;
    return c;
}

std::string worker_function_constants_key(const WorkerFunctionConstants& c) {
    const bool flags[] = {
        c.compressed, c.uncompressed, c.segwit, c.p2wsh, c.taproot, c.ethereum, c.xpoint,
        c.xrpSecp, c.suiSecp, c.iotaSecp, c.aptosSecp, c.icpSecp, c.filSecp, c.xtzSecp,
        c.secpAny, c.edAny, c.solana, c.dot, c.ada, c.ton, c.tonAll, c.xrpEd,
        c.aptosEd, c.suiEd, c.iotaEd, c.icpEd, c.xtzEd,
        c.edScalar, c.edHash, c.edLittleEndian
    };
    std::string key("worker-targets:");
    key.reserve(16 + sizeof(flags));
    for (bool flag : flags) {
        key.push_back(flag ? '1' : '0');
    }
    key += ":ada:";
    key += std::to_string(c.adaTypeMask);
    return key;
}

void bind_worker_function_constants(MTLFunctionConstantValues* values,
                                    const WorkerFunctionConstants& c) {
    const bool flags[] = {
        c.compressed, c.uncompressed, c.segwit, c.p2wsh, c.taproot, c.ethereum, c.xpoint,
        c.xrpSecp, c.suiSecp, c.iotaSecp, c.aptosSecp, c.icpSecp, c.filSecp, c.xtzSecp,
        c.secpAny, c.edAny, c.solana, c.dot, c.ada, c.ton, c.tonAll, c.xrpEd,
        c.aptosEd, c.suiEd, c.iotaEd, c.icpEd, c.xtzEd
    };
    for (NSUInteger i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
        bool value = flags[i];
        [values setConstantValue:&value type:MTLDataTypeBool atIndex:i];
    }
    uint32_t adaTypeMask = c.adaTypeMask;
    [values setConstantValue:&adaTypeMask type:MTLDataTypeUInt atIndex:32];
    bool value = c.edScalar;
    [values setConstantValue:&value type:MTLDataTypeBool atIndex:66];
    value = c.edHash;
    [values setConstantValue:&value type:MTLDataTypeBool atIndex:67];
    value = c.edLittleEndian;
    [values setConstantValue:&value type:MTLDataTypeBool atIndex:68];
}

DerThreadFunctionConstants make_derthread_function_constants() {
    DerThreadFunctionConstants c{};
    c.targets = make_worker_function_constants();
    c.substratePathCount = g_runtime_config.substratePathCount;
    c.dotEnabled = g_runtime_config.dot != 0u;
    return c;
}

std::string derthread_function_constants_key(const DerThreadFunctionConstants& c) {
    return worker_function_constants_key(c.targets) + ":substrate:" +
           std::to_string(c.substratePathCount) + ":dot:" +
           (c.dotEnabled ? "1" : "0");
}

void bind_derthread_function_constants(MTLFunctionConstantValues* values,
                                       const DerThreadFunctionConstants& c) {
    bind_worker_function_constants(values, c.targets);
    uint32_t pathCount = c.substratePathCount;
    [values setConstantValue:&pathCount type:MTLDataTypeUInt atIndex:69];
    bool dotEnabled = c.dotEnabled;
    [values setConstantValue:&dotEnabled type:MTLDataTypeBool atIndex:70];
}

template <typename T>
bool read_launch_value_arg(const MetalLaunchArg* args,
                           size_t count,
                           size_t index,
                           T& out);

struct PoetryFunctionConstants {
    WorkerFunctionConstants targets;
    bool hasRounds = false;
};

PoetryFunctionConstants make_poetry_function_constants(const MetalLaunchArg* args,
                                                        size_t count) {
    PoetryFunctionConstants constants{};
    constants.targets = make_worker_function_constants();
    uint64_t rounds = 0u;
    if (read_launch_value_arg(args, count, 12u, rounds)) {
        constants.hasRounds = rounds != 0u;
    }
    return constants;
}

std::string poetry_function_constants_key(const PoetryFunctionConstants& constants) {
    return worker_function_constants_key(constants.targets) + ":poetry-rounds:" +
           (constants.hasRounds ? "1" : "0");
}

void bind_poetry_function_constants(MTLFunctionConstantValues* values,
                                    const PoetryFunctionConstants& constants) {
    bind_worker_function_constants(values, constants.targets);
    bool hasRounds = constants.hasRounds;
    [values setConstantValue:&hasRounds
                        type:MTLDataTypeBool
                     atIndex:kPoetryHasRoundsFunctionConstantIndex];
}

struct PrivFileFunctionConstants {
    WorkerFunctionConstants targets;
    bool modeSpecialized = false;
    int mode = 0;
};

PrivFileFunctionConstants make_priv_file_function_constants(const MetalLaunchArg* args,
                                                             const size_t count) {
    PrivFileFunctionConstants c{};
    c.targets = make_worker_function_constants();
    c.modeSpecialized = read_launch_value_arg(args, count, 7u, c.mode);
    return c;
}

std::string priv_file_function_constants_key(const PrivFileFunctionConstants& c) {
    std::string key = worker_function_constants_key(c.targets);
    key += ":privfile:";
    key += c.modeSpecialized ? '1' : '0';
    key += ':';
    key += std::to_string(c.mode);
    return key;
}

void bind_priv_file_function_constants(MTLFunctionConstantValues* values,
                                       const PrivFileFunctionConstants& c) {
    bind_worker_function_constants(values, c.targets);
    if (c.modeSpecialized) {
        int mode = c.mode;
        [values setConstantValue:&mode type:MTLDataTypeInt atIndex:35];
    }
}

template <typename T>
bool read_launch_value_arg(const MetalLaunchArg* args,
                           const size_t count,
                           const size_t index,
                           T& out) {
    if (args == nullptr || index >= count) {
        return false;
    }
    const MetalLaunchArg& arg = args[index];
    if (arg.kind != MetalLaunchArg::Kind::Value || arg.data == nullptr || arg.size < sizeof(T)) {
        return false;
    }
    std::memcpy(&out, arg.data, sizeof(T));
    return true;
}

struct PrivGenFunctionConstants {
    WorkerFunctionConstants targets;
    bool prngSpecialized = false;
    bool prngIs64 = false;
    int prngEntropyLen = 0;
    int prngMode = 0;
    int prngGen = 0;
};

bool uses_priv_gen_function_constants(const std::string& name) {
    static const char* names[] = {
        "workerPRIV_gen",
        "workerPRIVHash_gen",
        "workerPRIVByte_gen",
        "workerPRIVSwap_gen",
        "workerPRIVPlus_gen",
        "workerPRIVadd_gen",
        "workerPRIV_hash",
        "workerPRIV_byte",
        "workerPRIV_plus",
        "workerPRIV_swap",
        "workerPRIV_pattern",
    };
    for (const char* candidate : names) {
        if (name == candidate) {
            return true;
        }
    }
    return false;
}

bool priv_gen_prng_arg_indices(const std::string& name,
                               size_t& is64Index,
                               size_t& entropyIndex,
                               size_t& modeIndex,
                               size_t& genIndex) {
    if (name == "workerPRIVByte_gen") {
        is64Index = 8u;
        entropyIndex = 9u;
        modeIndex = 10u;
        genIndex = 11u;
        return true;
    }
    if (name == "workerPRIV_gen" ||
        name == "workerPRIVHash_gen" ||
        name == "workerPRIVSwap_gen" ||
        name == "workerPRIVPlus_gen" ||
        name == "workerPRIVadd_gen") {
        is64Index = 6u;
        entropyIndex = 7u;
        modeIndex = 8u;
        genIndex = 9u;
        return true;
    }
    return false;
}

PrivGenFunctionConstants make_priv_gen_function_constants(const std::string& name,
                                                          const MetalLaunchArg* args,
                                                          const size_t count) {
    PrivGenFunctionConstants c{};
    c.targets = make_worker_function_constants();

    size_t is64Index = 0u;
    size_t entropyIndex = 0u;
    size_t modeIndex = 0u;
    size_t genIndex = 0u;
    if (priv_gen_prng_arg_indices(name, is64Index, entropyIndex, modeIndex, genIndex)) {
        bool is64 = false;
        int entropyLen = 0;
        int mode = 0;
        int gen = 0;
        if (read_launch_value_arg(args, count, is64Index, is64) &&
            read_launch_value_arg(args, count, entropyIndex, entropyLen) &&
            read_launch_value_arg(args, count, modeIndex, mode) &&
            read_launch_value_arg(args, count, genIndex, gen)) {
            c.prngSpecialized = true;
            c.prngIs64 = is64;
            c.prngEntropyLen = entropyLen;
            c.prngMode = mode;
            c.prngGen = gen;
        }
    }
    return c;
}

std::string priv_gen_function_constants_key(const PrivGenFunctionConstants& c) {
    std::string key = worker_function_constants_key(c.targets);
    key += ":privgen:";
    key += c.prngSpecialized ? '1' : '0';
    key += ':';
    key += c.prngIs64 ? '1' : '0';
    key += ':';
    key += std::to_string(c.prngEntropyLen);
    key += ':';
    key += std::to_string(c.prngMode);
    key += ':';
    key += std::to_string(c.prngGen);
    return key;
}

void bind_priv_gen_function_constants(MTLFunctionConstantValues* values,
                                      const PrivGenFunctionConstants& c) {
    bind_worker_function_constants(values, c.targets);

    bool boolValue = c.prngSpecialized;
    [values setConstantValue:&boolValue type:MTLDataTypeBool atIndex:27];
    boolValue = c.prngIs64;
    [values setConstantValue:&boolValue type:MTLDataTypeBool atIndex:28];

    int intValue = c.prngEntropyLen;
    [values setConstantValue:&intValue type:MTLDataTypeInt atIndex:29];
    intValue = c.prngMode;
    [values setConstantValue:&intValue type:MTLDataTypeInt atIndex:30];
    intValue = c.prngGen;
    [values setConstantValue:&intValue type:MTLDataTypeInt atIndex:31];
}

struct XpFunctionConstants {
    WorkerFunctionConstants targets;
    bool profileSpecialized = false;
    uint32_t profileKind = 0;
};

bool uses_xp_function_constants(const std::string& name) {
    return starts_with(name, "workerXP");
}

XpFunctionConstants make_xp_function_constants(const MetalLaunchArg* args,
                                               const size_t count) {
    XpFunctionConstants c{};
    c.targets = make_worker_function_constants();
    uint8_t profileKind = 0;
    if (read_launch_value_arg(args, count, 4u, profileKind)) {
        c.profileSpecialized = true;
        c.profileKind = static_cast<uint32_t>(profileKind);
    }
    return c;
}

std::string xp_function_constants_key(const XpFunctionConstants& c) {
    std::string key = worker_function_constants_key(c.targets);
    key += ":xp:";
    key += c.profileSpecialized ? '1' : '0';
    key += ':';
    key += std::to_string(c.profileKind);
    return key;
}

void bind_xp_function_constants(MTLFunctionConstantValues* values,
                                const XpFunctionConstants& c) {
    bind_worker_function_constants(values, c.targets);

    bool boolValue = c.profileSpecialized;
    [values setConstantValue:&boolValue type:MTLDataTypeBool atIndex:64];
    uint32_t uintValue = c.profileKind;
    [values setConstantValue:&uintValue type:MTLDataTypeUInt atIndex:65];
}

bool uses_worker_common_function_constants(const std::string& name) {
    static const char* names[] = {
        "worker",
        "workerPRIV",
        "workerPoetry",
        "worker_seq",
        "worker_seq_hexset",
        "worker_gen",
        "worker_recovery_hexset",
        "workerBrain",
        "workerBrain_seq",
        "workerBrain_seq_hexset",
        "workerBrain_gen",
        "workerBrain_recovery_hexset",
        "workerByte",
        "workerDerThread",
        "workerDerThread_mkd",
        "workerDerThread_mkd_gen",
        "workerPassThread",
        "workerPassThreadEntropy",
        "workerPassThreadEntropyBatch",
        "workerEntropy",
        "workerEntropy_seq",
        "workerEntropy_seq_hexset",
        "workerEntropy_gen",
        "workerEntropy_recovery_hexset",
        "workerSeed",
        "workerSeed_seq",
        "workerSeed_seq_hexset",
        "workerSeed_gen",
        "workerSeed_recovery_hexset",
        "workerHmac",
        "workerHmac_seq",
        "workerHmac_seq_hexset",
        "workerHmac_gen",
        "workerHmac_recovery_hexset",
        "workerBip32",
        "workerBip32_seq",
        "workerBip32_seq_hexset",
        "workerBip32_gen",
        "workerBip32_recovery_hexset",
        "workerArmory",
        "workerArmory_gen",
        "workerArmory_recovery_hexset",
        "workerArmoryRoot",
        "workerArmoryRoot_gen",
        "workerArmoryRoot_recovery_hexset",
        "workerMINIKEYS_process",
    };
    for (const char* candidate : names) {
        if (name == candidate) {
            return true;
        }
    }
    return false;
}

metal_crypto::Runtime& runtime() {
    return g_runtime;
}

metalError_t ensure_runtime(DeviceState& state, int device) {
    std::lock_guard<std::mutex> lock(state.runtimeMutex);
    if (state.runtime.ready()) {
        return metalSuccess;
    }
    return remember_status(state.runtime.initialize(device, metal_crypto::defaultMetallibPath()));
}

metalError_t ensure_runtime() {
    return ensure_runtime(device_state(), g_current_device);
}

metalError_t resolve_stream(metalStream_t handle, MetalStreamLease& out) {
    out = {};
    if (handle == nullptr) {
        return metalSuccess;
    }
    DeviceState& state = device_state();
    MetalStreamState* stream = static_cast<MetalStreamState*>(handle);
    std::lock_guard<std::mutex> lock(state.streamsMutex);
    auto found = state.streams.find(stream);
    if (found == state.streams.end()) {
        return remember(metalErrorInvalidValue);
    }
    out.owner = found->second;
    out.operationLock = std::shared_lock<std::shared_mutex>(out.owner->lifecycleMutex);
    return metalSuccess;
}

bool lease_dependency_stream(const std::shared_ptr<MetalStreamState>& requested,
                             MetalStreamLease& out) {
    out = {};
    if (!requested) {
        return false;
    }
    DeviceState& state = device_state();
    std::lock_guard<std::mutex> registryLock(state.streamsMutex);
    auto found = state.streams.find(requested.get());
    if (found == state.streams.end() || found->second != requested) {
        return false;
    }
    out.owner = found->second;
    out.operationLock = std::shared_lock<std::shared_mutex>(out.owner->lifecycleMutex);
    return true;
}

metalError_t ensure_buffer(metal_crypto::Buffer& buffer, size_t bytes) {
    if (buffer.valid()) {
        return metalSuccess;
    }
    metalError_t st = ensure_runtime();
    if (st != metalSuccess) {
        return st;
    }
    metal_crypto::Status status = runtime().makeBuffer(std::max<size_t>(bytes, 1), buffer);
    if (!status.ok) {
        return remember_status(status);
    }
    status = runtime().memsetBuffer(buffer, 0, std::max<size_t>(bytes, 1));
    return remember_status(status);
}

void fill_xor_metadata(const XorFilterUploadMetadata& src, metal_crypto::XorFilterMetadata& dst) {
    for (size_t i = 0; i < metal_crypto::kXorFilterSlots; ++i) {
        dst.size[i] = static_cast<uint64_t>(src.size[i]);
        dst.arrayLength[i] = static_cast<uint64_t>(src.arrayLength[i]);
        dst.segmentCount[i] = static_cast<uint64_t>(src.segmentCount[i]);
        dst.segmentCountLength[i] = static_cast<uint64_t>(src.segmentCountLength[i]);
        dst.segmentLength[i] = static_cast<uint64_t>(src.segmentLength[i]);
        dst.segmentLengthMask[i] = static_cast<uint64_t>(src.segmentLengthMask[i]);
    }
}

const void* resource_key(const metal_crypto::Buffer& buffer) {
    return buffer.valid() ? (__bridge const void*)buffer.native() : nullptr;
}

void mark_resource_dependency(const metal_crypto::Buffer& buffer,
                              const std::shared_ptr<MetalStreamState>& stream) {
    const void* key = resource_key(buffer);
    if (key == nullptr) return;
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    ResourceDependencies& dependencies = g_resource_dependencies[key];
    if (stream) {
        dependencies.streams[stream->id] = stream;
    } else {
        dependencies.defaultPending = true;
    }
}

void mark_resource_dependencies(const std::vector<metal_crypto::Buffer>& resources,
                                const std::shared_ptr<MetalStreamState>& stream) {
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    for (const metal_crypto::Buffer& buffer : resources) {
        const void* key = resource_key(buffer);
        if (key == nullptr) continue;
        ResourceDependencies& dependencies = g_resource_dependencies[key];
        if (stream) {
            dependencies.streams[stream->id] = stream;
        } else {
            dependencies.defaultPending = true;
        }
    }
}

void clear_resource_dependency(DeviceState& state,
                               const std::shared_ptr<MetalStreamState>& stream) {
    std::lock_guard<std::mutex> lock(state.allocMutex);
    for (auto it = state.resourceDependencies.begin(); it != state.resourceDependencies.end();) {
        if (stream) {
            it->second.streams.erase(stream->id);
        } else {
            it->second.defaultPending = false;
        }
        if (!it->second.defaultPending && it->second.streams.empty()) {
            it = state.resourceDependencies.erase(it);
        } else {
            ++it;
        }
    }
}

std::mutex& resource_sequence_mutex(DeviceState& state,
                                    const std::shared_ptr<MetalStreamState>& stream) {
    return stream ? stream->sequenceMutex : state.defaultSequenceMutex;
}

std::unique_lock<std::mutex> submit_resource_sequence(
    DeviceState& state,
    const std::shared_ptr<MetalStreamState>& stream) {
    return std::unique_lock<std::mutex>(resource_sequence_mutex(state, stream));
}

metal_crypto::Status synchronize_resource_sequence(
    DeviceState& state,
    const std::shared_ptr<MetalStreamState>& stream) {
    std::unique_lock<std::mutex> sequenceLock(resource_sequence_mutex(state, stream));
    metal_crypto::Status status = state.runtime.synchronize(
        stream ? stream->stream.get() : nullptr);
    clear_resource_dependency(state, stream);
    return status;
}

metalError_t prepare_runtime_state_locked() {
    metalError_t st = ensure_buffer(g_config_buffer, sizeof(g_runtime_config));
    if (st != metalSuccess) return st;
    st = ensure_buffer(g_filters_buffer, sizeof(g_filter_state));
    if (st != metalSuccess) return st;
    st = ensure_buffer(g_filter_storage_buffer, sizeof(g_filter_storage));
    if (st != metalSuccess) return st;
    st = ensure_buffer(g_empty_bloom_buffer, 1);
    if (st != metalSuccess) return st;
    st = ensure_buffer(g_empty_xor_buffer, 1);
    if (st != metalSuccess) return st;
    st = ensure_buffer(g_empty_xor_un_buffer, 1);
    if (st != metalSuccess) return st;
    st = ensure_buffer(g_empty_xor_uc_buffer, 1);
    if (st != metalSuccess) return st;
    st = ensure_buffer(g_empty_xor_hc_buffer, 1);
    if (st != metalSuccess) return st;
    st = ensure_buffer(g_results_count_buffer, sizeof(uint64_t));
    if (st != metalSuccess) return st;
    st = ensure_buffer(g_rng_state_buffer, sizeof(metal_crypto::RandomStateData));
    if (st != metalSuccess) return st;
    st = ensure_buffer(g_secp_walk_state_buffer, kSecpWalkStateBytes);
    if (st != metalSuccess) return st;

    g_filter_state = {};
    fill_xor_metadata(g_xor, g_filter_state.x);
    fill_xor_metadata(g_xor_un, g_filter_state.uncompressed);
    fill_xor_metadata(g_xor_uc, g_filter_state.uc);
    fill_xor_metadata(g_xor_hc, g_filter_state.hc);
    g_filter_storage.bloomCount = 0;
    g_filter_storage.xorCount = 0;
    g_filter_storage.xorUnCount = 0;
    g_filter_storage.xorUcCount = 0;
    g_filter_storage.xorHcCount = 0;
    for (size_t i = 0; i < g_bloom_ptrs.size(); ++i) {
        if (g_bloom_ptrs[i] != nullptr) {
            g_filter_storage.bloomCount = static_cast<uint32_t>(i + 1);
        }
    }
    for (size_t i = 0; i < metal_crypto::kXorFilterSlots; ++i) {
        if (g_xor.ptrs[i] != nullptr) g_filter_storage.xorCount = static_cast<uint32_t>(i + 1);
        if (g_xor_un.ptrs[i] != nullptr) g_filter_storage.xorUnCount = static_cast<uint32_t>(i + 1);
        if (g_xor_uc.ptrs[i] != nullptr) g_filter_storage.xorUcCount = static_cast<uint32_t>(i + 1);
        if (g_xor_hc.ptrs[i] != nullptr) g_filter_storage.xorHcCount = static_cast<uint32_t>(i + 1);
    }

    return metalSuccess;
}

metalError_t upload_runtime_state_locked() {
    metal_crypto::Stream* stream = g_dispatch_stream != nullptr ? g_dispatch_stream->stream.get() : nullptr;
    metal_crypto::Status status = runtime().copyToBufferAsync(
        g_config_buffer, 0, &g_runtime_config, sizeof(g_runtime_config), stream);
    if (!status.ok) return remember_status(status);
    mark_resource_dependency(g_config_buffer, g_dispatch_stream);
    status = runtime().copyToBufferAsync(
        g_filters_buffer, 0, &g_filter_state, sizeof(g_filter_state), stream);
    if (!status.ok) return remember_status(status);
    mark_resource_dependency(g_filters_buffer, g_dispatch_stream);
    status = runtime().copyToBufferAsync(
        g_filter_storage_buffer, 0, &g_filter_storage, sizeof(g_filter_storage), stream);
    if (status.ok) mark_resource_dependency(g_filter_storage_buffer, g_dispatch_stream);
    return remember_status(status);
}

metalError_t upload_runtime_state_dependency_aware_locked();

metalError_t sync_runtime_state() {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    metalError_t st = prepare_runtime_state_locked();
    if (st != metalSuccess) return st;
    if (g_deferred_runtime_state_depth != 0) {
        g_runtime_state_upload_pending = true;
        return remember(metalSuccess);
    }
    return upload_runtime_state_dependency_aware_locked();
}

metalError_t flush_deferred_runtime_state() {
    if (!g_runtime_state_upload_pending) {
        return metalSuccess;
    }
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    g_runtime_state_upload_pending = false;
    return upload_runtime_state_locked();
}

class DeferredRuntimeStateScope {
public:
    DeferredRuntimeStateScope() {
        ++g_deferred_runtime_state_depth;
    }

    ~DeferredRuntimeStateScope() {
        if (g_deferred_runtime_state_depth == 1) {
            g_runtime_state_upload_pending = false;
        }
        --g_deferred_runtime_state_depth;
    }
};

bool find_allocation_locked(const void* ptr, ResolvedBuffer& out) {
    if (ptr == nullptr) {
        return false;
    }
    const auto addr = reinterpret_cast<uintptr_t>(ptr);
    for (const AllocationRecord& rec : g_allocations) {
        const auto base = reinterpret_cast<uintptr_t>(rec.base);
        if (addr >= base && addr < base + rec.size) {
            out.buffer = rec.buffer;
            out.offset = static_cast<NSUInteger>(addr - base);
            out.available = rec.size - static_cast<size_t>(out.offset);
            return true;
        }
    }
    return false;
}

bool find_allocation(const void* ptr, ResolvedBuffer& out) {
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    return find_allocation_locked(ptr, out);
}

enum class DependencyKind {
    Default,
    Single,
    Conflict,
};

struct DependencyResolution {
    DependencyKind kind = DependencyKind::Default;
    bool defaultPending = false;
    std::vector<std::shared_ptr<MetalStreamState>> streams;
};

DependencyResolution resolve_resource_dependencies(
    const std::vector<metal_crypto::Buffer>& resources) {
    DependencyResolution resolution;
    std::unordered_map<uint64_t, std::shared_ptr<MetalStreamState>> streams;
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    for (const metal_crypto::Buffer& resource : resources) {
        const void* key = resource_key(resource);
        auto found = g_resource_dependencies.find(key);
        if (found == g_resource_dependencies.end()) continue;
        resolution.defaultPending = resolution.defaultPending || found->second.defaultPending;
        for (const auto& dependency : found->second.streams) {
            streams[dependency.first] = dependency.second;
        }
    }
    resolution.streams.reserve(streams.size());
    for (auto& dependency : streams) {
        resolution.streams.push_back(std::move(dependency.second));
    }
    if (resolution.streams.empty()) {
        resolution.kind = DependencyKind::Default;
    } else if (resolution.streams.size() == 1 && !resolution.defaultPending) {
        resolution.kind = DependencyKind::Single;
    } else {
        resolution.kind = DependencyKind::Conflict;
    }
    return resolution;
}

metalError_t synchronize_dependencies(const DependencyResolution& resolution) {
    metalError_t firstError = metalSuccess;
    DeviceState& state = device_state();
    if (resolution.defaultPending) {
        const metal_crypto::Status status = synchronize_resource_sequence(state, {});
        if (!status.ok && firstError == metalSuccess) firstError = remember_status(status);
    }
    for (const std::shared_ptr<MetalStreamState>& stream : resolution.streams) {
        const metal_crypto::Status status = synchronize_resource_sequence(state, stream);
        if (!status.ok && firstError == metalSuccess) firstError = remember_status(status);
    }
    return remember(firstError);
}

metalError_t synchronize_device_state(DeviceState& state) {
    std::vector<std::shared_ptr<MetalStreamState>> streamSnapshot;
    {
        std::lock_guard<std::mutex> registryLock(state.streamsMutex);
        streamSnapshot.reserve(state.streams.size());
        for (const auto& entry : state.streams) {
            streamSnapshot.push_back(entry.second);
        }
    }

    metalError_t firstError = metalSuccess;
    metal_crypto::Status status = synchronize_resource_sequence(state, {});
    if (!status.ok) firstError = remember_status(status);
    for (const std::shared_ptr<MetalStreamState>& stream : streamSnapshot) {
        status = synchronize_resource_sequence(state, stream);
        if (!status.ok && firstError == metalSuccess) firstError = remember_status(status);
    }
    return firstError;
}

std::vector<DeviceState*> snapshot_initialized_device_states() {
    std::vector<std::pair<int, DeviceState*>> candidates;
    {
        std::lock_guard<std::mutex> devicesLock(g_devices_mutex);
        candidates.reserve(g_devices.size());
        for (const auto& entry : g_devices) {
            candidates.emplace_back(entry.first, entry.second.get());
        }
    }
    std::sort(candidates.begin(), candidates.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.first < rhs.first;
    });

    std::vector<DeviceState*> initialized;
    initialized.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        DeviceState* state = candidate.second;
        std::lock_guard<std::mutex> runtimeLock(state->runtimeMutex);
        if (state->runtime.ready()) initialized.push_back(state);
    }
    return initialized;
}

metalError_t synchronize_repack_resources(const std::vector<ResolvedBuffer>& resolved) {
    std::vector<metal_crypto::Buffer> resources;
    resources.reserve(resolved.size());
    for (const ResolvedBuffer& source : resolved) {
        if (source.buffer.valid()) resources.push_back(source.buffer);
    }
    return synchronize_dependencies(resolve_resource_dependencies(resources));
}

std::vector<metal_crypto::Buffer> collect_launch_resources(
    const std::vector<LaunchBinding>& bindings,
    const std::vector<metal_crypto::Buffer>& indirectResources) {
    std::vector<metal_crypto::Buffer> resources;
    resources.reserve(bindings.size() + indirectResources.size());
    std::unordered_map<const void*, bool> seen;
    auto append = [&](const metal_crypto::Buffer& buffer) {
        const void* key = resource_key(buffer);
        if (key != nullptr && seen.emplace(key, true).second) {
            resources.push_back(buffer);
        }
    };
    for (const LaunchBinding& binding : bindings) {
        if (binding.track_dependency && !binding.is_nil) append(binding.buffer);
    }
    for (const metal_crypto::Buffer& buffer : indirectResources) append(buffer);
    return resources;
}

metalError_t select_dependency_stream(const DependencyResolution& resolution,
                                     MetalStreamLease& launchLease,
                                     std::shared_ptr<MetalStreamState>& launchStream) {
    launchLease = {};
    launchStream.reset();
    if (resolution.kind == DependencyKind::Single) {
        if (lease_dependency_stream(resolution.streams.front(), launchLease)) {
            launchStream = launchLease.owner;
            return metalSuccess;
        }
        return synchronize_dependencies(resolution);
    }
    if (resolution.kind == DependencyKind::Conflict) {
        return synchronize_dependencies(resolution);
    }
    return metalSuccess;
}

metalError_t upload_runtime_state_dependency_aware_locked() {
    const std::vector<metal_crypto::Buffer> resources = {
        g_config_buffer,
        g_filters_buffer,
        g_filter_storage_buffer,
    };
    const DependencyResolution resolution = resolve_resource_dependencies(resources);
    MetalStreamLease uploadLease;
    std::shared_ptr<MetalStreamState> uploadStream;
    metalError_t st = select_dependency_stream(resolution, uploadLease, uploadStream);
    if (st != metalSuccess) return st;
    auto sequenceLock = submit_resource_sequence(device_state(), uploadStream);
    DispatchStreamScope dispatchStreamScope(uploadStream);
    return upload_runtime_state_locked();
}

metalError_t submit_dependency_aware_launch(
    const std::string& name,
    NSUInteger totalThreads,
    NSUInteger threadsPerThreadgroup,
    const std::vector<LaunchBinding>& bindings,
    const std::vector<metal_crypto::Buffer>& indirectResources,
    const std::string& pipelineKey = std::string(),
    const std::function<void(MTLFunctionConstantValues*)>& constants = {});

const metal_crypto::Buffer& active_bloom_storage_buffer() {
    return g_bloom_storage_buffer.valid() ? g_bloom_storage_buffer : g_empty_bloom_buffer;
}

const metal_crypto::Buffer& active_xor_storage_buffer() {
    return g_xor_storage_buffer.valid() ? g_xor_storage_buffer : g_empty_xor_buffer;
}

const metal_crypto::Buffer& active_xor_un_storage_buffer() {
    return g_xor_un_storage_buffer.valid() ? g_xor_un_storage_buffer : g_empty_xor_un_buffer;
}

const metal_crypto::Buffer& active_xor_uc_storage_buffer() {
    return g_xor_uc_storage_buffer.valid() ? g_xor_uc_storage_buffer : g_empty_xor_uc_buffer;
}

const metal_crypto::Buffer& active_xor_hc_storage_buffer() {
    return g_xor_hc_storage_buffer.valid() ? g_xor_hc_storage_buffer : g_empty_xor_hc_buffer;
}

metalError_t checked_add_size(size_t& total, size_t add) {
    if (add > std::numeric_limits<size_t>::max() - total) {
        return remember(metalErrorInvalidValue);
    }
    total += add;
    return metalSuccess;
}

metalError_t copy_resolved_to_packed(const ResolvedBuffer& resolved,
                                    size_t bytes,
                                    metal_crypto::Buffer& packed,
                                    size_t offset) {
    if (!resolved.buffer.valid() || resolved.buffer.contents() == nullptr || bytes > resolved.available) {
        return remember(metalErrorInvalidDevicePointer);
    }
    const auto* src = static_cast<const uint8_t*>(resolved.buffer.contents()) + resolved.offset;
    metal_crypto::Status status = runtime().copyToBuffer(packed, src, bytes, offset);
    return remember_status(status);
}

metalError_t rebuild_bloom_storage() {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    metalError_t st = ensure_runtime();
    if (st != metalSuccess) return st;

    size_t total = 0;
    std::vector<ResolvedBuffer> resolved(g_bloom_ptrs.size());
    std::vector<size_t> bytes(g_bloom_ptrs.size(), 0);
    int highest = -1;
    for (size_t i = 0; i < g_bloom_ptrs.size(); ++i) {
        g_filter_storage.bloomOffsets[i] = 0;
        g_filter_storage.bloomSizes[i] = 0;
        if (g_bloom_ptrs[i] == nullptr) {
            continue;
        }
        if (!find_allocation(g_bloom_ptrs[i], resolved[i])) {
            return remember(metalErrorInvalidDevicePointer);
        }
        bytes[i] = resolved[i].available;
        st = checked_add_size(total, bytes[i]);
        if (st != metalSuccess) return st;
        highest = static_cast<int>(i);
    }

    st = synchronize_repack_resources(resolved);
    if (st != metalSuccess) return st;

    metal_crypto::Buffer packed;
    metal_crypto::Status status = runtime().makeBuffer(std::max<size_t>(total, 1), packed);
    if (!status.ok) return remember_status(status);

    size_t offset = 0;
    for (size_t i = 0; i < g_bloom_ptrs.size(); ++i) {
        if (g_bloom_ptrs[i] == nullptr) {
            continue;
        }
        g_filter_storage.bloomOffsets[i] = static_cast<uint64_t>(offset);
        g_filter_storage.bloomSizes[i] = static_cast<uint64_t>(bytes[i]);
        if (bytes[i] != 0) {
            st = copy_resolved_to_packed(resolved[i], bytes[i], packed, offset);
            if (st != metalSuccess) return st;
        }
        offset += bytes[i];
    }
    g_filter_storage.bloomCount = highest >= 0 ? static_cast<uint32_t>(highest + 1) : 0u;
    g_bloom_storage_buffer = packed;
    return remember(metalSuccess);
}

metalError_t rebuild_xor_storage(const XorFilterUploadMetadata& metadata,
                                metal_crypto::Buffer& storageBuffer,
                                uint64_t* offsets,
                                uint32_t& count) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    metalError_t st = ensure_runtime();
    if (st != metalSuccess) return st;

    size_t total = 0;
    std::vector<ResolvedBuffer> resolved(metal_crypto::kXorFilterSlots);
    int highest = -1;
    for (size_t i = 0; i < metal_crypto::kXorFilterSlots; ++i) {
        offsets[i] = 0;
        if (metadata.ptrs[i] == nullptr) {
            continue;
        }
        if (!find_allocation(metadata.ptrs[i], resolved[i])) {
            return remember(metalErrorInvalidDevicePointer);
        }
        if (metadata.bytes[i] > resolved[i].available) {
            return remember(metalErrorInvalidValue);
        }
        st = checked_add_size(total, metadata.bytes[i]);
        if (st != metalSuccess) return st;
        highest = static_cast<int>(i);
    }

    st = synchronize_repack_resources(resolved);
    if (st != metalSuccess) return st;

    metal_crypto::Buffer packed;
    metal_crypto::Status status = runtime().makeBuffer(std::max<size_t>(total, 1), packed);
    if (!status.ok) return remember_status(status);

    size_t offset = 0;
    for (size_t i = 0; i < metal_crypto::kXorFilterSlots; ++i) {
        if (metadata.ptrs[i] == nullptr) {
            continue;
        }
        offsets[i] = static_cast<uint64_t>(offset);
        if (metadata.bytes[i] != 0) {
            st = copy_resolved_to_packed(resolved[i], metadata.bytes[i], packed, offset);
            if (st != metalSuccess) return st;
        }
        offset += metadata.bytes[i];
    }
    count = highest >= 0 ? static_cast<uint32_t>(highest + 1) : 0u;
    storageBuffer = packed;
    return remember(metalSuccess);
}

metalError_t push_pointer_binding(std::vector<LaunchBinding>& bindings, const void* ptr) {
    if (ptr == nullptr) {
        bindings.push_back(LaunchBinding{metal_crypto::Buffer(), 0, true, false});
        return metalSuccess;
    }
    ResolvedBuffer resolved;
    if (!find_allocation(ptr, resolved)) {
        return remember(metalErrorInvalidDevicePointer);
    }
    bindings.push_back(LaunchBinding{resolved.buffer, resolved.offset, false, true});
    return metalSuccess;
}

metalError_t push_buffer_binding(std::vector<LaunchBinding>& bindings, const metal_crypto::Buffer& buffer) {
    if (!buffer.valid()) {
        bindings.push_back(LaunchBinding{metal_crypto::Buffer(), 0, true, false});
    } else {
        bindings.push_back(LaunchBinding{buffer, 0, false, true});
    }
    return metalSuccess;
}

metalError_t encode_buffer_resource(id<MTLArgumentEncoder> encoder, NSUInteger index, const metal_crypto::Buffer& buffer) {
    if (!buffer.valid()) {
        [encoder setBuffer:nil offset:0 atIndex:index];
        return metalSuccess;
    }
    [encoder setBuffer:buffer.native() offset:0 atIndex:index];
    return metalSuccess;
}

metalError_t push_value_binding(std::vector<LaunchBinding>& bindings,
                               std::vector<metal_crypto::Buffer>& temporaries,
                               const void* data,
                               size_t bytes) {
    metalError_t st = ensure_runtime();
    if (st != metalSuccess) {
        return st;
    }
    metal_crypto::Buffer buffer;
    metal_crypto::Status status = runtime().makeBuffer(std::max<size_t>(bytes, 1), buffer);
    if (!status.ok) {
        return remember_status(status);
    }
    if (bytes != 0 && data != nullptr) {
        status = runtime().copyToBuffer(buffer, data, bytes);
    } else {
        status = runtime().memsetBuffer(buffer, 0, std::max<size_t>(bytes, 1));
    }
    if (!status.ok) {
        return remember_status(status);
    }
    temporaries.push_back(buffer);
    bindings.push_back(LaunchBinding{buffer, 0, false, true});
    return metalSuccess;
}

metalError_t push_launch_arg(std::vector<LaunchBinding>& bindings,
                            std::vector<metal_crypto::Buffer>& temporaries,
                            const MetalLaunchArg& arg) {
    if (arg.kind == MetalLaunchArg::Kind::Pointer) {
        return push_pointer_binding(bindings, arg.data);
    }
    return push_value_binding(bindings, temporaries, arg.data, arg.size);
}

metalError_t append_original_args(std::vector<LaunchBinding>& bindings,
                                 std::vector<metal_crypto::Buffer>& temporaries,
                                 const MetalLaunchArg* args,
                                 size_t begin,
                                 size_t end) {
    for (size_t i = begin; i < end; ++i) {
        metalError_t st = push_launch_arg(bindings, temporaries, args[i]);
        if (st != metalSuccess) {
            return st;
        }
    }
    return metalSuccess;
}

metalError_t append_filter_bindings(std::vector<LaunchBinding>& bindings) {
    metalError_t st = sync_runtime_state();
    if (st != metalSuccess) return st;
    push_buffer_binding(bindings, g_config_buffer);
    push_buffer_binding(bindings, g_filters_buffer);
    push_buffer_binding(bindings, g_filter_storage_buffer);
    push_buffer_binding(bindings, active_bloom_storage_buffer());
    push_buffer_binding(bindings, active_xor_storage_buffer());
    push_buffer_binding(bindings, active_xor_un_storage_buffer());
    push_buffer_binding(bindings, active_xor_uc_storage_buffer());
    push_buffer_binding(bindings, active_xor_hc_storage_buffer());
    return metalSuccess;
}

metalError_t append_filter_bindings_no_hc(std::vector<LaunchBinding>& bindings) {
    metalError_t st = sync_runtime_state();
    if (st != metalSuccess) return st;
    push_buffer_binding(bindings, g_config_buffer);
    push_buffer_binding(bindings, g_filters_buffer);
    push_buffer_binding(bindings, g_filter_storage_buffer);
    push_buffer_binding(bindings, active_bloom_storage_buffer());
    push_buffer_binding(bindings, active_xor_storage_buffer());
    push_buffer_binding(bindings, active_xor_un_storage_buffer());
    push_buffer_binding(bindings, active_xor_uc_storage_buffer());
    return metalSuccess;
}

metalError_t append_xp_runtime_bindings(std::vector<LaunchBinding>& bindings,
                                       std::vector<metal_crypto::Buffer>& temporaries) {
    metalError_t st = append_filter_bindings(bindings);
    if (st != metalSuccess) return st;

    XpRuntimeParamsHost params;
    params.randstormSeedEvents = read_symbol_or_default<uint32_t>("d_xp_randstorm_seed_events", 0u);
    params.randstormScreenSeedX = read_symbol_or_default<uint32_t>("d_xp_randstorm_screen_seed_x", 0u);
    params.randstormScreenSeedY = read_symbol_or_default<uint32_t>("d_xp_randstorm_screen_seed_y", 0u);
    params.randstormTimeMode = read_symbol_or_default<uint32_t>("d_xp_randstorm_time_mode", 0u);
    params.randstormMileageStart = read_symbol_or_default<uint32_t>("d_xp_randstorm_mileage_start", 0u);
    params.randstormMileageCount = read_symbol_or_default<uint64_t>("d_xp_randstorm_mileage_count", 1ull);
    return push_value_binding(bindings, temporaries, &params, sizeof(params));
}

metalError_t append_found_full(std::vector<LaunchBinding>& bindings, bool include_iter, bool include_deriv2, bool include_seed, bool include_substrate) {
    metalError_t st = push_pointer_binding(bindings, g_found.foundStrings);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundPrvKeys);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundHash160);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundLen);
    if (st != metalSuccess) return st;
    if (include_iter) {
        st = push_pointer_binding(bindings, g_found.foundIter);
        if (st != metalSuccess) return st;
    }
    st = push_pointer_binding(bindings, g_found.foundType);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundDerivations);
    if (st != metalSuccess) return st;
    if (include_deriv2) {
        st = push_pointer_binding(bindings, g_found.foundDerivations2);
        if (st != metalSuccess) return st;
    }
    st = push_pointer_binding(bindings, g_found.pass);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.passSize);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.round);
    if (st != metalSuccess) return st;
    if (include_seed) {
        st = push_pointer_binding(bindings, g_found.seed);
        if (st != metalSuccess) return st;
    }
    st = push_buffer_binding(bindings, g_results_count_buffer);
    if (st != metalSuccess) return st;
    if (include_substrate) {
        st = push_pointer_binding(bindings, g_found.substratePaths);
    }
    return st;
}

metalError_t append_found_vanity_tables(std::vector<LaunchBinding>& bindings) {
    metalError_t st = push_pointer_binding(bindings, g_found.foundStrings);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundPrvKeys);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundHash160);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundLen);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_vanity_gx);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundType);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundDerivations);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundDerivations2);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.pass);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.passSize);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.round);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.seed);
    if (st != metalSuccess) return st;
    return push_buffer_binding(bindings, g_results_count_buffer);
}

metalError_t append_found_priv_minimal(std::vector<LaunchBinding>& bindings, bool include_substrate) {
    metalError_t st = push_pointer_binding(bindings, g_found.foundPrvKeys);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundHash160);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundType);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.round);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.seed);
    if (st != metalSuccess) return st;
    st = push_buffer_binding(bindings, g_results_count_buffer);
    if (st != metalSuccess) return st;
    if (include_substrate) {
        st = push_pointer_binding(bindings, g_found.substratePaths);
    }
    return st;
}

metalError_t append_found_flexible(std::vector<LaunchBinding>& bindings,
                                  bool include_strings,
                                  bool include_prv,
                                  bool include_hash,
                                  bool include_len,
                                  bool include_iter,
                                  bool include_type,
                                  bool include_deriv,
                                  bool include_deriv2,
                                  bool include_pass,
                                  bool include_pass_size,
                                  bool include_round,
                                  bool include_seed,
                                  bool include_count,
                                  bool include_substrate) {
    metalError_t st = metalSuccess;
    if (include_strings && (st = push_pointer_binding(bindings, g_found.foundStrings)) != metalSuccess) return st;
    if (include_prv && (st = push_pointer_binding(bindings, g_found.foundPrvKeys)) != metalSuccess) return st;
    if (include_hash && (st = push_pointer_binding(bindings, g_found.foundHash160)) != metalSuccess) return st;
    if (include_len && (st = push_pointer_binding(bindings, g_found.foundLen)) != metalSuccess) return st;
    if (include_iter && (st = push_pointer_binding(bindings, g_found.foundIter)) != metalSuccess) return st;
    if (include_type && (st = push_pointer_binding(bindings, g_found.foundType)) != metalSuccess) return st;
    if (include_deriv && (st = push_pointer_binding(bindings, g_found.foundDerivations)) != metalSuccess) return st;
    if (include_deriv2 && (st = push_pointer_binding(bindings, g_found.foundDerivations2)) != metalSuccess) return st;
    if (include_pass && (st = push_pointer_binding(bindings, g_found.pass)) != metalSuccess) return st;
    if (include_pass_size && (st = push_pointer_binding(bindings, g_found.passSize)) != metalSuccess) return st;
    if (include_round && (st = push_pointer_binding(bindings, g_found.round)) != metalSuccess) return st;
    if (include_seed && (st = push_pointer_binding(bindings, g_found.seed)) != metalSuccess) return st;
    if (include_count && (st = push_buffer_binding(bindings, g_results_count_buffer)) != metalSuccess) return st;
    if (include_substrate && (st = push_pointer_binding(bindings, g_found.substratePaths)) != metalSuccess) return st;
    return metalSuccess;
}

metalError_t append_priv_minimal_no_seed(std::vector<LaunchBinding>& bindings, bool include_substrate) {
    metalError_t st = push_pointer_binding(bindings, g_found.foundPrvKeys);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundHash160);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.foundType);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.round);
    if (st != metalSuccess) return st;
    st = push_buffer_binding(bindings, g_results_count_buffer);
    if (st != metalSuccess) return st;
    if (include_substrate) {
        st = push_pointer_binding(bindings, g_found.substratePaths);
    }
    return st;
}

metalError_t append_wallet_results(std::vector<LaunchBinding>& bindings,
                                  std::vector<metal_crypto::Buffer>& temporaries,
                                  bool include_window_sizes) {
    metalError_t st = push_pointer_binding(bindings, g_found.walletResults);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.walletCount);
    if (st != metalSuccess) return st;
    const uint32_t max_founds = g_runtime_config.maxFounds;
    st = push_value_binding(bindings, temporaries, &max_founds, sizeof(max_founds));
    if (st != metalSuccess) return st;
    if (include_window_sizes) {
        const uint32_t zero = 0;
        st = push_value_binding(bindings, temporaries, &zero, sizeof(zero));
        if (st != metalSuccess) return st;
        st = push_value_binding(bindings, temporaries, &zero, sizeof(zero));
    }
    return st;
}

RuntimePointersHost make_runtime_pointers() {
    RuntimePointersHost rt;
    rt.config = g_config_buffer.contents();
    rt.filters = g_filters_buffer.contents();
    rt.filterStorage = g_filter_storage_buffer.contents();
    rt.bloomStorage = active_bloom_storage_buffer().contents();
    rt.xorStorage = active_xor_storage_buffer().contents();
    rt.xorUnStorage = active_xor_un_storage_buffer().contents();
    rt.xorUcStorage = active_xor_uc_storage_buffer().contents();
    rt.xorHcStorage = active_xor_hc_storage_buffer().contents();
    rt.foundStrings = g_found.foundStrings;
    rt.foundPrvKeys = g_found.foundPrvKeys;
    rt.foundHash160 = g_found.foundHash160;
    rt.foundLen = g_found.foundLen;
    rt.foundIter = g_found.foundIter;
    rt.foundType = g_found.foundType;
    rt.foundDerivations = g_found.foundDerivations;
    rt.foundDerivations2 = g_found.foundDerivations2;
    rt.foundPass = g_found.pass;
    rt.foundPassSize = g_found.passSize;
    rt.foundRound = g_found.round;
    rt.foundSeed = g_found.seed;
    rt.resultsCount = g_results_count_buffer.contents();
    rt.substratePaths = g_found.substratePaths;
    return rt;
}

RecoveryRuntimePointersHost make_recovery_runtime_pointers() {
    RuntimePointersHost base = make_runtime_pointers();
    RecoveryRuntimePointersHost rt;
    std::memcpy(&rt, &base, sizeof(RecoveryRuntimePointersHost) - sizeof(void*));
    rt.customDict = g_found.customDict;
    return rt;
}

XpRuntimePointersHost make_xp_runtime_pointers() {
    XpRuntimePointersHost rt;
    rt.config = g_config_buffer.contents();
    rt.filters = g_filters_buffer.contents();
    rt.filterStorage = g_filter_storage_buffer.contents();
    rt.bloomStorage = active_bloom_storage_buffer().contents();
    rt.xorStorage = active_xor_storage_buffer().contents();
    rt.xorUnStorage = active_xor_un_storage_buffer().contents();
    rt.xorUcStorage = active_xor_uc_storage_buffer().contents();
    rt.xorHcStorage = active_xor_hc_storage_buffer().contents();
    rt.xpResults = g_found.xpResults;
    rt.xpCount = g_found.xpCount;
    rt.randstormSeedEvents = read_symbol_or_default<uint32_t>("d_xp_randstorm_seed_events", 0u);
    rt.randstormScreenSeedX = read_symbol_or_default<uint32_t>("d_xp_randstorm_screen_seed_x", 0u);
    rt.randstormScreenSeedY = read_symbol_or_default<uint32_t>("d_xp_randstorm_screen_seed_y", 0u);
    rt.randstormTimeMode = read_symbol_or_default<uint32_t>("d_xp_randstorm_time_mode", 0u);
    rt.randstormMileageStart = read_symbol_or_default<uint32_t>("d_xp_randstorm_mileage_start", 0u);
    rt.randstormMileageCount = read_symbol_or_default<uint64_t>("d_xp_randstorm_mileage_count", 1ull);
    return rt;
}

metalError_t append_runtime_argument_buffer(std::vector<LaunchBinding>& bindings,
                                           std::vector<metal_crypto::Buffer>& temporaries,
                                           std::vector<metal_crypto::Buffer>& indirect_resources,
                                           const std::string& function_name,
                                           const std::string& pipeline_key,
                                           const std::function<void(MTLFunctionConstantValues*)>& constants,
                                           bool recovery_runtime,
                                           bool mnemonic_runtime) {
    metalError_t st = sync_runtime_state();
    if (st != metalSuccess) return st;
    const NSUInteger buffer_index = static_cast<NSUInteger>(bindings.size());
    metal_crypto::Buffer argument_buffer;
    metalError_t encode_status = metalSuccess;
    metal_crypto::Status status = runtime().makeArgumentBuffer(
        function_name,
        buffer_index,
        pipeline_key,
        constants,
        [&](id<MTLArgumentEncoder> encoder) {
            auto remember_indirect = [&](const metal_crypto::Buffer& buffer) {
                if (buffer.valid()) {
                    indirect_resources.push_back(buffer);
                }
            };
            auto encode_buffer = [&](NSUInteger index, const metal_crypto::Buffer& buffer) {
                if (encode_status == metalSuccess) {
                    encode_status = encode_buffer_resource(encoder, index, buffer);
                    if (encode_status == metalSuccess) {
                        remember_indirect(buffer);
                    }
                }
            };
            auto encode_pointer = [&](NSUInteger index, const void* ptr) {
                if (encode_status != metalSuccess) {
                    return;
                }
                if (ptr == nullptr) {
                    [encoder setBuffer:nil offset:0 atIndex:index];
                    return;
                }
                ResolvedBuffer resolved;
                if (!find_allocation(ptr, resolved)) {
                    encode_status = remember(metalErrorInvalidDevicePointer);
                    return;
                }
                [encoder setBuffer:resolved.buffer.native() offset:resolved.offset atIndex:index];
                remember_indirect(resolved.buffer);
            };

            encode_buffer(0, g_config_buffer);
            encode_buffer(1, g_filters_buffer);
            encode_buffer(2, g_filter_storage_buffer);
            encode_buffer(3, active_bloom_storage_buffer());
            encode_buffer(4, active_xor_storage_buffer());
            encode_buffer(5, active_xor_un_storage_buffer());
            encode_buffer(6, active_xor_uc_storage_buffer());
            encode_buffer(7, active_xor_hc_storage_buffer());
            encode_pointer(8, g_found.foundStrings);
            encode_pointer(9, g_found.foundPrvKeys);
            encode_pointer(10, g_found.foundHash160);
            encode_pointer(11, g_found.foundLen);
            encode_pointer(12, g_found.foundIter);
            encode_pointer(13, g_found.foundType);
            encode_pointer(14, g_found.foundDerivations);
            encode_pointer(15, g_found.foundDerivations2);
            encode_pointer(16, g_found.pass);
            encode_pointer(17, g_found.passSize);
            encode_pointer(18, g_found.round);
            encode_pointer(19, g_found.seed);
            encode_buffer(20, g_results_count_buffer);
            encode_pointer(21, recovery_runtime ? g_found.customDict : g_found.substratePaths);
            if (mnemonic_runtime) {
                encode_pointer(22, g_found.customDict);
            }
        },
        argument_buffer);
    if (!status.ok) {
        return remember_status(status);
    }
    if (encode_status != metalSuccess) {
        return encode_status;
    }
    temporaries.push_back(argument_buffer);
    bindings.push_back(LaunchBinding{argument_buffer, 0, false, true});
    return metalSuccess;
}

uint64_t read_value_u64(const MetalLaunchArg& arg) {
    uint64_t out = 0;
    if (arg.kind == MetalLaunchArg::Kind::Value && arg.data != nullptr) {
        std::memcpy(&out, arg.data, std::min<size_t>(arg.size, sizeof(out)));
    }
    return out;
}

uint32_t read_value_u32(const MetalLaunchArg& arg) {
    return static_cast<uint32_t>(read_value_u64(arg));
}

bool read_value_bool(const MetalLaunchArg& arg) {
    if (arg.kind != MetalLaunchArg::Kind::Value || arg.data == nullptr || arg.size == 0) {
        return false;
    }
    uint8_t v = 0;
    std::memcpy(&v, arg.data, 1);
    return v != 0;
}

metalError_t append_derthread_packed_launch(std::vector<LaunchBinding>& bindings,
                                           std::vector<metal_crypto::Buffer>& temporaries,
                                           const std::string& name,
                                           const MetalLaunchArg* args,
                                           size_t count) {
    if (name == "workerDerThread_bip32_compressed") {
        if (count < 17) return remember(metalErrorInvalidValue);
        metalError_t st = append_original_args(bindings, temporaries, args, 0, 6);
        if (st != metalSuccess) return st;
        st = push_launch_arg(bindings, temporaries, args[7]);
        if (st != metalSuccess) return st;
        st = push_launch_arg(bindings, temporaries, args[11]);
        if (st != metalSuccess) return st;
        st = push_launch_arg(bindings, temporaries, args[12]);
        if (st != metalSuccess) return st;
        st = push_launch_arg(bindings, temporaries, args[13]);
        if (st != metalSuccess) return st;
        DerThreadRunParamsHost params;
        params.d_save_len = read_value_u32(args[6]);
        params.pass_len = read_value_u32(args[8]);
        params.seed_value = read_value_u64(args[9]);
        params.store_seed = read_value_bool(args[10]) ? 1u : 0u;
        params.der_indexes_size = read_value_u32(args[14]);
        params.der_offset = read_value_u32(args[15]);
        params.round = read_value_u64(args[16]);
        st = push_value_binding(bindings, temporaries, &params, sizeof(params));
        if (st != metalSuccess) return st;
        st = append_filter_bindings(bindings);
        if (st != metalSuccess) return st;
        return append_found_full(bindings, false, false, true, false);
    }
    if (name == "workerDerThread_slip0010_solana") {
        if (count < 16) return remember(metalErrorInvalidValue);
        metalError_t st = append_original_args(bindings, temporaries, args, 0, 5);
        if (st != metalSuccess) return st;
        st = push_launch_arg(bindings, temporaries, args[6]);
        if (st != metalSuccess) return st;
        st = push_launch_arg(bindings, temporaries, args[10]);
        if (st != metalSuccess) return st;
        st = push_launch_arg(bindings, temporaries, args[11]);
        if (st != metalSuccess) return st;
        st = push_launch_arg(bindings, temporaries, args[12]);
        if (st != metalSuccess) return st;
        DerThreadRunParamsHost params;
        params.d_save_len = read_value_u32(args[5]);
        params.pass_len = read_value_u32(args[7]);
        params.seed_value = read_value_u64(args[8]);
        params.store_seed = read_value_bool(args[9]) ? 1u : 0u;
        params.der_indexes_size = read_value_u32(args[13]);
        params.der_offset = read_value_u32(args[14]);
        params.round = read_value_u64(args[15]);
        st = push_value_binding(bindings, temporaries, &params, sizeof(params));
        if (st != metalSuccess) return st;
        st = append_filter_bindings(bindings);
        if (st != metalSuccess) return st;
        return append_found_full(bindings, false, false, true, false);
    }
    return remember(metalErrorInvalidValue);
}

metalError_t handle_config_setter(const std::string& name, const MetalLaunchArg* args, size_t count) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (name == "setHEX") {
        g_runtime_config.isHex = 1u;
        return remember(metalSuccess);
    }
    if (name == "setUTF8") {
        g_runtime_config.utf8 = 1u;
        UTF8 = true;
        return remember(metalSuccess);
    }
    if (name == "setPASS") {
        g_runtime_config.isPass = 1u;
        return remember(metalSuccess);
    }
    if (name == "setFULL") {
        g_runtime_config.full = 1u;
        return remember(metalSuccess);
    }
    if (name == "setLE") {
        g_runtime_config.isLittleEndian = 1u;
        return remember(metalSuccess);
    }
    if (name == "setEd25519_scalar") {
        g_runtime_config.isEd25519Scalar = 1u;
        g_runtime_config.isEd25519Hash = 0u;
        return remember(metalSuccess);
    }
    if (name == "setEd25519_hash") {
        g_runtime_config.isEd25519Scalar = 0u;
        g_runtime_config.isEd25519Hash = 1u;
        return remember(metalSuccess);
    }
    if (name == "setFoundSize" && count >= 1) {
        g_runtime_config.maxFounds = read_value_u32(args[0]);
        return remember(metalSuccess);
    }
    if (name == "SetDeep" && count >= 1) {
        g_runtime_config.deep = read_value_u32(args[0]);
        return remember(metalSuccess);
    }
    if (name == "SetDerivationTypeMask" && count >= 1) {
        g_runtime_config.derivationTypeMask = read_value_u32(args[0]) & 0xffu;
        return remember(metalSuccess);
    }
    if (name == "SetSeqStep" && count >= 1) {
        g_runtime_config.seqStep = read_value_u64(args[0]);
        return remember(metalSuccess);
    }
    if (name == "SetSkipDev" && count >= 1) {
        g_runtime_config.skip = read_value_u64(args[0]);
        return remember(metalSuccess);
    }
    if (name == "SetSkipDev64" && count >= 1) {
        g_runtime_config.skip64 = read_value_u64(args[0]);
        return remember(metalSuccess);
    }
    if (name == "setFilterType" && count >= 5) {
        g_runtime_config.useBloom = read_value_u32(args[0]);
        g_runtime_config.useXor = read_value_u32(args[1]);
        g_runtime_config.useXorUn = read_value_u32(args[2]);
        g_runtime_config.useXorUc = read_value_u32(args[3]);
        g_runtime_config.useXorHc = read_value_u32(args[4]);
        uint64_t rng_counter = 0x726b2b9d438b9d4dull;
        g_runtime_config.seed = host_rng_splitmix64(rng_counter);
        return remember(metalSuccess);
    }
    if (name == "setDict" && count >= 1) {
        const int lang = static_cast<int>(read_value_u32(args[0]));
        if (g_runtime_config.oldElectrum == 0u) {
            g_runtime_config.dictLang = (lang >= 0 && lang <= 9) ? static_cast<uint32_t>(lang) : 0u;
            metalError_t st = ensure_builtin_dict_for_lang(static_cast<int>(g_runtime_config.dictLang));
            if (st != metalSuccess) {
                return st;
            }
            g_runtime_config.useCustomDict = (g_found.customDict != nullptr) ? 1u : 0u;
        }
        return remember(metalSuccess);
    }
    if (name == "setDictPointer" && count >= 1) {
        g_found.customDict = const_cast<void*>(args[0].data);
        if (g_runtime_config.oldElectrum == 0u) {
            g_runtime_config.useCustomDict = (g_found.customDict != nullptr) ? 1u : 0u;
        }
        return remember(metalSuccess);
    }
    if (name == "set_electrum" && count >= 3) {
        g_runtime_config.electrumSegwit = read_value_bool(args[0]) ? 1u : 0u;
        g_runtime_config.electrum128 = read_value_bool(args[1]) ? 1u : 0u;
        g_runtime_config.electrumCakeWallet = read_value_bool(args[2]) ? 1u : 0u;
        return remember(metalSuccess);
    }
    if (name == "set_iter" && count >= 1) {
        g_runtime_config.pbkdf2Iterations = read_value_u64(args[0]);
        return remember(metalSuccess);
    }
    if (name == "rand_state") {
        metal_crypto::RandomStateData state{};
        state.seed = static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
        if (state.seed == 0ull) {
            state.seed = 0x6a09e667f3bcc909ull;
        }
        state.initialized = 1u;
        metalError_t st = ensure_buffer(g_rng_state_buffer, sizeof(state));
        if (st != metalSuccess) return st;
        const std::vector<metal_crypto::Buffer> resources = {g_rng_state_buffer};
        const DependencyResolution resolution = resolve_resource_dependencies(resources);
        MetalStreamLease writeLease;
        std::shared_ptr<MetalStreamState> writeStream;
        st = select_dependency_stream(resolution, writeLease, writeStream);
        if (st != metalSuccess) return st;
        auto sequenceLock = submit_resource_sequence(device_state(), writeStream);
        DispatchStreamScope dispatchStreamScope(writeStream);
        metal_crypto::Status status = runtime().copyToBufferAsync(
            g_rng_state_buffer,
            0,
            &state,
            sizeof(state),
            writeStream ? writeStream->stream.get() : nullptr);
        if (status.ok) mark_resource_dependencies(resources, writeStream);
        return remember_status(status);
    }
    if (name == "SetCurve" && count >= 27) {
        g_runtime_config.secp256 = read_value_u32(args[0]);
        g_runtime_config.ed25519 = read_value_u32(args[1]);
        g_runtime_config.electrum = read_value_u32(args[2]);
        g_runtime_config.tonMnemonic = read_value_u32(args[3]);
        g_runtime_config.tonOnly = read_value_u32(args[4]);
        g_runtime_config.oldElectrum = read_value_u32(args[5]);
        g_runtime_config.compressed = read_value_u32(args[6]);
        g_runtime_config.uncompressed = read_value_u32(args[7]);
        g_runtime_config.segwit = read_value_u32(args[8]);
        g_runtime_config.p2wsh = read_value_u32(args[9]);
        g_runtime_config.taproot = read_value_u32(args[10]);
        g_runtime_config.ethereum = read_value_u32(args[11]);
        g_runtime_config.xpoint = read_value_u32(args[12]);
        g_runtime_config.solana = read_value_u32(args[13]);
        g_runtime_config.ton = read_value_u32(args[14]);
        g_runtime_config.tonAll = read_value_u32(args[15]);
        g_runtime_config.dot = read_value_u32(args[16]);
        g_runtime_config.aptos = read_value_u32(args[17]);
        g_runtime_config.sui = read_value_u32(args[18]);
        g_runtime_config.xrp = read_value_u32(args[19]);
        g_runtime_config.exodus = read_value_u32(args[20]);
        g_runtime_config.iota = read_value_u32(args[21]);
        g_runtime_config.ada = read_value_u32(args[22]);
        g_runtime_config.icp = read_value_u32(args[23]);
        g_runtime_config.fil = read_value_u32(args[24]);
        g_runtime_config.xtz = read_value_u32(args[25]);
        g_runtime_config.endomorphism = read_value_u32(args[26]);
        const bool aptos_secp = g_runtime_config.aptos && metal_type_enabled(g_runtime_config.aptosTypeMask, 0x22u, 0x20u, 0x22u);
        const bool aptos_ed = g_runtime_config.aptos && (metal_type_enabled(g_runtime_config.aptosTypeMask, 0x20u, 0x20u, 0x22u) || metal_type_enabled(g_runtime_config.aptosTypeMask, 0x21u, 0x20u, 0x22u));
        const bool sui_secp = g_runtime_config.sui && metal_type_enabled(g_runtime_config.suiTypeMask, 0x70u, 0x70u, 0x71u);
        const bool sui_ed = g_runtime_config.sui && metal_type_enabled(g_runtime_config.suiTypeMask, 0x71u, 0x70u, 0x71u);
        const bool xrp_secp = g_runtime_config.xrp && metal_type_enabled(g_runtime_config.xrpTypeMask, 0x90u, 0x90u, 0x91u);
        const bool xrp_ed = g_runtime_config.xrp && metal_type_enabled(g_runtime_config.xrpTypeMask, 0x91u, 0x90u, 0x91u);
        const bool iota_secp = g_runtime_config.iota && metal_type_enabled(g_runtime_config.iotaTypeMask, 0x50u, 0x50u, 0x51u);
        const bool iota_ed = g_runtime_config.iota && metal_type_enabled(g_runtime_config.iotaTypeMask, 0x51u, 0x50u, 0x51u);
        const bool icp_ed = g_runtime_config.icp && metal_type_enabled(g_runtime_config.icpTypeMask, 0x52u, 0x52u, 0x53u);
        const bool icp_secp = g_runtime_config.icp && metal_type_enabled(g_runtime_config.icpTypeMask, 0x53u, 0x52u, 0x53u);
        const bool fil_secp = g_runtime_config.fil && (metal_type_enabled(g_runtime_config.filTypeMask, 0x41u, 0x41u, 0x42u) || metal_type_enabled(g_runtime_config.filTypeMask, 0x42u, 0x41u, 0x42u));
        const bool xtz_secp = g_runtime_config.xtz && metal_type_enabled(g_runtime_config.xtzTypeMask, 0x92u, 0x92u, 0x93u);
        const bool xtz_ed = g_runtime_config.xtz && metal_type_enabled(g_runtime_config.xtzTypeMask, 0x93u, 0x92u, 0x93u);
        const bool dot_ed = g_runtime_config.dot && (metal_type_enabled(g_runtime_config.dotTypeMask, 0x30u, 0x30u, 0x31u) || metal_type_enabled(g_runtime_config.dotTypeMask, 0x31u, 0x30u, 0x31u));
        const bool ton_ed = (g_runtime_config.ton || g_runtime_config.tonAll) && g_runtime_config.tonTypeMask != 0u;
        g_runtime_config.secpTargetsAny = (g_runtime_config.compressed || g_runtime_config.uncompressed || g_runtime_config.segwit || g_runtime_config.p2wsh || g_runtime_config.taproot || g_runtime_config.ethereum || g_runtime_config.xpoint || xrp_secp || aptos_secp || sui_secp || iota_secp || icp_secp || fil_secp || xtz_secp) ? 1u : 0u;
        g_runtime_config.edTargetsAny = (g_runtime_config.solana || ton_ed || dot_ed || aptos_ed || sui_ed || xrp_ed || iota_ed || icp_ed || xtz_ed || g_runtime_config.ada) ? 1u : 0u;
        return remember(metalSuccess);
    }
    return metalErrorNotSupported;
}

bool is_cpu_setter_kernel(const std::string& name) {
    static const char* names[] = {
        "setHEX", "setUTF8", "setPASS", "setFULL", "setLE", "setEd25519_scalar",
        "setEd25519_hash", "setFoundSize", "SetDeep", "SetDerivationTypeMask",
        "SetSeqStep", "SetSkipDev", "SetSkipDev64", "setFilterType", "setDict",
        "setDictPointer", "set_electrum", "set_iter", "rand_state", "SetCurve"
    };
    for (const char* n : names) {
        if (name == n) {
            return true;
        }
    }
    return false;
}

metalError_t store_xor(XorFilterUploadMetadata& dst,
                      metal_crypto::Buffer& storageBuffer,
                      uint64_t* offsets,
                      uint32_t& storageCount,
                      void* ptr,
                      int count,
                      size_t element_size,
                      size_t size_h,
                      size_t arrayLength_h,
                      size_t segmentCount_h,
                      size_t segmentCountLength_h,
                      size_t segmentLength_h,
                      size_t segmentLengthMask_h) {
    if (count < 0 || static_cast<size_t>(count) >= metal_crypto::kXorFilterSlots) {
        return remember(metalErrorInvalidValue);
    }
    const size_t i = static_cast<size_t>(count);
    dst.ptrs[i] = ptr;
    if (arrayLength_h > std::numeric_limits<size_t>::max() / element_size) {
        return remember(metalErrorInvalidValue);
    }
    dst.bytes[i] = arrayLength_h * element_size;
    dst.size[i] = size_h;
    dst.arrayLength[i] = arrayLength_h;
    dst.segmentCount[i] = segmentCount_h;
    dst.segmentCountLength[i] = segmentCountLength_h;
    dst.segmentLength[i] = segmentLength_h;
    dst.segmentLengthMask[i] = segmentLengthMask_h;
    return rebuild_xor_storage(dst, storageBuffer, offsets, storageCount);
}

metalError_t launch_xor_metadata_kernel(const char* function_name,
                                       int count,
                                       size_t size_h,
                                       size_t arrayLength_h,
                                       size_t segmentCount_h,
                                       size_t segmentCountLength_h,
                                       size_t segmentLength_h,
                                       size_t segmentLengthMask_h) {
    DeferredRuntimeStateScope deferredRuntimeState;
    metalError_t st = sync_runtime_state();
    if (st != metalSuccess) {
        return st;
    }
    std::vector<LaunchBinding> bindings;
    std::vector<metal_crypto::Buffer> temporaries;
    bindings.reserve(9);
    temporaries.reserve(7);

    st = push_buffer_binding(bindings, g_filters_buffer);
    if (st != metalSuccess) return st;
    st = push_buffer_binding(bindings, g_filter_storage_buffer);
    if (st != metalSuccess) return st;
    st = push_value_binding(bindings, temporaries, &count, sizeof(count));
    if (st != metalSuccess) return st;
    st = push_value_binding(bindings, temporaries, &size_h, sizeof(size_h));
    if (st != metalSuccess) return st;
    st = push_value_binding(bindings, temporaries, &arrayLength_h, sizeof(arrayLength_h));
    if (st != metalSuccess) return st;
    st = push_value_binding(bindings, temporaries, &segmentCount_h, sizeof(segmentCount_h));
    if (st != metalSuccess) return st;
    st = push_value_binding(bindings, temporaries, &segmentCountLength_h, sizeof(segmentCountLength_h));
    if (st != metalSuccess) return st;
    st = push_value_binding(bindings, temporaries, &segmentLength_h, sizeof(segmentLength_h));
    if (st != metalSuccess) return st;
    st = push_value_binding(bindings, temporaries, &segmentLengthMask_h, sizeof(segmentLengthMask_h));
    if (st != metalSuccess) return st;

    const std::vector<metal_crypto::Buffer> indirectResources;
    return submit_dependency_aware_launch(function_name, 1, 1, bindings, indirectResources);
}

void update_pointer_symbol(const char* symbol, void* ptr) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (std::strcmp(symbol, "d_foundStrings") == 0) g_found.foundStrings = ptr;
    else if (std::strcmp(symbol, "d_foundPrvKeys") == 0) g_found.foundPrvKeys = ptr;
    else if (std::strcmp(symbol, "d_foundHash160") == 0) g_found.foundHash160 = ptr;
    else if (std::strcmp(symbol, "d_len") == 0) g_found.foundLen = ptr;
    else if (std::strcmp(symbol, "d_iter") == 0) g_found.foundIter = ptr;
    else if (std::strcmp(symbol, "d_type") == 0) g_found.foundType = ptr;
    else if (std::strcmp(symbol, "d_foundDerivations") == 0) g_found.foundDerivations = ptr;
    else if (std::strcmp(symbol, "d_foundDerivations2") == 0) g_found.foundDerivations2 = ptr;
    else if (std::strcmp(symbol, "d_pass") == 0) g_found.pass = ptr;
    else if (std::strcmp(symbol, "d_pass_size") == 0) g_found.passSize = ptr;
    else if (std::strcmp(symbol, "d_round") == 0) g_found.round = ptr;
    else if (std::strcmp(symbol, "d_seed") == 0) g_found.seed = ptr;
    else if (std::strcmp(symbol, "SUBSTRATE_PATHS_D") == 0) g_found.substratePaths = ptr;
    else if (std::strcmp(symbol, "d_profanityResults") == 0) g_found.profanityResults = ptr;
    else if (std::strcmp(symbol, "d_profanityCount") == 0) g_found.profanityCount = ptr;
    else if (std::strcmp(symbol, "d_walletResults") == 0) g_found.walletResults = ptr;
    else if (std::strcmp(symbol, "d_walletCount") == 0) g_found.walletCount = ptr;
    else if (std::strcmp(symbol, "d_xpResults") == 0) g_found.xpResults = ptr;
    else if (std::strcmp(symbol, "d_xpCount") == 0) g_found.xpCount = ptr;
}

} // namespace

const char* metalGetErrorString(metalError_t error) {
    switch (error) {
    case metalSuccess: return "metalSuccess";
    case metalErrorInvalidValue: return "metalErrorInvalidValue";
    case metalErrorMemoryAllocation: return "metalErrorMemoryAllocation";
    case metalErrorInvalidDevicePointer: return "metalErrorInvalidDevicePointer";
    case metalErrorInvalidDevice: return "metalErrorInvalidDevice";
    case metalErrorInvalidConfiguration: return "metalErrorInvalidConfiguration";
    case metalErrorNotSupported: return "metalErrorNotSupported";
    default: return "metalErrorUnknown";
    }
}

const char* metalGetErrorName(metalError_t error) {
    return metalGetErrorString(error);
}

metalError_t metalMalloc(void** ptr, size_t bytes) {
    if (ptr == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    *ptr = nullptr;
    if (bytes == 0) {
        return remember(metalSuccess);
    }
    metalError_t st = ensure_runtime();
    if (st != metalSuccess) {
        return st;
    }
    metal_crypto::Buffer buffer;
    metal_crypto::Status status = runtime().makeBuffer(bytes, buffer);
    if (!status.ok || !buffer.valid() || buffer.contents() == nullptr) {
        return remember(status.ok ? metalErrorMemoryAllocation : metalErrorUnknown);
    }
    status = runtime().memsetBuffer(buffer, 0, bytes);
    if (!status.ok) {
        return remember_status(status);
    }
    {
        std::lock_guard<std::mutex> lock(g_alloc_mutex);
        g_allocations.push_back(AllocationRecord{buffer.contents(), bytes, buffer});
        device_state().allocatedBytes += bytes;
    }
    *ptr = buffer.contents();
    return remember(metalSuccess);
}

metalError_t metalMallocManaged(void** ptr, size_t bytes) {
    return metalMalloc(ptr, bytes);
}

metalError_t metalMallocHost(void** ptr, size_t bytes) {
    if (ptr == nullptr) return remember(metalErrorInvalidValue);
    *ptr = nullptr;
    if (bytes == 0) return remember(metalSuccess);
    void* allocation = std::malloc(bytes);
    if (allocation == nullptr) return remember(metalErrorMemoryAllocation);
    {
        std::lock_guard<std::mutex> lock(g_host_alloc_mutex);
        g_host_allocations.emplace(allocation, bytes);
    }
    *ptr = allocation;
    return remember(metalSuccess);
}

metalError_t metalMallocPitch(void** ptr, size_t* pitch, size_t width, size_t height) {
    if (pitch == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    *pitch = width;
    if (ptr == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    *ptr = nullptr;
    if (height != 0 && width > std::numeric_limits<size_t>::max() / height) {
        return remember(metalErrorInvalidValue);
    }
    return metalMalloc(ptr, width * height);
}

metalError_t metalFree(void* ptr) {
    if (ptr == nullptr) {
        return remember(metalSuccess);
    }
    metalError_t st = metalDeviceSynchronize();
    if (st != metalSuccess) {
        return st;
    }
    std::lock_guard<std::mutex> lock(g_alloc_mutex);
    auto it = std::find_if(g_allocations.begin(), g_allocations.end(), [ptr](const AllocationRecord& rec) {
        return rec.base == ptr;
    });
    if (it != g_allocations.end()) {
        device_state().allocatedBytes -= std::min(device_state().allocatedBytes, it->size);
        g_allocations.erase(it);
        return remember(metalSuccess);
    }
    return remember(metalErrorInvalidDevicePointer);
}

metalError_t metalFreeHost(void* ptr) {
    if (ptr == nullptr) return remember(metalSuccess);
    {
        std::lock_guard<std::mutex> lock(g_host_alloc_mutex);
        if (g_host_allocations.find(ptr) == g_host_allocations.end()) {
            return remember(metalErrorInvalidDevicePointer);
        }
    }
    metalError_t firstError = metalSuccess;
    const std::vector<DeviceState*> states = snapshot_initialized_device_states();
    for (DeviceState* state : states) {
        const metalError_t status = synchronize_device_state(*state);
        if (status != metalSuccess && firstError == metalSuccess) firstError = status;
    }
    {
        std::lock_guard<std::mutex> lock(g_host_alloc_mutex);
        auto found = g_host_allocations.find(ptr);
        if (found == g_host_allocations.end()) return remember(metalErrorInvalidDevicePointer);
        g_host_allocations.erase(found);
    }
    std::free(ptr);
    return remember(firstError);
}

metalError_t metalMemcpy(void* dst, const void* src, size_t bytes, metalMemcpyKind kind) {
    if (bytes == 0) {
        return remember(metalSuccess);
    }
    if (dst == nullptr || src == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    metalError_t st = metalDeviceSynchronize();
    if (st != metalSuccess) {
        return st;
    }

    ResolvedBuffer dstBuffer;
    ResolvedBuffer srcBuffer;
    const bool dstIsDevice = find_allocation(dst, dstBuffer);
    const bool srcIsDevice = find_allocation(src, srcBuffer);
    if (kind == metalMemcpyDefault) {
        kind = dstIsDevice ? (srcIsDevice ? metalMemcpyDeviceToDevice : metalMemcpyHostToDevice)
                           : (srcIsDevice ? metalMemcpyDeviceToHost : metalMemcpyHostToHost);
    }
    metal_crypto::Status status;
    switch (kind) {
    case metalMemcpyHostToHost:
        std::memcpy(dst, src, bytes);
        return remember(metalSuccess);
    case metalMemcpyHostToDevice:
        if (!dstIsDevice || bytes > dstBuffer.available) return remember(metalErrorInvalidDevicePointer);
        status = runtime().copyToBuffer(dstBuffer.buffer, src, bytes, dstBuffer.offset);
        break;
    case metalMemcpyDeviceToHost:
        if (!srcIsDevice || bytes > srcBuffer.available) return remember(metalErrorInvalidDevicePointer);
        status = runtime().copyFromBuffer(dst, srcBuffer.buffer, bytes, srcBuffer.offset);
        break;
    case metalMemcpyDeviceToDevice:
        if (!dstIsDevice || !srcIsDevice || bytes > dstBuffer.available || bytes > srcBuffer.available) {
            return remember(metalErrorInvalidDevicePointer);
        }
        std::memmove(static_cast<uint8_t*>(dstBuffer.buffer.contents()) + dstBuffer.offset,
                     static_cast<const uint8_t*>(srcBuffer.buffer.contents()) + srcBuffer.offset,
                     bytes);
        [dstBuffer.buffer.native() didModifyRange:NSMakeRange(dstBuffer.offset, bytes)];
        return remember(metalSuccess);
    default:
        return remember(metalErrorInvalidValue);
    }
    return remember_status(status);
}

metalError_t metalMemcpyAsync(void* dst, const void* src, size_t bytes, metalMemcpyKind kind, metalStream_t streamHandle) {
    if (bytes == 0) {
        return remember(metalSuccess);
    }
    if (dst == nullptr || src == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    metalError_t st = ensure_runtime();
    if (st != metalSuccess) return st;
    MetalStreamLease compatStream;
    st = resolve_stream(streamHandle, compatStream);
    if (st != metalSuccess) return st;
    metal_crypto::Stream* stream = compatStream.owner ? compatStream.owner->stream.get() : nullptr;

    ResolvedBuffer dstBuffer;
    ResolvedBuffer srcBuffer;
    const bool dstIsDevice = find_allocation(dst, dstBuffer);
    const bool srcIsDevice = find_allocation(src, srcBuffer);
    if (kind == metalMemcpyDefault) {
        kind = dstIsDevice ? (srcIsDevice ? metalMemcpyDeviceToDevice : metalMemcpyHostToDevice)
                           : (srcIsDevice ? metalMemcpyDeviceToHost : metalMemcpyHostToHost);
    }
    auto sequenceLock = submit_resource_sequence(device_state(), compatStream.owner);
    metal_crypto::Status status;
    switch (kind) {
    case metalMemcpyHostToHost:
        status = runtime().copyHostAsync(dst, src, bytes, stream);
        break;
    case metalMemcpyHostToDevice:
        if (!dstIsDevice || bytes > dstBuffer.available) return remember(metalErrorInvalidDevicePointer);
        status = runtime().copyToBufferAsync(dstBuffer.buffer, dstBuffer.offset, src, bytes, stream);
        if (status.ok) mark_resource_dependency(dstBuffer.buffer, compatStream.owner);
        break;
    case metalMemcpyDeviceToHost:
        if (!srcIsDevice || bytes > srcBuffer.available) return remember(metalErrorInvalidDevicePointer);
        status = runtime().copyFromBufferAsync(dst, srcBuffer.buffer, srcBuffer.offset, bytes, stream);
        if (status.ok) mark_resource_dependency(srcBuffer.buffer, compatStream.owner);
        break;
    case metalMemcpyDeviceToDevice:
        if (!dstIsDevice || !srcIsDevice || bytes > dstBuffer.available || bytes > srcBuffer.available) {
            return remember(metalErrorInvalidDevicePointer);
        }
        status = runtime().copyBufferAsync(dstBuffer.buffer, dstBuffer.offset,
                                           srcBuffer.buffer, srcBuffer.offset, bytes, stream);
        if (status.ok) {
            mark_resource_dependency(dstBuffer.buffer, compatStream.owner);
            mark_resource_dependency(srcBuffer.buffer, compatStream.owner);
        }
        break;
    default:
        return remember(metalErrorInvalidValue);
    }
    return remember_status(status);
}

metalError_t metalMemset(void* ptr, int value, size_t bytes) {
    if (bytes == 0) {
        return remember(metalSuccess);
    }
    if (ptr == nullptr) {
        return remember(metalErrorInvalidDevicePointer);
    }
    metalError_t st = metalDeviceSynchronize();
    if (st != metalSuccess) return st;
    ResolvedBuffer buffer;
    if (!find_allocation(ptr, buffer) || bytes > buffer.available) {
        return remember(metalErrorInvalidDevicePointer);
    }
    return remember_status(runtime().memsetBuffer(buffer.buffer, static_cast<uint8_t>(value), bytes, buffer.offset));
}

metalError_t metalMemsetAsync(void* ptr, int value, size_t bytes, metalStream_t streamHandle) {
    if (bytes == 0) return remember(metalSuccess);
    if (ptr == nullptr) return remember(metalErrorInvalidDevicePointer);
    metalError_t st = ensure_runtime();
    if (st != metalSuccess) return st;
    MetalStreamLease compatStream;
    st = resolve_stream(streamHandle, compatStream);
    if (st != metalSuccess) return st;
    ResolvedBuffer buffer;
    if (!find_allocation(ptr, buffer) || bytes > buffer.available) {
        return remember(metalErrorInvalidDevicePointer);
    }
    metal_crypto::Stream* stream = compatStream.owner ? compatStream.owner->stream.get() : nullptr;
    auto sequenceLock = submit_resource_sequence(device_state(), compatStream.owner);
    metal_crypto::Status status = runtime().memsetBufferAsync(buffer.buffer, buffer.offset,
                                                              static_cast<uint8_t>(value), bytes, stream);
    if (status.ok) mark_resource_dependency(buffer.buffer, compatStream.owner);
    return remember_status(status);
}

metalError_t metalDeviceSynchronize() {
    metalError_t st = ensure_runtime();
    if (st != metalSuccess) return st;
    return remember(synchronize_device_state(device_state()));
}

metalError_t metalStreamCreate(metalStream_t* stream) {
    if (stream == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    *stream = nullptr;
    metalError_t st = ensure_runtime();
    if (st != metalSuccess) return st;
    std::shared_ptr<MetalStreamState> created = std::make_shared<MetalStreamState>();
    created->device = g_current_device;
    metal_crypto::Status status = runtime().createStream(created->stream);
    if (!status.ok) return remember_status(status);
    MetalStreamState* raw = created.get();
    {
        DeviceState& state = device_state();
        std::lock_guard<std::mutex> lock(state.streamsMutex);
        created->id = state.nextStreamId++;
        state.streams.emplace(raw, created);
    }
    *stream = raw;
    return remember(metalSuccess);
}

metalError_t metalStreamSynchronize(metalStream_t streamHandle) {
    MetalStreamLease stream;
    metalError_t st = resolve_stream(streamHandle, stream);
    if (st != metalSuccess) return st;
    metal_crypto::Status status = synchronize_resource_sequence(device_state(), stream.owner);
    return remember_status(status);
}

metalError_t metalStreamDestroy(metalStream_t streamHandle) {
    if (streamHandle == nullptr) return remember(metalSuccess);
    DeviceState& state = device_state();
    std::shared_ptr<MetalStreamState> stream;
    std::unique_lock<std::mutex> registryLock(state.streamsMutex);
    MetalStreamState* raw = static_cast<MetalStreamState*>(streamHandle);
    auto found = state.streams.find(raw);
    if (found == state.streams.end()) return remember(metalErrorInvalidValue);
    stream = found->second;
    std::unique_lock<std::shared_mutex> lifecycleLock(stream->lifecycleMutex);
    state.streams.erase(found);
    metal_crypto::Status status = synchronize_resource_sequence(state, stream);
    return remember_status(status);
}

metalError_t metalSetDevice(int device) {
    const int count = metal_crypto::Runtime::availableDeviceCount();
    if (device < 0 || device >= count) {
        return remember(metalErrorInvalidDevice);
    }
    g_current_device = device;
    g_cached_device = -1;
    g_cached_device_state = nullptr;
    return remember(metalSuccess);
}

metalError_t metalGetDevice(int* device) {
    if (device == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    *device = g_current_device;
    return remember(metalSuccess);
}

metalError_t metalGetDeviceCount(int* count) {
    if (count == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    *count = metal_crypto::Runtime::availableDeviceCount();
    return remember(metalSuccess);
}

metalError_t metalGetDeviceProperties(metalDeviceProp* prop, int device) {
    if (prop == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    const int count = metal_crypto::Runtime::availableDeviceCount();
    if (device < 0 || device >= count) {
        return remember(metalErrorInvalidDevice);
    }
    DeviceState& state = device_state_for(device);
    metalError_t st = ensure_runtime(state, device);
    if (st != metalSuccess) {
        std::snprintf(prop->name, sizeof(prop->name), "%s", "Metal GPU");
        prop->multiProcessorCount = 1;
        prop->maxThreadsPerBlock = 1024;
        return st;
    }
    const metal_crypto::DeviceInfo& info = state.runtime.deviceInfo();
    std::snprintf(prop->name, sizeof(prop->name), "%s", info.name.empty() ? "Metal GPU" : info.name.c_str());
    prop->multiProcessorCount = info.gpuCoreCount != 0u
        ? static_cast<int>(info.gpuCoreCount)
        : 1;
    prop->maxThreadsPerBlock = static_cast<int>(std::max<NSUInteger>(1, info.maxThreadsPerThreadgroup));
    prop->recommendedMaxWorkingSetSize = info.recommendedMaxWorkingSetSize;
    prop->currentAllocatedSize = info.currentAllocatedSize;
    prop->maxBufferLength = info.maxBufferLength;
    prop->hasUnifiedMemory = info.hasUnifiedMemory ? 1 : 0;
    {
        std::lock_guard<std::mutex> lock(g_alloc_mutex);
        prop->currentAllocatedSize = std::max<uint64_t>(
            prop->currentAllocatedSize,
            static_cast<uint64_t>(state.allocatedBytes));
    }
    return remember(metalSuccess);
}

metalError_t metalMemGetInfo(size_t* free_bytes, size_t* total_bytes) {
    if (free_bytes == nullptr && total_bytes == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    metalError_t st = ensure_runtime();
    if (st != metalSuccess) return st;
    const metal_crypto::DeviceInfo& info = runtime().deviceInfo();
    const uint64_t reported = info.recommendedMaxWorkingSetSize != 0
        ? info.recommendedMaxWorkingSetSize
        : info.maxBufferLength;
    const size_t total = reported > static_cast<uint64_t>(std::numeric_limits<size_t>::max())
        ? std::numeric_limits<size_t>::max()
        : static_cast<size_t>(reported);
    size_t allocated = 0;
    {
        std::lock_guard<std::mutex> lock(g_alloc_mutex);
        allocated = device_state().allocatedBytes;
    }
    const size_t free = allocated < total ? total - allocated : 0;
    if (free_bytes != nullptr) {
        *free_bytes = free;
    }
    if (total_bytes != nullptr) {
        *total_bytes = total;
    }
    return remember(metalSuccess);
}

metalError_t metalGetLastError() {
    const metalError_t out = g_last_error;
    g_last_error = metalSuccess;
    return out;
}

metalError_t metalWriteState(const char* symbol, const void* src, size_t bytes) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (symbol == nullptr || src == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    metalError_t syncStatus = metalDeviceSynchronize();
    if (syncStatus != metalSuccess) return syncStatus;
    if (std::strcmp(symbol, "d_resultsCount") == 0) {
        metalError_t st = ensure_buffer(g_results_count_buffer, sizeof(uint64_t));
        if (st != metalSuccess) return st;
        uint64_t value = 0;
        std::memcpy(&value, src, std::min(bytes, sizeof(value)));
        metal_crypto::Status status = runtime().copyToBuffer(g_results_count_buffer, &value, sizeof(value));
        if (!status.ok) return remember_status(status);
    }
    {
        std::lock_guard<std::mutex> lock(g_symbol_mutex);
        const auto* first = static_cast<const uint8_t*>(src);
        g_symbol_bytes[std::string(symbol)] = std::vector<uint8_t>(first, first + bytes);
    }

    update_pointer_symbol(symbol, read_pointer_value(src, bytes));

    if (std::strcmp(symbol, "BIP_DERIVATIONS_ENABLED_D") == 0) {
        copy_symbol_value(src, g_runtime_config.bipDerivationsEnabled, bytes);
    } else if (std::strcmp(symbol, "SUBSTRATE_PATH_COUNT_D") == 0) {
        copy_symbol_value(src, g_runtime_config.substratePathCount, bytes);
    } else if (std::strcmp(symbol, "ADA_POINTER_ENABLED_D") == 0) {
        copy_symbol_value(src, g_runtime_config.adaPointerEnabled, bytes);
    } else if (std::strcmp(symbol, "ADA_POINTER_SLOT_D") == 0) {
        copy_symbol_value(src, g_runtime_config.adaPointerSlot, bytes);
    } else if (std::strcmp(symbol, "ADA_POINTER_TX_D") == 0) {
        copy_symbol_value(src, g_runtime_config.adaPointerTx, bytes);
    } else if (std::strcmp(symbol, "ADA_POINTER_CERT_D") == 0) {
        copy_symbol_value(src, g_runtime_config.adaPointerCert, bytes);
    } else if (std::strcmp(symbol, "ADA_TYPE_MASK_D") == 0) {
        copy_symbol_value(src, g_runtime_config.adaTypeMask, bytes);
    } else if (std::strcmp(symbol, "TON_TYPE_MASK_D") == 0) {
        copy_symbol_value(src, g_runtime_config.tonTypeMask, bytes);
    } else if (std::strcmp(symbol, "DOT_TYPE_MASK_D") == 0) {
        copy_symbol_value(src, g_runtime_config.dotTypeMask, bytes);
    } else if (std::strcmp(symbol, "APTOS_TYPE_MASK_D") == 0) {
        copy_symbol_value(src, g_runtime_config.aptosTypeMask, bytes);
    } else if (std::strcmp(symbol, "SUI_TYPE_MASK_D") == 0) {
        copy_symbol_value(src, g_runtime_config.suiTypeMask, bytes);
    } else if (std::strcmp(symbol, "XRP_TYPE_MASK_D") == 0) {
        copy_symbol_value(src, g_runtime_config.xrpTypeMask, bytes);
    } else if (std::strcmp(symbol, "IOTA_TYPE_MASK_D") == 0) {
        copy_symbol_value(src, g_runtime_config.iotaTypeMask, bytes);
    } else if (std::strcmp(symbol, "ICP_TYPE_MASK_D") == 0) {
        copy_symbol_value(src, g_runtime_config.icpTypeMask, bytes);
    } else if (std::strcmp(symbol, "FIL_TYPE_MASK_D") == 0) {
        copy_symbol_value(src, g_runtime_config.filTypeMask, bytes);
    } else if (std::strcmp(symbol, "XTZ_TYPE_MASK_D") == 0) {
        copy_symbol_value(src, g_runtime_config.xtzTypeMask, bytes);
    }
    return remember(metalSuccess);
}

metalError_t metalReadState(void* dst, const char* symbol, size_t bytes) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (dst == nullptr || symbol == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    metalError_t syncStatus = metalDeviceSynchronize();
    if (syncStatus != metalSuccess) return syncStatus;
    if (std::strcmp(symbol, "d_resultsCount") == 0) {
        metalError_t st = ensure_buffer(g_results_count_buffer, sizeof(uint64_t));
        if (st != metalSuccess) return st;
        uint64_t value = 0;
        metal_crypto::Status status = runtime().copyFromBuffer(&value, g_results_count_buffer, sizeof(value));
        if (!status.ok) return remember_status(status);
        std::memcpy(dst, &value, std::min(bytes, sizeof(value)));
        if (bytes > sizeof(value)) {
            std::memset(static_cast<uint8_t*>(dst) + sizeof(value), 0, bytes - sizeof(value));
        }
        return remember(metalSuccess);
    }
    std::lock_guard<std::mutex> lock(g_symbol_mutex);
    auto it = g_symbol_bytes.find(std::string(symbol));
    if (it == g_symbol_bytes.end()) {
        std::memset(dst, 0, bytes);
        return remember(metalSuccess);
    }
    const size_t n = std::min(bytes, it->second.size());
    std::memcpy(dst, it->second.data(), n);
    if (n < bytes) {
        std::memset(static_cast<uint8_t*>(dst) + n, 0, bytes - n);
    }
    return remember(metalSuccess);
}

namespace {

metalError_t submit_dependency_aware_launch(
    const std::string& name,
    NSUInteger totalThreads,
    NSUInteger threadsPerThreadgroup,
    const std::vector<LaunchBinding>& bindings,
    const std::vector<metal_crypto::Buffer>& indirectResources,
    const std::string& pipelineKey,
    const std::function<void(MTLFunctionConstantValues*)>& constants) {
    const std::vector<metal_crypto::Buffer> resources =
        collect_launch_resources(bindings, indirectResources);
    const DependencyResolution resolution = resolve_resource_dependencies(resources);

    MetalStreamLease launchLease;
    std::shared_ptr<MetalStreamState> launchStream;
    metalError_t st = select_dependency_stream(resolution, launchLease, launchStream);
    if (st != metalSuccess) return st;

    auto sequenceLock = submit_resource_sequence(device_state(), launchStream);
    DispatchStreamScope dispatchStreamScope(launchStream);
    st = flush_deferred_runtime_state();
    if (st != metalSuccess) return st;

    metal_crypto::Status status = runtime().launch1D(
        name,
        totalThreads,
        threadsPerThreadgroup,
        [&](id<MTLComputeCommandEncoder> encoder) {
            for (NSUInteger i = 0; i < bindings.size(); ++i) {
                const LaunchBinding& binding = bindings[i];
                if (binding.is_nil || !binding.buffer.valid()) {
                    [encoder setBuffer:nil offset:0 atIndex:i];
                } else {
                    [encoder setBuffer:binding.buffer.native()
                                 offset:binding.offset
                                atIndex:i];
                }
            }
            for (const metal_crypto::Buffer& resource : indirectResources) {
                if (resource.valid()) {
                    [encoder useResource:resource.native()
                                    usage:(MTLResourceUsageRead | MTLResourceUsageWrite)];
                }
            }
        },
        pipelineKey,
        constants,
        launchStream ? launchStream->stream.get() : nullptr);
    if (status.ok) {
        mark_resource_dependencies(resources, launchStream);
    }
    return remember_status(status);
}

} // namespace

metalError_t metal_launch_impl(const char* function_name,
                              MetalGridSize grid,
                              MetalGridSize block,
                              const MetalLaunchArg* args,
                              size_t count) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (function_name == nullptr) {
        return remember(metalErrorInvalidValue);
    }
    const std::string name(function_name);
    if (is_cpu_setter_kernel(name)) {
        return handle_config_setter(name, args, count);
    }

    metalError_t st = ensure_runtime();
    if (st != metalSuccess) {
        return st;
    }
    DeferredRuntimeStateScope deferredRuntimeState;

    std::vector<LaunchBinding> bindings;
    std::vector<metal_crypto::Buffer> temporaries;
    std::vector<metal_crypto::Buffer> indirect_resources;
    bindings.reserve(count + 32);
    temporaries.reserve(count + 8);
    indirect_resources.reserve(32);

    std::string pipelineKey;
    std::function<void(MTLFunctionConstantValues*)> constants;
    if (name == "workerPRIV") {
        const PrivFileFunctionConstants privFileConstants = make_priv_file_function_constants(args, count);
        pipelineKey = priv_file_function_constants_key(privFileConstants);
        constants = [privFileConstants](MTLFunctionConstantValues* values) {
            bind_priv_file_function_constants(values, privFileConstants);
        };
    } else if (name == "workerBrowserVaultGrouped") {
        const BrowserVaultFunctionConstants browserVaultConstants =
            make_browser_vault_function_constants(args, count);
        pipelineKey = browser_vault_function_constants_key(browserVaultConstants);
        constants = [browserVaultConstants](MTLFunctionConstantValues* values) {
            bind_browser_vault_function_constants(values, browserVaultConstants);
        };
    } else if (name == "workerDerThread") {
        const DerThreadFunctionConstants derThreadConstants = make_derthread_function_constants();
        pipelineKey = derthread_function_constants_key(derThreadConstants);
        constants = [derThreadConstants](MTLFunctionConstantValues* values) {
            bind_derthread_function_constants(values, derThreadConstants);
        };
    } else if (uses_xp_function_constants(name)) {
        uint8_t profileKind = 0u;
        if (!read_launch_value_arg(args, count, 4u, profileKind)) {
            return remember(metalErrorInvalidValue);
        }
        const XpFunctionConstants xpConstants = make_xp_function_constants(args, count);
        pipelineKey = xp_function_constants_key(xpConstants);
        constants = [xpConstants](MTLFunctionConstantValues* values) {
            bind_xp_function_constants(values, xpConstants);
        };
    } else if (uses_priv_gen_function_constants(name)) {
        const PrivGenFunctionConstants privGenConstants = make_priv_gen_function_constants(name, args, count);
        pipelineKey = priv_gen_function_constants_key(privGenConstants);
        constants = [privGenConstants](MTLFunctionConstantValues* values) {
            bind_priv_gen_function_constants(values, privGenConstants);
        };
    } else if (name == "workerPoetry") {
        const PoetryFunctionConstants poetryConstants =
            make_poetry_function_constants(args, count);
        pipelineKey = poetry_function_constants_key(poetryConstants);
        constants = [poetryConstants](MTLFunctionConstantValues* values) {
            bind_poetry_function_constants(values, poetryConstants);
        };
    } else if (uses_worker_common_function_constants(name)) {
        const WorkerFunctionConstants workerConstants = make_worker_function_constants();
        pipelineKey = worker_function_constants_key(workerConstants);
        constants = [workerConstants](MTLFunctionConstantValues* values) {
            bind_worker_function_constants(values, workerConstants);
        };
    }
    if (name == "workerPRIV_seq_128_edonly") {
        pipelineKey = "runtime-target-masks";
        constants = nullptr;
    } else {
        const EcmultWindowFunctionConstants ecmultConstants = make_ecmult_window_function_constants();
        const std::string ecmultKey = ecmult_window_function_constants_key(ecmultConstants);
        if (pipelineKey.empty()) {
            pipelineKey = ecmultKey;
        } else {
            pipelineKey += ":";
            pipelineKey += ecmultKey;
        }
        const std::function<void(MTLFunctionConstantValues*)> specializedConstants = constants;
        constants = [specializedConstants, ecmultConstants](MTLFunctionConstantValues* values) {
            if (specializedConstants) {
                specializedConstants(values);
            }
            bind_ecmult_window_function_constants(values, ecmultConstants);
        };
    }

    if (name == "workerDerThread_bip32_compressed" || name == "workerDerThread_slip0010_solana") {
        st = append_derthread_packed_launch(bindings, temporaries, name, args, count);
        if (st != metalSuccess) return st;
    } else if (name == "workerDerThread_seed_slip0010_solana") {
        if (count < 10) return remember(metalErrorInvalidValue);
        st = append_original_args(bindings, temporaries, args, 0, 10);
        if (st != metalSuccess) return st;
        st = append_filter_bindings(bindings);
        if (st != metalSuccess) return st;
        st = append_found_full(bindings, false, false, true, false);
        if (st != metalSuccess) return st;
    } else if (name == "workerPRIV_seq_128" || name == "workerPRIV_seq_128_edonly") {
        st = sync_runtime_state();
        if (st != metalSuccess) return st;
        st = append_original_args(bindings, temporaries, args, 0, std::min<size_t>(count, 8));
        if (st != metalSuccess) return st;
        st = append_filter_bindings(bindings);
        if (st != metalSuccess) return st;
        st = append_found_full(bindings, true, true, true, true);
        if (st != metalSuccess) return st;
        st = push_buffer_binding(bindings, g_secp_walk_state_buffer);
        if (st != metalSuccess) return st;
    } else {
        st = append_original_args(bindings, temporaries, args, 0, count);
        if (st != metalSuccess) return st;

        if (name == "compute_P0_H_kernel") {
            st = sync_runtime_state();
            if (st != metalSuccess) return st;
            st = push_buffer_binding(bindings, g_secp_walk_state_buffer);
            if (st != metalSuccess) return st;
            st = push_value_binding(bindings, temporaries, &g_ecmult_windows, sizeof(g_ecmult_windows));
            if (st != metalSuccess) return st;
            st = push_value_binding(bindings, temporaries, &g_ecmult_window_bits, sizeof(g_ecmult_window_bits));
            if (st != metalSuccess) return st;
        } else if (name == "precompute_vanity_starts_kernel" ||
                   name == "advance_P0_kernel" ||
                   name == "vanity_compute_persistent_shift_kernel" ||
                   name == "vanity_apply_persistent_shift_kernel") {
            st = sync_runtime_state();
            if (st != metalSuccess) return st;
            st = push_buffer_binding(bindings, g_secp_walk_state_buffer);
            if (st != metalSuccess) return st;
        } else if (name == "workerPRIV") {
            st = push_buffer_binding(bindings, g_rng_state_buffer);
            if (st != metalSuccess) return st;
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = append_found_full(bindings, false, true, true, true);
            if (st != metalSuccess) return st;
        } else if (name == "workerPoetry") {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = append_found_flexible(bindings,
                                       true, true, true, true, false, true,
                                       false, false, false, false, true, false,
                                       true, true);
            if (st != metalSuccess) return st;
        } else if (starts_with(name, "workerPRIV_seq_vanity")) {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            if (name == "workerPRIV_seq_vanity_c" ||
                name == "workerPRIV_seq_vanity_s" ||
                name == "workerPRIV_seq_vanity_x" ||
                name == "workerPRIV_seq_vanity_u" ||
                name == "workerPRIV_seq_vanity_e" ||
                name == "workerPRIV_seq_vanity_p") {
                st = append_found_vanity_tables(bindings);
            } else {
                st = append_found_full(bindings, true, true, true, false);
            }
            if (st != metalSuccess) return st;
        } else if (name == "workerPRIV_seq") {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = append_found_full(bindings, true, true, true, true);
            if (st != metalSuccess) return st;
        } else if (name == "workerPRIV_seq_hexset") {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = append_priv_minimal_no_seed(bindings, true);
            if (st != metalSuccess) return st;
        } else if ((name == "workerPRIV_byte") ||
                   (starts_with(name, "workerPRIV") &&
                   (contains(name, "_gen") || name == "workerPRIV_hash" ||
                    name == "workerPRIV_plus" || name == "workerPRIV_swap" ||
                    name == "workerPRIV_pattern"))) {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = append_found_priv_minimal(bindings, true);
            if (st != metalSuccess) return st;
        } else if (name == "workerPvkRecoveryBatch") {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = append_found_flexible(bindings,
                                       false, true, true, false, false, true,
                                       false, false, false, false, true, false,
                                       true, false);
            if (st != metalSuccess) return st;
        } else if (starts_with(name, "workerPvkRecoverySeq") ||
                   name == "workerPvkRecoveryBatchEdOnly") {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = append_found_full(bindings, true, true, true, false);
            if (st != metalSuccess) return st;
        } else if (name == "workerArmoryWallet") {
            st = append_wallet_results(bindings, temporaries, false);
            if (st != metalSuccess) return st;
        } else if (name == "workerArmoryRoot_gen") {
            st = append_runtime_argument_buffer(bindings, temporaries, indirect_resources, name, pipelineKey, constants, false, false);
            if (st != metalSuccess) return st;
        } else if (starts_with(name, "workerArmory")) {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = append_found_flexible(bindings, true, true, true, true, false, true,
                                       true, false, false, false, true, true,
                                       true, false);
            if (st != metalSuccess) return st;
        } else if (name == "workerBrain_gen") {
            st = append_runtime_argument_buffer(bindings, temporaries, indirect_resources, name, pipelineKey, constants, false, false);
            if (st != metalSuccess) return st;
        } else if (starts_with(name, "workerBrain")) {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            const bool include_derivs = !(contains(name, "_hexset"));
            st = append_found_flexible(bindings, true, true, true, true, true, true,
                                       include_derivs, include_derivs, false, false,
                                       true, false, true, true);
            if (st != metalSuccess) return st;
        } else if (starts_with(name, "workerOld")) {
            const bool old_seed_no_hc = name == "workerOldSeed_gen" ||
                                        name == "workerOldSeed_recovery_hexset" ||
                                        name == "workerOldSeed_seq_hexset";
            st = old_seed_no_hc ? append_filter_bindings_no_hc(bindings)
                                : append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            const bool old_seed_hex = name == "workerOldSeed_recovery_hexset" ||
                                      name == "workerOldSeed_seq_hexset";
            const bool include_deriv2 = !old_seed_hex && name != "workerOldSeed_gen";
            const bool include_seed = !old_seed_hex && name != "workerOldSeed";
            st = append_found_flexible(bindings, true, true, true, true, false, true,
                                       true, include_deriv2,
                                       false, false, true,
                                       include_seed,
                                       true, false);
            if (st != metalSuccess) return st;
        } else if (name == "workerMINIKEYS_seed_collect_gen" ||
                   name == "workerMINIKEYS_seed_collect_file" ||
                   name == "workerMINIKEYS_seed_collect_seq") {
            st = sync_runtime_state();
            if (st != metalSuccess) return st;
            st = push_buffer_binding(bindings, g_config_buffer);
            if (st != metalSuccess) return st;
        } else if (name == "workerMINIKEYS_process") {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = append_found_full(bindings, true, true, true, true);
            if (st != metalSuccess) return st;
        } else if (starts_with(name, "workerWalletJS_seed")) {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = push_pointer_binding(bindings, g_found.walletResults);
            if (st != metalSuccess) return st;
            st = push_pointer_binding(bindings, g_found.walletCount);
            if (st != metalSuccess) return st;
        } else if (starts_with(name, "workerWalletJS")) {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = push_pointer_binding(bindings, g_found.walletResults);
            if (st != metalSuccess) return st;
            st = push_pointer_binding(bindings, g_found.walletCount);
            if (st != metalSuccess) return st;
        } else if (starts_with(name, "workerProfanity_")) {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
            st = push_pointer_binding(bindings, g_found.profanityResults);
            if (st != metalSuccess) return st;
            st = push_pointer_binding(bindings, g_found.profanityCount);
            if (st != metalSuccess) return st;
        } else if (starts_with(name, "workerProfanityRecoveryReverse")) {
            st = append_filter_bindings(bindings);
            if (st != metalSuccess) return st;
        } else if (name == "workerProfanitySeedResolve" ||
                   name == "workerProfanitySeedResolveBatch") {
            st = push_pointer_binding(bindings, g_found.profanityResults);
            if (st != metalSuccess) return st;
            st = push_pointer_binding(bindings, g_found.profanityCount);
            if (st != metalSuccess) return st;
            const uint32_t max_founds = g_runtime_config.maxFounds;
            st = push_value_binding(bindings, temporaries, &max_founds, sizeof(max_founds));
            if (st != metalSuccess) return st;
        } else if (name == "workerWalletDat" || name == "workerWalletDatResolveHits") {
            st = append_wallet_results(bindings, temporaries, true);
            if (st != metalSuccess) return st;
	        } else if (name == "workerBrowserVault" ||
	                   name == "workerBrowserVaultGrouped" ||
	                   name == "workerKeystoreV3" ||
	                   name == "workerExodusSeco" ||
	                   name == "workerBitcoinJWallet" ||
	                   name == "workerElectrumWallet" ||
	                   name == "workerElectrumWalletFieldOnly") {
	            st = append_wallet_results(bindings, temporaries, false);
	            if (st != metalSuccess) return st;
        } else if (starts_with(name, "workerXP")) {
            st = append_xp_runtime_bindings(bindings, temporaries);
            if (st != metalSuccess) return st;
        } else if (name == "workerDerThread" || name == "workerPassThread" ||
                   name == "workerPassThreadEntropy" || name == "workerPassThreadEntropyBatch" ||
                   name == "worker" ||
                   name == "worker_gen" || name == "worker_seq" ||
                   name == "worker_seq_hexset" || name == "worker_recovery_hexset" ||
                   starts_with(name, "workerEntropy") ||
                   starts_with(name, "workerHmac") ||
                   starts_with(name, "workerSeed") ||
                   name == "workerBip32" ||
                   name == "workerByte" ||
                   contains(name, "workerBip32") ||
                   name == "workerRecoveryEvalBatch" ||
                   name == "workerRecoveryEvalMasterBatch" ||
                   name == "workerRecoveryFused") {
            const bool recovery_runtime = name == "workerRecoveryEvalBatch" ||
                                          name == "workerRecoveryEvalMasterBatch" ||
                                          name == "workerRecoveryFused";
            const bool mnemonic_runtime = name == "workerPassThread" ||
                                          name == "workerPassThreadEntropy" ||
                                          name == "workerPassThreadEntropyBatch" ||
                                          name == "worker_gen" ||
                                          starts_with(name, "workerEntropy") ||
                                          starts_with(name, "workerHmac") ||
                                          starts_with(name, "workerSeed");
            st = append_runtime_argument_buffer(bindings, temporaries, indirect_resources, name, pipelineKey, constants, recovery_runtime, mnemonic_runtime);
            if (st != metalSuccess) return st;
            if (name == "workerDerThread") {
                st = push_pointer_binding(bindings, g_found.substratePaths);
                if (st != metalSuccess) return st;
            }
        } else if (name == "workerDerThread_mkd" || name == "workerDerThread_mkd_gen") {
            st = sync_runtime_state();
            if (st != metalSuccess) return st;
            st = push_buffer_binding(bindings, g_config_buffer);
            if (st != metalSuccess) return st;
            st = push_pointer_binding(bindings, g_found.customDict);
            if (st != metalSuccess) return st;
        }
    }

    const NSUInteger totalThreads = std::max<NSUInteger>(1, static_cast<NSUInteger>(grid.x) * static_cast<NSUInteger>(block.x));
    const NSUInteger threadsPerThreadgroup = std::max<NSUInteger>(1, static_cast<NSUInteger>(block.x));
    return submit_dependency_aware_launch(name,
                                          totalThreads,
                                          threadsPerThreadgroup,
                                          bindings,
                                          indirect_resources,
                                          pipelineKey,
                                          constants);
}

metalError_t loadPrefix(const char*, size_t) {
    return remember(metalSuccess);
}

metalError_t loadHashTarget(const uint32_t words[8], const uint32_t masks[8], uint32_t lenBytes, bool enabled) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (words != nullptr) {
        std::copy(words, words + 8, g_runtime_config.hashTargetWords);
    }
    if (masks != nullptr) {
        std::copy(masks, masks + 8, g_runtime_config.hashTargetMasks);
    }
    g_runtime_config.hashTargetLen = lenBytes;
    g_runtime_config.hashTargetEnabled = enabled ? 1u : 0u;
    return remember(metalSuccess);
}

metalError_t loadLevel(int level) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    g_runtime_config.shaLevel = static_cast<uint32_t>(level);
    return remember(metalSuccess);
}

metalError_t loadIteration(int iteration) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    g_runtime_config.iteration = static_cast<uint32_t>(iteration);
    return remember(metalSuccess);
}

metalError_t loadShaPre(uint32_t* pre) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (pre != nullptr) {
        std::copy(pre, pre + 8, g_runtime_config.shaPre);
    }
    return remember(metalSuccess);
}

metalError_t metalLoadBloomFilter(uint8_t* bloomFilterPtr, int count) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (count < 0 || static_cast<size_t>(count) >= g_bloom_ptrs.size()) {
        return remember(metalErrorInvalidValue);
    }
    g_bloom_ptrs[static_cast<size_t>(count)] = bloomFilterPtr;
    return rebuild_bloom_storage();
}

metalError_t metalLoadCompressedXorFilter(uint32_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    metalError_t st = store_xor(g_xor, g_xor_storage_buffer, g_filter_storage.xorOffsets, g_filter_storage.xorCount, deviceFilter, count, sizeof(uint32_t), size_h, arrayLength_h, segmentCount_h, segmentCountLength_h, segmentLength_h, segmentLengthMask_h);
    if (st != metalSuccess) return st;
    return launch_xor_metadata_kernel("copyXorCompressedFilter", count, size_h, arrayLength_h, segmentCount_h, segmentCountLength_h, segmentLength_h, segmentLengthMask_h);
}

metalError_t metalLoadUncompressedXorFilter(uint32_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    metalError_t st = store_xor(g_xor_un, g_xor_un_storage_buffer, g_filter_storage.xorUnOffsets, g_filter_storage.xorUnCount, deviceFilter, count, sizeof(uint32_t), size_h, arrayLength_h, segmentCount_h, segmentCountLength_h, segmentLength_h, segmentLengthMask_h);
    if (st != metalSuccess) return st;
    return launch_xor_metadata_kernel("copyXorUncompressedFilter", count, size_h, arrayLength_h, segmentCount_h, segmentCountLength_h, segmentLength_h, segmentLengthMask_h);
}

metalError_t metalLoadUltraXorFilter(uint16_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    metalError_t st = store_xor(g_xor_uc, g_xor_uc_storage_buffer, g_filter_storage.xorUcOffsets, g_filter_storage.xorUcCount, deviceFilter, count, sizeof(uint16_t), size_h, arrayLength_h, segmentCount_h, segmentCountLength_h, segmentLength_h, segmentLengthMask_h);
    if (st != metalSuccess) return st;
    return launch_xor_metadata_kernel("copyXorUltraFilter", count, size_h, arrayLength_h, segmentCount_h, segmentCountLength_h, segmentLength_h, segmentLengthMask_h);
}

metalError_t metalLoadHyperXorFilter(uint8_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    metalError_t st = store_xor(g_xor_hc, g_xor_hc_storage_buffer, g_filter_storage.xorHcOffsets, g_filter_storage.xorHcCount, deviceFilter, count, sizeof(uint8_t), size_h, arrayLength_h, segmentCount_h, segmentCountLength_h, segmentLength_h, segmentLengthMask_h);
    if (st != metalSuccess) return st;
    return launch_xor_metadata_kernel("copyXorHyperFilter", count, size_h, arrayLength_h, segmentCount_h, segmentCountLength_h, segmentLength_h, segmentLengthMask_h);
}

metalError_t loadWindow(unsigned int windowSize, unsigned int windows) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    g_ecmult_window_bits = windowSize;
    g_ecmult_windows = windows;
    return metalSuccess;
}

metalError_t launchWorkerRecoveryChecksum(const uint16_t* base_ids,
                                         int words_count,
                                         const int* missing_positions,
                                         int missing_count,
                                         uint64_t range_start,
                                         uint64_t range_count,
                                         uint16_t* out_ids,
                                         uint32_t* out_count,
                                         uint32_t out_capacity,
                                         uint32_t blocks,
                                         uint32_t threads) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    return metal_launch("workerRecoveryChecksum",
                        MetalGridSize(blocks),
                        MetalGridSize(threads),
                        base_ids,
                        words_count,
                        missing_positions,
                        missing_count,
                        range_start,
                        range_count,
                        out_ids,
                        out_count,
                        out_capacity);
}

metalError_t launchWorkerMnemonicScramble(
    const uint16_t* unique_ids,
    const uint16_t* initial_counts,
    uint32_t unique_count,
    const uint16_t* output_template,
    uint32_t words_count,
    const uint16_t* movable_positions,
    uint32_t movable_count,
    const uint32_t* allowed_masks,
    const uint64_t* base_ordinal,
    const uint64_t* domain_size,
    uint64_t range_count,
    uint16_t* out_ids,
    uint32_t* out_count,
    uint32_t out_capacity,
    uint32_t blocks,
    uint32_t threads) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    return metal_launch(
        "workerMnemonicScramble",
        MetalGridSize(blocks),
        MetalGridSize(threads),
        unique_ids,
        initial_counts,
        unique_count,
        output_template,
        words_count,
        movable_positions,
        movable_count,
        allowed_masks,
        base_ordinal,
        domain_size,
        range_count,
        out_ids,
        out_count,
        out_capacity);
}

metalError_t launchWorkerRecoverySeedBatch(const uint16_t* batch_ids,
                                          int words_count,
                                          uint32_t batch_count,
                                          const char* passwd,
                                          uint32_t pass_size,
                                          const uint32_t* iterations,
                                          uint32_t iterations_size,
                                          uint32_t* batch_master_words,
                                          uint32_t blocks,
                                          uint32_t threads) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    DeferredRuntimeStateScope deferredRuntimeState;
    metalError_t st = sync_runtime_state();
    if (st != metalSuccess) return st;
    std::array<MetalLaunchArg, 8> args = {
        metal_make_launch_arg(batch_ids),
        metal_make_launch_arg(words_count),
        metal_make_launch_arg(batch_count),
        metal_make_launch_arg(passwd),
        metal_make_launch_arg(pass_size),
        metal_make_launch_arg(iterations),
        metal_make_launch_arg(iterations_size),
        metal_make_launch_arg(batch_master_words),
    };
    std::vector<LaunchBinding> bindings;
    std::vector<metal_crypto::Buffer> temporaries;
    bindings.reserve(10);
    temporaries.reserve(8);
    st = append_original_args(bindings, temporaries, args.data(), 0, args.size());
    if (st != metalSuccess) return st;
    st = push_buffer_binding(bindings, g_config_buffer);
    if (st != metalSuccess) return st;
    st = push_pointer_binding(bindings, g_found.customDict);
    if (st != metalSuccess) return st;

    const NSUInteger totalThreads = std::max<NSUInteger>(1, static_cast<NSUInteger>(blocks) * static_cast<NSUInteger>(threads));
    const NSUInteger threadsPerThreadgroup = std::max<NSUInteger>(1, static_cast<NSUInteger>(threads));
    const std::vector<metal_crypto::Buffer> indirectResources;
    return submit_dependency_aware_launch("workerRecoverySeedBatch",
                                          totalThreads,
                                          threadsPerThreadgroup,
                                          bindings,
                                          indirectResources);
}

metalError_t launchWorkerRecoveryFused(bool* is_result,
                                      bool* buff_result,
                                      const secp256k1_ge_storage* prec,
                                      size_t prec_pitch,
                                      const uint16_t* base_ids,
                                      int words_count,
                                      const int* missing_positions,
                                      int missing_count,
                                      uint64_t range_start,
                                      uint64_t range_count,
                                      const uint32_t* derivations,
                                      const uint32_t* derindex,
                                      uint32_t der_indexes_size,
                                      uint32_t der_start_index,
                                      const char* passwd,
                                      uint32_t pass_size,
                                      uint32_t starter_pass,
                                      uint64_t round,
                                      uint8_t m_mode,
                                      const uint32_t* iterations,
                                      uint32_t iterations_size,
                                      bool is_str,
                                      bool dub_mnem,
                                      uint64_t* valid_count,
                                      uint32_t blocks,
                                      uint32_t threads) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (range_count == 0ull) {
        return metalSuccess;
    }
    if (is_result == nullptr || buff_result == nullptr || prec == nullptr || base_ids == nullptr ||
        derivations == nullptr || derindex == nullptr || passwd == nullptr || iterations == nullptr ||
        valid_count == nullptr) {
        return metalErrorInvalidValue;
    }
    if (words_count <= 0 || words_count > 48 || (words_count % 3) != 0) {
        return metalErrorInvalidValue;
    }
    if (missing_count < 0 || missing_count > words_count) {
        return metalErrorInvalidValue;
    }
    if (missing_count > 0 && missing_positions == nullptr) {
        return metalErrorInvalidValue;
    }
    if (iterations_size == 0u) {
        return metalErrorInvalidValue;
    }
    if (threads == 0u) {
        threads = 256u;
    }
    if (blocks == 0u) {
        blocks = 1u;
    }
    return metal_launch("workerRecoveryFused",
                        MetalGridSize(blocks),
                        MetalGridSize(threads),
                        is_result,
                        buff_result,
                        prec,
                        prec_pitch,
                        base_ids,
                        words_count,
                        missing_positions,
                        missing_count,
                        range_start,
                        range_count,
                        derivations,
                        derindex,
                        der_indexes_size,
                        der_start_index,
                        passwd,
                        pass_size,
                        starter_pass,
                        round,
                        m_mode,
                        iterations,
                        iterations_size,
                        is_str,
                        dub_mnem,
                        valid_count);
}

metalError_t launchWorkerRecoveryEvalBatch(bool* is_result,
                                          bool* buff_result,
                                          const secp256k1_ge_storage* prec,
                                          size_t prec_pitch,
                                          const uint16_t* batch_ids,
                                          int words_count,
                                          uint32_t batch_count,
                                          const uint32_t* derivations,
                                          const uint32_t* derindex,
                                          uint32_t der_indexes_size,
                                          uint32_t der_start_index,
                                          const char* passwd,
                                          uint32_t pass_size,
                                          uint32_t starter_pass,
                                          uint64_t round,
                                          uint8_t m_mode,
                                          const uint32_t* iterations,
                                          uint32_t iterations_size,
                                          bool is_str,
                                          bool dub_mnem,
                                          uint32_t blocks,
                                          uint32_t threads) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    if (batch_count == 0u) {
        return metalSuccess;
    }
    if (is_result == nullptr || buff_result == nullptr || prec == nullptr || batch_ids == nullptr ||
        derivations == nullptr || derindex == nullptr || passwd == nullptr || iterations == nullptr) {
        return metalErrorInvalidValue;
    }
    if (words_count <= 0 || words_count > 48 || (words_count % 3) != 0) {
        return metalErrorInvalidValue;
    }
    if (iterations_size == 0u) {
        return metalErrorInvalidValue;
    }
    if (threads == 0u) {
        threads = 256u;
    }
    if (blocks == 0u) {
        blocks = 1u;
    }
    return metal_launch("workerRecoveryEvalBatch",
                        MetalGridSize(blocks),
                        MetalGridSize(threads),
                        is_result,
                        buff_result,
                        prec,
                        prec_pitch,
                        batch_ids,
                        words_count,
                        batch_count,
                        derivations,
                        derindex,
                        der_indexes_size,
                        der_start_index,
                        passwd,
                        pass_size,
                        starter_pass,
                        round,
                        m_mode,
                        iterations,
                        iterations_size,
                        is_str,
                        dub_mnem);
}

metalError_t launchWorkerRecoveryEvalMasterBatch(bool* is_result,
                                                bool* buff_result,
                                                const secp256k1_ge_storage* prec,
                                                size_t prec_pitch,
                                                const uint16_t* batch_ids,
                                                const uint32_t* batch_master_words,
                                                int words_count,
                                                uint32_t batch_count,
                                                const uint32_t* derivations,
                                                const uint32_t* derindex,
                                                uint32_t der_indexes_size,
                                                uint32_t der_start_index,
                                                const char* passwd,
                                                uint32_t pass_size,
                                                uint32_t starter_pass,
                                                uint64_t round,
                                                uint8_t m_mode,
                                                bool is_str,
                                                bool dub_mnem,
                                                uint32_t blocks,
                                                uint32_t threads) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    return metal_launch("workerRecoveryEvalMasterBatch",
                        MetalGridSize(blocks),
                        MetalGridSize(threads),
                        is_result,
                        buff_result,
                        prec,
                        prec_pitch,
                        batch_ids,
                        batch_master_words,
                        words_count,
                        batch_count,
                        derivations,
                        derindex,
                        der_indexes_size,
                        der_start_index,
                        passwd,
                        pass_size,
                        starter_pass,
                        round,
                        m_mode,
                        is_str,
                        dub_mnem);
}

metalError_t metal_vanity_set_step_increment(uint64_t step_value, const void* prec, size_t precPitch) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    g_runtime_config.seqStep = step_value;
    metalError_t st = sync_runtime_state();
    if (st != metalSuccess) return st;
    if (prec == nullptr) {
        return remember(metalErrorInvalidDevicePointer);
    }

#ifndef METAL_VANITY_GROUP_SIZE
#define METAL_VANITY_GROUP_SIZE 1024
#endif
    static_assert((METAL_VANITY_GROUP_SIZE % 2) == 0, "vanity group size must be even");
    constexpr size_t kVanityTableWords = (METAL_VANITY_GROUP_SIZE / 2u) * 4u;
    constexpr size_t kVanityTableTotalWords = (2u * kVanityTableWords) + 8u;
    if (g_vanity_gx == nullptr) {
        st = metalMalloc(&g_vanity_gx, kVanityTableTotalWords * sizeof(uint64_t));
        if (st != metalSuccess) return st;
        g_vanity_gy = g_vanity_gx + kVanityTableWords;
        g_vanity_2gnx = g_vanity_gy + kVanityTableWords;
        g_vanity_2gny = g_vanity_2gnx + 4u;
    }

    {
        const auto* precPtr = static_cast<const secp256k1_ge_storage*>(prec);
        const uint32_t windows = g_ecmult_windows;
        const uint32_t bits = g_ecmult_window_bits;
        st = metal_launch("vanity_set_step_table_kernel",
                          1,
                          1,
                          step_value,
                          precPtr,
                          precPitch,
                          g_vanity_gx,
                          g_vanity_gy,
                          g_vanity_2gnx,
                          g_vanity_2gny,
                          windows,
                          bits);
    }
    return st;
}

metalError_t metal_vanity_set_persistent_shift(uint64_t advance) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    metalError_t st = sync_runtime_state();
    if (st != metalSuccess) return st;
    return metal_launch("vanity_compute_persistent_shift_kernel", 1, 1, advance, nullptr);
}

metalError_t metal_vanity_apply_persistent_shift(uint64_t* startx_buf, uint64_t* starty_buf, MetalGridSize grid, MetalGridSize block) {
    SnapshotLock snapshotLock(device_state().snapshotMutex);
    metalError_t st = sync_runtime_state();
    if (st != metalSuccess) return st;
    return metal_launch("vanity_apply_persistent_shift_kernel", grid, block, startx_buf, starty_buf);
}

namespace modeinfra {
namespace {

constexpr std::uint64_t kMiB = 1024ull * 1024ull;
constexpr std::uint64_t kGiB = 1024ull * kMiB;

bool add_u64_checked(const U256& value,
                     std::uint64_t addend,
                     U256& result) {
    return add_checked(value, U256::from_u64(addend), result);
}

bool u256_to_u64(const U256& value, std::uint64_t& result) {
    if (value.limbs[1] != 0 || value.limbs[2] != 0 ||
        value.limbs[3] != 0) {
        return false;
    }
    result = value.limbs[0];
    return true;
}

bool parse_u64_decimal(std::string_view text, std::uint64_t& result) {
    if (text.empty()) {
        return false;
    }
    std::uint64_t value = 0;
    for (char ch : text) {
        if (ch < '0' || ch > '9') {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) /
                        10ull) {
            return false;
        }
        value = value * 10ull + digit;
    }
    result = value;
    return true;
}

std::string trim_lower(std::string_view text) {
    std::size_t begin = 0;
    std::size_t end = text.size();
    while (begin < end &&
           std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
        ++begin;
    }
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
        --end;
    }
    std::string result(text.substr(begin, end - begin));
    std::transform(result.begin(), result.end(), result.begin(), [](char ch) {
        return static_cast<char>(
            std::tolower(static_cast<unsigned char>(ch)));
    });
    return result;
}

bool checked_mul_u64(std::uint64_t left,
                     std::uint64_t right,
                     std::uint64_t& result) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        return false;
    }
    result = left * right;
    return true;
}

bool checked_add_u64(std::uint64_t left,
                     std::uint64_t right,
                     std::uint64_t& result) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        return false;
    }
    result = left + right;
    return true;
}

std::string format_rate(double value) {
    static constexpr const char* kSuffixes[] = {
        "", "K", "M", "G", "T", "P", "E"
    };
    std::size_t suffix = 0;
    while (value >= 1000.0 &&
           suffix + 1 < sizeof(kSuffixes) / sizeof(kSuffixes[0])) {
        value /= 1000.0;
        ++suffix;
    }
    std::ostringstream output;
    output << std::fixed << std::setprecision(2) << value << kSuffixes[suffix];
    return output.str();
}

std::uint64_t delta(std::uint64_t current, std::uint64_t base) {
    return current >= base ? current - base : 0;
}

} // namespace

void ModeProgress::begin(const char* mode_name,
                         ProgressUnit primary_unit,
                         ProgressPhase phase) {
    active_.store(false, std::memory_order_release);
    completed_candidates_.store(0, std::memory_order_relaxed);
    primitive_operations_.store(0, std::memory_order_relaxed);
    exact_verifications_.store(0, std::memory_order_relaxed);
    logical_targets_.store(0, std::memory_order_relaxed);
    resident_targets_.store(0, std::memory_order_relaxed);
    solved_targets_.store(0, std::memory_order_relaxed);
    founds_.store(0, std::memory_order_relaxed);
    allocated_working_set_.store(0, std::memory_order_relaxed);
    readback_ns_.store(0, std::memory_order_relaxed);
    mode_name_.store(mode_name == nullptr ? "" : mode_name,
                     std::memory_order_relaxed);
    primary_unit_.store(static_cast<std::uint32_t>(primary_unit),
                        std::memory_order_relaxed);
    phase_.store(static_cast<std::uint32_t>(phase),
                 std::memory_order_relaxed);
    epoch_.fetch_add(1, std::memory_order_acq_rel);
    active_.store(true, std::memory_order_release);
}

void ModeProgress::end() {
    active_.store(false, std::memory_order_release);
    phase_.store(static_cast<std::uint32_t>(ProgressPhase::Idle),
                 std::memory_order_relaxed);
    epoch_.fetch_add(1, std::memory_order_acq_rel);
}

void ModeProgress::set_phase(ProgressPhase phase) {
    phase_.store(static_cast<std::uint32_t>(phase),
                 std::memory_order_release);
    epoch_.fetch_add(1, std::memory_order_acq_rel);
}

void ModeProgress::credit_completed(std::uint64_t candidates,
                                    std::uint64_t primitive_operations,
                                    std::uint64_t exact_verifications,
                                    std::uint64_t readback_ns) {
    completed_candidates_.fetch_add(candidates, std::memory_order_release);
    primitive_operations_.fetch_add(
        primitive_operations, std::memory_order_release);
    exact_verifications_.fetch_add(
        exact_verifications, std::memory_order_release);
    readback_ns_.fetch_add(readback_ns, std::memory_order_release);
}

void ModeProgress::set_targets(std::uint64_t logical,
                               std::uint64_t resident,
                               std::uint64_t solved) {
    logical_targets_.store(logical, std::memory_order_release);
    resident_targets_.store(resident, std::memory_order_release);
    solved_targets_.store(solved, std::memory_order_release);
}

void ModeProgress::set_founds(std::uint64_t founds) {
    founds_.store(founds, std::memory_order_release);
}

void ModeProgress::set_allocated_working_set(std::uint64_t bytes) {
    allocated_working_set_.store(bytes, std::memory_order_release);
}

ProgressSnapshot ModeProgress::snapshot() const {
    ProgressSnapshot result;
    result.active = active_.load(std::memory_order_acquire);
    result.mode_name = mode_name_.load(std::memory_order_acquire);
    result.phase = static_cast<ProgressPhase>(
        phase_.load(std::memory_order_acquire));
    result.primary_unit = static_cast<ProgressUnit>(
        primary_unit_.load(std::memory_order_acquire));
    result.epoch = epoch_.load(std::memory_order_acquire);
    result.completed_candidates =
        completed_candidates_.load(std::memory_order_acquire);
    result.primitive_operations =
        primitive_operations_.load(std::memory_order_acquire);
    result.exact_verifications =
        exact_verifications_.load(std::memory_order_acquire);
    result.logical_targets =
        logical_targets_.load(std::memory_order_acquire);
    result.resident_targets =
        resident_targets_.load(std::memory_order_acquire);
    result.solved_targets =
        solved_targets_.load(std::memory_order_acquire);
    result.founds = founds_.load(std::memory_order_acquire);
    result.allocated_working_set =
        allocated_working_set_.load(std::memory_order_acquire);
    result.readback_ns = readback_ns_.load(std::memory_order_acquire);
    return result;
}

ModeProgress& global_mode_progress() {
    static ModeProgress progress;
    return progress;
}

const char* progress_phase_name(ProgressPhase phase) {
    switch (phase) {
    case ProgressPhase::Load: return "LOAD";
    case ProgressPhase::Build: return "BUILD";
    case ProgressPhase::Search: return "SEARCH";
    case ProgressPhase::Verify: return "VERIFY";
    case ProgressPhase::Idle:
    default:
        return "IDLE";
    }
}

const char* progress_unit_name(ProgressUnit unit) {
    switch (unit) {
    case ProgressUnit::Key: return "Key";
    case ProgressUnit::Address: return "Addr";
    case ProgressUnit::Path: return "Path";
    case ProgressUnit::Nonce: return "Nonce";
    case ProgressUnit::Password: return "Pwd";
    case ProgressUnit::Kdf: return "KDF";
    case ProgressUnit::Verify: return "Verify";
    case ProgressUnit::Candidate:
    default:
        return "Candidate";
    }
}

std::string format_progress_line(const ProgressSnapshot& base,
                                 const ProgressSnapshot& current,
                                 double elapsed_seconds) {
    if (elapsed_seconds <= 0.0) {
        elapsed_seconds = 0.001;
    }
    const double completed_rate =
        static_cast<double>(delta(current.completed_candidates,
                                  base.completed_candidates)) /
        elapsed_seconds;
    const double primitive_rate =
        static_cast<double>(delta(current.primitive_operations,
                                  base.primitive_operations)) /
        elapsed_seconds;
    const double verify_rate =
        static_cast<double>(delta(current.exact_verifications,
                                  base.exact_verifications)) /
        elapsed_seconds;

    std::ostringstream output;
    output << "[!] T:[" << current.completed_candidates << "]"
           << " | MODE:["
           << (current.mode_name == nullptr ? "" : current.mode_name)
           << ":" << progress_phase_name(current.phase) << "]"
           << " | S:[" << format_rate(completed_rate) << " "
           << progress_unit_name(current.primary_unit) << "/s]";
    if (current.primitive_operations != 0 ||
        base.primitive_operations != 0) {
        output << " [" << format_rate(primitive_rate) << " Primitive/s]";
    }
    if (current.exact_verifications != 0 ||
        base.exact_verifications != 0) {
        output << " [" << format_rate(verify_rate) << " Verify/s]";
    }
    output << " | A:[" << current.resident_targets
           << "/" << current.logical_targets
           << "] R:[" << current.solved_targets << "]"
           << " | M:[" << std::fixed << std::setprecision(2)
           << static_cast<double>(current.allocated_working_set) /
                  static_cast<double>(kGiB)
           << " GiB]"
           << " RB:[" << std::fixed << std::setprecision(2)
           << static_cast<double>(current.readback_ns) / 1000000.0
           << " ms]"
           << " | F:[" << current.founds << "] [!]";
    return output.str();
}

bool parse_memory_spec(std::string_view text,
                       MemorySpec& result,
                       std::string& error) {
    const std::string normalized = trim_lower(text);
    if (normalized == "auto") {
        result = MemorySpec{ MemoryKind::Auto, 0 };
        return true;
    }
    if (normalized == "all") {
        result = MemorySpec{ MemoryKind::All, 0 };
        return true;
    }
    if (normalized.empty()) {
        error = "memory value is empty";
        return false;
    }

    if (normalized.back() == '%') {
        std::uint64_t percent = 0;
        if (!parse_u64_decimal(
                std::string_view(normalized).substr(
                    0, normalized.size() - 1), percent) ||
            percent == 0 || percent > 100) {
            error = "memory percentage must be between 1% and 100%";
            return false;
        }
        result = MemorySpec{ MemoryKind::Percent, percent };
        return true;
    }

    std::uint64_t multiplier = kMiB;
    std::string_view digits(normalized);
    if (normalized.size() >= 3) {
        const std::string_view suffix =
            std::string_view(normalized).substr(normalized.size() - 3);
        if (suffix == "mib") {
            digits = std::string_view(normalized).substr(
                0, normalized.size() - 3);
        } else if (suffix == "gib") {
            digits = std::string_view(normalized).substr(
                0, normalized.size() - 3);
            multiplier = kGiB;
        }
    }
    std::uint64_t count = 0;
    std::uint64_t bytes = 0;
    if (!parse_u64_decimal(digits, count) || count == 0 ||
        !checked_mul_u64(count, multiplier, bytes)) {
        error = "memory size must be a positive integer in MiB or GiB";
        return false;
    }
    result = MemorySpec{ MemoryKind::Bytes, bytes };
    return true;
}

bool resolve_memory_budget(const MemorySpec& spec,
                           const std::vector<MemoryDeviceInfo>& devices,
                           std::uint64_t mandatory_per_device,
                           std::uint64_t host_resident_bytes,
                           MemoryBudget& result,
                           std::string& error,
                           std::uint64_t runtime_reserve) {
    if (devices.empty()) {
        error = "no Metal devices were selected";
        return false;
    }

    std::uint64_t minimum_free = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t minimum_max_buffer =
        std::numeric_limits<std::uint64_t>::max();
    bool any_unified = false;
    for (const MemoryDeviceInfo& device : devices) {
        const std::uint64_t total =
            device.recommended_max_working_set != 0
            ? device.recommended_max_working_set
            : device.max_buffer_length;
        const std::uint64_t free =
            total > device.current_allocated
            ? total - device.current_allocated
            : 0;
        minimum_free = std::min(minimum_free, free);
        minimum_max_buffer =
            std::min(minimum_max_buffer, device.max_buffer_length);
        any_unified = any_unified || device.unified;
    }
    if (minimum_free <= runtime_reserve) {
        error = "not enough recommended Metal working set after runtime reserve";
        return false;
    }

    std::uint64_t requested = 0;
    switch (spec.kind) {
    case MemoryKind::Auto:
        requested = std::min(
            minimum_free / 2ull,
            minimum_free - runtime_reserve);
        break;
    case MemoryKind::All:
        requested = minimum_free - runtime_reserve;
        break;
    case MemoryKind::Percent:
        requested = static_cast<std::uint64_t>(
            (static_cast<unsigned __int128>(minimum_free) * spec.value) /
            100ull);
        break;
    case MemoryKind::Bytes:
        requested = spec.value;
        break;
    }
    if (requested > minimum_free - runtime_reserve) {
        error = "requested memory exceeds the remaining recommended Metal working set";
        return false;
    }

    std::uint64_t replicated_mandatory = 0;
    if (!checked_mul_u64(mandatory_per_device,
                         static_cast<std::uint64_t>(devices.size()),
                         replicated_mandatory)) {
        error = "mandatory Metal memory size overflows 64 bits";
        return false;
    }
    std::uint64_t mandatory_total = 0;
    if (!checked_add_u64(replicated_mandatory,
                         host_resident_bytes,
                         mandatory_total)) {
        error = "mandatory host and Metal memory size overflows 64 bits";
        return false;
    }

    if (any_unified) {
        if (mandatory_total > requested) {
            error = "memory budget is smaller than mandatory unified-memory buffers";
            return false;
        }
        const std::uint64_t device_pool = requested - host_resident_bytes;
        result.per_device_budget =
            device_pool / static_cast<std::uint64_t>(devices.size());
        result.total_budget = requested;
    } else {
        if (mandatory_per_device > requested) {
            error = "per-device memory budget is smaller than mandatory buffers";
            return false;
        }
        result.per_device_budget = requested;
        std::uint64_t replicated_budget = 0;
        if (!checked_mul_u64(requested,
                             static_cast<std::uint64_t>(devices.size()),
                             replicated_budget) ||
            !checked_add_u64(replicated_budget,
                             host_resident_bytes,
                             result.total_budget)) {
            error = "aggregate Metal memory budget overflows 64 bits";
            return false;
        }
    }

    result.free_working_set = minimum_free;
    result.max_buffer_length = minimum_max_buffer;
    result.mandatory_bytes = mandatory_total;
    result.unified = any_unified;
    return true;
}

U256 U256::from_u64(std::uint64_t value) {
    U256 result;
    result.limbs[0] = value;
    return result;
}

bool U256::is_zero() const {
    return limbs[0] == 0 && limbs[1] == 0 &&
           limbs[2] == 0 && limbs[3] == 0;
}

int compare(const U256& left, const U256& right) {
    for (std::size_t i = 4; i-- > 0;) {
        if (left.limbs[i] < right.limbs[i]) return -1;
        if (left.limbs[i] > right.limbs[i]) return 1;
    }
    return 0;
}

bool add_checked(const U256& left, const U256& right, U256& result) {
    unsigned __int128 carry = 0;
    for (std::size_t i = 0; i < result.limbs.size(); ++i) {
        const unsigned __int128 sum =
            static_cast<unsigned __int128>(left.limbs[i]) +
            right.limbs[i] + carry;
        result.limbs[i] = static_cast<std::uint64_t>(sum);
        carry = sum >> 64u;
    }
    return carry == 0;
}

bool subtract_checked(const U256& left,
                      const U256& right,
                      U256& result) {
    if (compare(left, right) < 0) {
        result = U256{};
        return false;
    }
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < result.limbs.size(); ++i) {
        const std::uint64_t right_with_borrow = right.limbs[i] + borrow;
        const bool carry_from_borrow =
            borrow != 0 && right_with_borrow == 0;
        const bool next_borrow =
            carry_from_borrow || left.limbs[i] < right_with_borrow;
        result.limbs[i] = left.limbs[i] - right_with_borrow;
        borrow = next_borrow ? 1u : 0u;
    }
    return borrow == 0;
}

bool multiply_checked(const U256& value,
                      std::uint64_t factor,
                      U256& result) {
    unsigned __int128 carry = 0;
    for (std::size_t i = 0; i < result.limbs.size(); ++i) {
        const unsigned __int128 product =
            static_cast<unsigned __int128>(value.limbs[i]) * factor +
            carry;
        result.limbs[i] = static_cast<std::uint64_t>(product);
        carry = product >> 64u;
    }
    return carry == 0;
}

bool divide(const U256& value,
            std::uint64_t divisor,
            U256& quotient,
            std::uint64_t& remainder) {
    if (divisor == 0) {
        quotient = U256{};
        remainder = 0;
        return false;
    }
    unsigned __int128 carry = 0;
    for (std::size_t i = 4; i-- > 0;) {
        const unsigned __int128 current =
            (carry << 64u) | value.limbs[i];
        quotient.limbs[i] =
            static_cast<std::uint64_t>(current / divisor);
        carry = current % divisor;
    }
    remainder = static_cast<std::uint64_t>(carry);
    return true;
}

bool parse_u256(std::string_view text, U256& result, std::string& error) {
    const std::string normalized = trim_lower(text);
    if (normalized.empty()) {
        error = "U256 value is empty";
        return false;
    }
    if (normalized.rfind("2^", 0) == 0) {
        std::uint64_t exponent = 0;
        if (!parse_u64_decimal(std::string_view(normalized).substr(2),
                               exponent) ||
            exponent > 255) {
            error = "U256 exponent must be between 0 and 255";
            return false;
        }
        result = U256{};
        result.limbs[exponent / 64u] =
            1ull << static_cast<unsigned int>(exponent % 64u);
        return true;
    }

    const bool hexadecimal = normalized.rfind("0x", 0) == 0;
    const std::string_view digits = hexadecimal
        ? std::string_view(normalized).substr(2)
        : std::string_view(normalized);
    if (digits.empty()) {
        error = "U256 value has no digits";
        return false;
    }

    result = U256{};
    const std::uint64_t base = hexadecimal ? 16ull : 10ull;
    for (char ch : digits) {
        std::uint64_t digit = 0;
        if (ch >= '0' && ch <= '9') {
            digit = static_cast<std::uint64_t>(ch - '0');
        } else if (hexadecimal && ch >= 'a' && ch <= 'f') {
            digit = static_cast<std::uint64_t>(ch - 'a' + 10);
        } else {
            error = "U256 value contains an invalid digit";
            return false;
        }
        if (digit >= base) {
            error = "U256 value contains an invalid digit";
            return false;
        }
        U256 multiplied;
        U256 next;
        if (!multiply_checked(result, base, multiplied) ||
            !add_u64_checked(multiplied, digit, next)) {
            error = "U256 value overflows 256 bits";
            return false;
        }
        result = next;
    }
    return true;
}

std::string u256_hex(const U256& value) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t i = 4; i-- > 0;) {
        output << std::setw(16) << value.limbs[i];
    }
    return output.str();
}

bool MixedRadixDomain::reset(const std::vector<std::uint64_t>& radices,
                             std::string& error) {
    radices_.clear();
    size_ = U256{};
    if (radices.empty()) {
        error = "mixed-radix domain requires at least one radix";
        return false;
    }
    U256 total = U256::from_u64(1);
    for (std::uint64_t radix : radices) {
        if (radix == 0) {
            error = "mixed-radix values must be non-zero";
            return false;
        }
        U256 next;
        if (!multiply_checked(total, radix, next)) {
            error = "mixed-radix domain exceeds 256 bits";
            return false;
        }
        total = next;
    }
    radices_ = radices;
    size_ = total;
    return true;
}

const U256& MixedRadixDomain::size() const {
    return size_;
}

const std::vector<std::uint64_t>& MixedRadixDomain::radices() const {
    return radices_;
}

bool MixedRadixDomain::decode(const U256& ordinal,
                              std::vector<std::uint64_t>& digits,
                              std::string& error) const {
    if (radices_.empty() || compare(ordinal, size_) >= 0) {
        error = "mixed-radix ordinal is outside the domain";
        return false;
    }
    digits.assign(radices_.size(), 0);
    U256 current = ordinal;
    for (std::size_t i = 0; i < radices_.size(); ++i) {
        U256 quotient;
        std::uint64_t remainder = 0;
        if (!divide(current, radices_[i], quotient, remainder)) {
            error = "mixed-radix division failed";
            return false;
        }
        digits[i] = remainder;
        current = quotient;
    }
    return true;
}

bool MixedRadixDomain::split(std::uint64_t shard_index,
                             std::uint64_t shard_count,
                             U256& begin,
                             U256& count,
                             std::string& error) const {
    if (radices_.empty() || shard_count == 0 ||
        shard_index >= shard_count) {
        error = "invalid mixed-radix shard";
        return false;
    }
    U256 quotient;
    std::uint64_t remainder = 0;
    if (!divide(size_, shard_count, quotient, remainder)) {
        error = "mixed-radix shard division failed";
        return false;
    }
    U256 scaled;
    if (!multiply_checked(quotient, shard_index, scaled) ||
        !add_u64_checked(
            scaled, std::min(shard_index, remainder), begin)) {
        error = "mixed-radix shard offset overflows 256 bits";
        return false;
    }
    if (!add_u64_checked(
            quotient, shard_index < remainder ? 1ull : 0ull, count)) {
        error = "mixed-radix shard length overflows 256 bits";
        return false;
    }
    return true;
}

bool MixedRadixDomain::next_window(const U256& cursor,
                                   std::uint64_t maximum_items,
                                   U256& end,
                                   std::uint64_t& count,
                                   std::string& error) const {
    if (maximum_items == 0 || compare(cursor, size_) > 0) {
        error = "invalid mixed-radix window";
        return false;
    }
    U256 remaining;
    if (!subtract_checked(size_, cursor, remaining)) {
        error = "mixed-radix cursor is outside the domain";
        return false;
    }
    if (remaining.is_zero()) {
        end = cursor;
        count = 0;
        return true;
    }
    const U256 maximum = U256::from_u64(maximum_items);
    if (compare(remaining, maximum) <= 0) {
        if (!u256_to_u64(remaining, count)) {
            error = "mixed-radix final window exceeds 64 bits";
            return false;
        }
    } else {
        count = maximum_items;
    }
    if (!add_u64_checked(cursor, count, end)) {
        error = "mixed-radix window end overflows 256 bits";
        return false;
    }
    return true;
}

void print_help_section(FILE* output,
                        const char* title,
                        std::initializer_list<const char*> lines) {
    if (output == nullptr) {
        return;
    }
    std::fprintf(output, "[!] %s [!]\n", title == nullptr ? "" : title);
    for (const char* line : lines) {
        std::fprintf(output, "[!] %s\n", line == nullptr ? "" : line);
    }
}

} // namespace modeinfra
