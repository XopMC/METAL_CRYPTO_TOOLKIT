#include "Eth2ValidatorMode.h"

#include "../MetalBackend.h"
#include "../RecoveryWordlistsEmbedded.h"
#include "../bls12_381/Bls12381.h"
#include "../lib/hash/sha256.h"

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CoreFoundation/CoreFoundation.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace eth2validator_mode {
namespace {

constexpr std::uint32_t kThreadgroupSize = 256u;
constexpr std::uint64_t kMaximumBatch = 4096u;
constexpr std::uint32_t kHitCapacity = 4096u;
constexpr std::uint64_t kPasswordStride = 128u;
constexpr std::uint64_t kMnemonicStride = 256u;
constexpr std::uint64_t kRuntimeReserve =
    512ull * 1024ull * 1024ull;
constexpr std::uint32_t kKdfPbkdf2 = 1u;
constexpr std::uint32_t kKdfScrypt = 2u;

struct GpuTarget {
    std::uint32_t kdf_type = 0u;
    std::uint32_t iterations = 0u;
    std::uint32_t scrypt_n = 0u;
    std::uint32_t scrypt_r = 0u;
    std::uint32_t scrypt_p = 0u;
    std::uint32_t salt_len = 0u;
    std::uint32_t target_index = 0u;
    std::uint32_t reserved = 0u;
    std::array<std::uint8_t, 64> salt{};
    std::array<std::uint8_t, 16> iv{};
    std::array<std::uint8_t, 32> ciphertext{};
    std::array<std::uint8_t, 32> checksum{};
    std::array<std::uint8_t, 48> public_key{};
};

struct alignas(8) GpuHit {
    std::uint64_t candidate_index = 0u;
    std::uint32_t target_index = 0u;
    std::uint32_t password_len = 0u;
    std::array<std::uint8_t, 128> password{};
    std::array<std::uint8_t, 32> derived_key{};
    std::array<std::uint8_t, 32> secret{};
};

static_assert(sizeof(GpuTarget) == 224u);
static_assert(sizeof(GpuHit) == 208u);

struct Options {
    std::vector<std::string> keystores;
    std::vector<std::pair<std::string, bool>> candidate_inputs;
    std::vector<std::string> mnemonic_inputs;
    std::vector<std::string> seed_inputs;
    std::vector<std::string> target_inputs;
    std::string mask;
    std::string start;
    std::string end;
    std::string mnemonic_passphrase;
    std::string path = "m/12381/3600/0/0/0";
    std::string memory = "auto";
    std::string scrypt_memory;
    std::string output_path;
    std::vector<int> devices{0};
    std::uint64_t batch = kMaximumBatch;
    bool save = false;
    bool silent = false;
};

struct Target {
    GpuTarget gpu;
    std::string source;
    std::string path;
    std::vector<std::string> origins;
    bool solved = false;
};

struct PublicTarget {
    std::array<std::uint8_t, 48> key{};
    std::vector<std::string> origins;
    bool solved = false;
};

struct DeviceBuffers {
    int device = -1;
    GpuTarget* targets = nullptr;
    std::uint8_t* solved = nullptr;
    char* passwords = nullptr;
    std::uint8_t* lengths = nullptr;
    std::uint8_t* scratch = nullptr;
    GpuHit* hits = nullptr;
    std::uint32_t* hit_count = nullptr;
    std::uint64_t capacity = 0u;
    std::uint64_t allocated = 0u;
};

struct MnemonicBuffers {
    int device = -1;
    char* mnemonics = nullptr;
    std::uint16_t* lengths = nullptr;
    std::uint8_t* salt = nullptr;
    std::uint8_t* seeds = nullptr;
    std::uint64_t capacity = 0u;
    std::uint64_t allocated = 0u;
};

std::string trim_copy(std::string value) {
    const std::size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1u);
}

std::string lower_copy(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

bool parse_u64(const std::string& raw, std::uint64_t& value) {
    try {
        std::size_t consumed = 0u;
        value = std::stoull(raw, &consumed, 0);
        return consumed == raw.size();
    } catch (...) {
        return false;
    }
}

int hex_digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

bool decode_hex(const std::string& raw,
                std::vector<std::uint8_t>& output) {
    std::string value = trim_copy(raw);
    if (value.size() >= 2u && value[0] == '0' &&
        (value[1] == 'x' || value[1] == 'X')) {
        value.erase(0u, 2u);
    }
    if (value.empty() || (value.size() & 1u) != 0u) return false;
    output.resize(value.size() / 2u);
    for (std::size_t i = 0u; i < output.size(); ++i) {
        const int high = hex_digit(value[i * 2u]);
        const int low = hex_digit(value[i * 2u + 1u]);
        if (high < 0 || low < 0) return false;
        output[i] =
            static_cast<std::uint8_t>((high << 4u) | low);
    }
    return true;
}

std::string hex_string(const std::uint8_t* bytes,
                       std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t i = 0u; i < size; ++i) {
        output << std::setw(2)
               << static_cast<unsigned>(bytes[i]);
    }
    return output.str();
}

bool read_text_file(const std::string& path,
                    std::string& text,
                    std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "cannot open '" + path + "'";
        return false;
    }
    std::ostringstream contents;
    contents << input.rdbuf();
    text = contents.str();
    return true;
}

bool parse_devices(const std::string& raw,
                   std::vector<int>& devices,
                   std::string& error) {
    std::set<int> unique;
    std::stringstream input(raw);
    std::string token;
    while (std::getline(input, token, ',')) {
        token = trim_copy(token);
        if (token.empty()) {
            error = "empty item in -device";
            return false;
        }
        const std::size_t dash = token.find('-');
        if (dash == std::string::npos) {
            std::uint64_t value = 0u;
            if (!parse_u64(token, value) ||
                value > static_cast<std::uint64_t>(
                    std::numeric_limits<int>::max())) {
                error = "invalid -device item '" + token + "'";
                return false;
            }
            unique.insert(static_cast<int>(value));
            continue;
        }
        std::uint64_t first = 0u;
        std::uint64_t last = 0u;
        if (!parse_u64(token.substr(0u, dash), first) ||
            !parse_u64(token.substr(dash + 1u), last) ||
            first > last || last > 1024u) {
            error = "invalid -device range '" + token + "'";
            return false;
        }
        for (std::uint64_t value = first; value <= last; ++value) {
            unique.insert(static_cast<int>(value));
        }
    }
    if (unique.empty()) {
        error = "-device list is empty";
        return false;
    }
    devices.assign(unique.begin(), unique.end());
    return true;
}

bool parse_options(int argc, char** argv,
                   Options& options,
                   std::string& error) {
    bool after_mode = false;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "-eth2validator") {
            after_mode = true;
            continue;
        }
        const auto value = [&](const char* flag) -> const char* {
            if (i + 1 >= argc) {
                error = std::string(flag) + " requires a value";
                return nullptr;
            }
            return argv[++i];
        };
        if (argument == "-keystore") {
            const char* item = value("-keystore");
            if (!item) return false;
            options.keystores.emplace_back(item);
        } else if (argument == "-pass") {
            const char* item = value("-pass");
            if (!item) return false;
            options.candidate_inputs.push_back({item, false});
        } else if (argument == "-i") {
            const char* item = value("-i");
            if (!item) return false;
            options.candidate_inputs.push_back({item, true});
        } else if (argument == "-mnemonic") {
            const char* item = value("-mnemonic");
            if (!item) return false;
            options.mnemonic_inputs.emplace_back(item);
        } else if (argument == "-seed") {
            const char* item = value("-seed");
            if (!item) return false;
            options.seed_inputs.emplace_back(item);
        } else if (argument == "-target") {
            const char* item = value("-target");
            if (!item) return false;
            options.target_inputs.emplace_back(item);
        } else if (argument == "-path") {
            const char* item = value("-path");
            if (!item) return false;
            options.path = item;
        } else if (argument == "-passphrase") {
            const char* item = value("-passphrase");
            if (!item) return false;
            options.mnemonic_passphrase = item;
        } else if (argument == "-mask") {
            const char* item = value("-mask");
            if (!item) return false;
            options.mask = item;
        } else if (argument == "-start") {
            const char* item = value("-start");
            if (!item) return false;
            options.start = item;
        } else if (argument == "-end") {
            const char* item = value("-end");
            if (!item) return false;
            options.end = item;
        } else if (argument == "-wallet-mem") {
            const char* item = value("-wallet-mem");
            if (!item) return false;
            options.memory = item;
        } else if (argument == "-wallet-scrypt-mem") {
            const char* item = value("-wallet-scrypt-mem");
            if (!item) return false;
            options.scrypt_memory = item;
        } else if (argument == "-n") {
            const char* item = value("-n");
            if (!item || !parse_u64(item, options.batch) ||
                options.batch == 0u ||
                options.batch > kMaximumBatch) {
                error = "-n must be in 1..4096";
                return false;
            }
        } else if (argument == "-device") {
            const char* item = value("-device");
            if (!item ||
                !parse_devices(item, options.devices, error)) {
                return false;
            }
        } else if (argument == "-o") {
            const char* item = value("-o");
            if (!item) return false;
            options.output_path = item;
        } else if (argument == "-save") {
            options.save = true;
        } else if (argument == "-silent") {
            options.silent = true;
        } else if (argument == "-help" || argument == "--help" ||
                   argument == "-h" || argument == "help") {
            continue;
        } else if (!argument.empty() && argument[0] != '-' &&
                   after_mode) {
            options.keystores.push_back(argument);
        } else {
            error = "unsupported -eth2validator argument '" +
                argument + "'";
            return false;
        }
    }

    const bool derivation_requested =
        !options.mnemonic_inputs.empty() ||
        !options.seed_inputs.empty() ||
        (options.keystores.empty() &&
         !options.target_inputs.empty() &&
         !options.candidate_inputs.empty());
    if (derivation_requested && options.keystores.empty()) {
        for (const auto& input : options.candidate_inputs) {
            if (!input.second) {
                error = "-pass belongs to EIP-2335 password recovery; "
                        "use -mnemonic for a literal phrase";
                return false;
            }
            options.mnemonic_inputs.push_back(input.first);
        }
        options.candidate_inputs.clear();
    }
    if (!options.keystores.empty() && derivation_requested) {
        error = "choose EIP-2335 keystores or mnemonic/seed derivation, not both";
        return false;
    }
    if (options.keystores.empty() &&
        options.mnemonic_inputs.empty() &&
        options.seed_inputs.empty()) {
        error = "provide a v4 EIP-2335 keystore, -mnemonic/-i, or -seed";
        return false;
    }
    if ((!options.mnemonic_inputs.empty() ||
         !options.seed_inputs.empty()) &&
        options.target_inputs.empty()) {
        error = "mnemonic/seed recovery requires -target validator pubkey";
        return false;
    }
    const int password_modes =
        (!options.candidate_inputs.empty() ? 1 : 0) +
        (!options.mask.empty() ? 1 : 0) +
        ((!options.start.empty() || !options.end.empty()) ? 1 : 0);
    if (!options.keystores.empty() && password_modes > 1) {
        error = "choose one password source: -pass/-i, -mask, or -start/-end";
        return false;
    }
    if ((!options.start.empty() || !options.end.empty()) &&
        (options.start.empty() || options.end.empty())) {
        error = "numeric password search requires both -start and -end";
        return false;
    }
    return true;
}

bool json_value_start(const std::string& object,
                      const std::string& key,
                      std::size_t& position) {
    const std::string marker = "\"" + key + "\"";
    position = object.find(marker);
    if (position == std::string::npos) return false;
    position = object.find(':', position + marker.size());
    if (position == std::string::npos) return false;
    ++position;
    while (position < object.size() &&
           std::isspace(static_cast<unsigned char>(
               object[position])) != 0) {
        ++position;
    }
    return position < object.size();
}

bool json_string_value(const std::string& object,
                       const std::string& key,
                       std::string& value) {
    std::size_t position = 0u;
    if (!json_value_start(object, key, position) ||
        object[position] != '"') {
        return false;
    }
    ++position;
    value.clear();
    bool escaped = false;
    for (; position < object.size(); ++position) {
        const char character = object[position];
        if (escaped) {
            if (character == '"' || character == '\\' ||
                character == '/') {
                value.push_back(character);
            } else if (character == 'n') {
                value.push_back('\n');
            } else if (character == 'r') {
                value.push_back('\r');
            } else if (character == 't') {
                value.push_back('\t');
            } else {
                return false;
            }
            escaped = false;
        } else if (character == '\\') {
            escaped = true;
        } else if (character == '"') {
            return true;
        } else {
            value.push_back(character);
        }
    }
    return false;
}

bool json_u64_value(const std::string& object,
                    const std::string& key,
                    std::uint64_t& value) {
    std::size_t position = 0u;
    if (!json_value_start(object, key, position)) return false;
    const std::size_t start = position;
    while (position < object.size() &&
           std::isdigit(static_cast<unsigned char>(
               object[position])) != 0) {
        ++position;
    }
    return position > start &&
        parse_u64(object.substr(start, position - start), value);
}

bool json_object_value(const std::string& object,
                       const std::string& key,
                       std::string& value) {
    std::size_t position = 0u;
    if (!json_value_start(object, key, position) ||
        object[position] != '{') {
        return false;
    }
    const std::size_t start = position;
    unsigned depth = 0u;
    bool string = false;
    bool escaped = false;
    for (; position < object.size(); ++position) {
        const char character = object[position];
        if (string) {
            if (escaped) escaped = false;
            else if (character == '\\') escaped = true;
            else if (character == '"') string = false;
            continue;
        }
        if (character == '"') {
            string = true;
        } else if (character == '{') {
            ++depth;
        } else if (character == '}') {
            if (--depth == 0u) {
                value = object.substr(
                    start, position - start + 1u);
                return true;
            }
        }
    }
    return false;
}

template <std::size_t Size>
bool decode_fixed(const std::string& value,
                  std::array<std::uint8_t, Size>& output) {
    std::vector<std::uint8_t> decoded;
    if (!decode_hex(value, decoded) ||
        decoded.size() != Size) {
        return false;
    }
    std::copy(decoded.begin(), decoded.end(), output.begin());
    return true;
}

bool parse_keystore(const std::string& path,
                    Target& target,
                    std::string& error) {
    std::string root;
    if (!read_text_file(path, root, error)) return false;
    std::uint64_t version = 0u;
    if (!json_u64_value(root, "version", version) ||
        version != 4u) {
        error = path + ": only EIP-2335 version 4 is supported";
        return false;
    }
    std::string crypto;
    std::string kdf;
    std::string checksum;
    std::string cipher;
    std::string params;
    if (!json_object_value(root, "crypto", crypto) ||
        !json_object_value(crypto, "kdf", kdf) ||
        !json_object_value(crypto, "checksum", checksum) ||
        !json_object_value(crypto, "cipher", cipher)) {
        error = path + ": malformed crypto modules";
        return false;
    }
    std::string function;
    std::string field;
    std::uint64_t number = 0u;
    if (!json_string_value(kdf, "function", function) ||
        !json_object_value(kdf, "params", params)) {
        error = path + ": malformed kdf module";
        return false;
    }
    function = lower_copy(function);
    if (function == "pbkdf2") {
        std::string prf;
        if (!json_string_value(params, "prf", prf) ||
            lower_copy(prf) != "hmac-sha256" ||
            !json_u64_value(params, "c", number) ||
            number == 0u ||
            number > std::numeric_limits<std::uint32_t>::max()) {
            error = path + ": unsupported PBKDF2 parameters";
            return false;
        }
        target.gpu.kdf_type = kKdfPbkdf2;
        target.gpu.iterations =
            static_cast<std::uint32_t>(number);
    } else if (function == "scrypt") {
        std::uint64_t n = 0u;
        std::uint64_t r = 0u;
        std::uint64_t p = 0u;
        if (!json_u64_value(params, "n", n) ||
            !json_u64_value(params, "r", r) ||
            !json_u64_value(params, "p", p) ||
            n < 2u || (n & (n - 1u)) != 0u ||
            r == 0u || r > 8u || p == 0u ||
            n > std::numeric_limits<std::uint32_t>::max() ||
            p > std::numeric_limits<std::uint32_t>::max()) {
            error = path + ": unsupported scrypt parameters";
            return false;
        }
        target.gpu.kdf_type = kKdfScrypt;
        target.gpu.scrypt_n =
            static_cast<std::uint32_t>(n);
        target.gpu.scrypt_r =
            static_cast<std::uint32_t>(r);
        target.gpu.scrypt_p =
            static_cast<std::uint32_t>(p);
    } else {
        error = path + ": unsupported KDF '" + function + "'";
        return false;
    }
    if (!json_u64_value(params, "dklen", number) ||
        number != 32u ||
        !json_string_value(params, "salt", field)) {
        error = path + ": EIP-2335 requires dklen 32 and a salt";
        return false;
    }
    std::vector<std::uint8_t> salt;
    if (!decode_hex(field, salt) || salt.empty() ||
        salt.size() > target.gpu.salt.size()) {
        error = path + ": invalid KDF salt";
        return false;
    }
    target.gpu.salt_len =
        static_cast<std::uint32_t>(salt.size());
    std::copy(salt.begin(), salt.end(), target.gpu.salt.begin());

    if (!json_string_value(checksum, "function", function) ||
        lower_copy(function) != "sha256" ||
        !json_string_value(checksum, "message", field) ||
        !decode_fixed(field, target.gpu.checksum)) {
        error = path + ": checksum must be SHA-256/32 bytes";
        return false;
    }
    if (!json_string_value(cipher, "function", function) ||
        lower_copy(function) != "aes-128-ctr" ||
        !json_string_value(cipher, "message", field) ||
        !decode_fixed(field, target.gpu.ciphertext) ||
        !json_object_value(cipher, "params", params) ||
        !json_string_value(params, "iv", field) ||
        !decode_fixed(field, target.gpu.iv)) {
        error = path + ": cipher must be AES-128-CTR with a 32-byte message";
        return false;
    }
    if (!json_string_value(root, "pubkey", field) ||
        !decode_fixed(field, target.gpu.public_key)) {
        error = path + ": missing 48-byte BLS public key";
        return false;
    }
    if (!json_string_value(root, "path", target.path)) {
        target.path.clear();
    }
    target.source = path;
    target.origins.push_back(path);
    return true;
}

std::string target_identity(const Target& target) {
    return std::string(
        reinterpret_cast<const char*>(&target.gpu),
        sizeof(target.gpu));
}

bool load_keystores(const Options& options,
                    std::vector<Target>& targets,
                    std::uint64_t& logical,
                    std::string& error) {
    std::unordered_map<std::string, std::size_t> unique;
    for (const std::string& path : options.keystores) {
        Target target;
        if (!parse_keystore(path, target, error)) return false;
        const std::string identity = target_identity(target);
        const auto found = unique.find(identity);
        if (found == unique.end()) {
            if (targets.size() >=
                std::numeric_limits<std::uint32_t>::max()) {
                error = "too many unique EIP-2335 keystores";
                return false;
            }
            target.gpu.target_index =
                static_cast<std::uint32_t>(targets.size());
            unique.emplace(identity, targets.size());
            targets.push_back(std::move(target));
        } else {
            targets[found->second].origins.push_back(path);
        }
        ++logical;
    }
    return !targets.empty();
}

bool normalize_nfkd(const std::string& input,
                    bool strip_controls,
                    std::string& output,
                    std::string& error) {
    CFStringRef original = CFStringCreateWithBytes(
        kCFAllocatorDefault,
        reinterpret_cast<const UInt8*>(input.data()),
        static_cast<CFIndex>(input.size()),
        kCFStringEncodingUTF8, false);
    if (original == nullptr) {
        error = "input is not valid UTF-8";
        return false;
    }
    CFMutableStringRef normalized =
        CFStringCreateMutableCopy(
            kCFAllocatorDefault, 0, original);
    CFRelease(original);
    if (normalized == nullptr) {
        error = "cannot allocate normalized string";
        return false;
    }
    CFStringNormalize(normalized, kCFStringNormalizationFormKD);
    CFStringRef filtered = normalized;
    CFMutableStringRef owned_filtered = nullptr;
    if (strip_controls) {
        const CFIndex count = CFStringGetLength(normalized);
        std::vector<UniChar> characters(
            static_cast<std::size_t>(count));
        CFStringGetCharacters(
            normalized, CFRangeMake(0, count),
            characters.data());
        characters.erase(
            std::remove_if(
                characters.begin(), characters.end(),
                [](UniChar character) {
                    return character <= 0x1fu ||
                        character == 0x7fu ||
                        (character >= 0x80u &&
                         character <= 0x9fu);
                }),
            characters.end());
        owned_filtered = CFStringCreateMutable(
            kCFAllocatorDefault, 0);
        if (owned_filtered != nullptr && !characters.empty()) {
            CFStringAppendCharacters(
                owned_filtered, characters.data(),
                static_cast<CFIndex>(characters.size()));
        }
        filtered = owned_filtered;
    }
    if (filtered == nullptr) {
        CFRelease(normalized);
        error = "cannot strip password controls";
        return false;
    }
    const CFIndex count = CFStringGetLength(filtered);
    const CFIndex capacity =
        CFStringGetMaximumSizeForEncoding(
            count, kCFStringEncodingUTF8) + 1;
    std::vector<char> buffer(
        static_cast<std::size_t>(capacity));
    const bool converted = CFStringGetCString(
        filtered, buffer.data(), capacity,
        kCFStringEncodingUTF8);
    if (owned_filtered != nullptr) CFRelease(owned_filtered);
    CFRelease(normalized);
    if (!converted) {
        error = "cannot encode normalized UTF-8";
        return false;
    }
    output.assign(buffer.data());
    return true;
}

std::vector<std::string> split_words(const std::string& phrase) {
    std::istringstream input(phrase);
    std::vector<std::string> words;
    std::string word;
    while (input >> word) words.push_back(word);
    return words;
}

const std::unordered_map<std::string, std::uint16_t>&
bip39_index() {
    static const auto result = [] {
        std::unordered_map<std::string, std::uint16_t> index;
        index.reserve(2048u);
        for (std::uint16_t i = 0u; i < 2048u; ++i) {
            index.emplace(kRecoveryWords_bip39_en[i], i);
        }
        return index;
    }();
    return result;
}

bool valid_bip39(const std::string& phrase) {
    const std::vector<std::string> words = split_words(phrase);
    if (words.size() != 12u && words.size() != 15u &&
        words.size() != 18u && words.size() != 21u &&
        words.size() != 24u) {
        return false;
    }
    const std::size_t total_bits = words.size() * 11u;
    const std::size_t entropy_bits = total_bits * 32u / 33u;
    const std::size_t checksum_bits = total_bits - entropy_bits;
    std::vector<std::uint8_t> bits(total_bits, 0u);
    std::size_t bit = 0u;
    for (const std::string& word : words) {
        const auto found = bip39_index().find(word);
        if (found == bip39_index().end()) return false;
        for (int shift = 10; shift >= 0; --shift) {
            bits[bit++] =
                static_cast<std::uint8_t>(
                    (found->second >> shift) & 1u);
        }
    }
    std::vector<std::uint8_t> entropy(entropy_bits / 8u, 0u);
    for (std::size_t i = 0u; i < entropy_bits; ++i) {
        entropy[i >> 3u] |=
            static_cast<std::uint8_t>(
                bits[i] << (7u - (i & 7u)));
    }
    std::array<std::uint8_t, 32> digest{};
    sha256(entropy.data(), entropy.size(), digest.data());
    for (std::size_t i = 0u; i < checksum_bits; ++i) {
        if (bits[entropy_bits + i] !=
            ((digest[i >> 3u] >> (7u - (i & 7u))) & 1u)) {
            return false;
        }
    }
    return true;
}

bool load_lines_or_literal(
    const std::vector<std::string>& inputs,
    std::vector<std::pair<std::string, std::string>>& output,
    std::string& error) {
    for (const std::string& input_value : inputs) {
        std::error_code filesystem_error;
        if (std::filesystem::is_regular_file(
                input_value, filesystem_error) &&
            !filesystem_error) {
            std::ifstream input(input_value);
            if (!input) {
                error = "cannot open '" + input_value + "'";
                return false;
            }
            std::string line;
            std::size_t number = 0u;
            while (std::getline(input, line)) {
                ++number;
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                const std::size_t comment = line.find('#');
                if (comment != std::string::npos) {
                    line.erase(comment);
                }
                line = trim_copy(line);
                if (!line.empty()) {
                    output.push_back({
                        line, input_value + ":" +
                            std::to_string(number)});
                }
            }
        } else {
            output.push_back({input_value, "argv"});
        }
    }
    return true;
}

bool load_mnemonics(
    const Options& options,
    std::vector<std::pair<std::string, std::string>>& mnemonics,
    std::string& error) {
    std::vector<std::pair<std::string, std::string>> raw;
    if (!load_lines_or_literal(
            options.mnemonic_inputs, raw, error)) {
        return false;
    }
    std::unordered_set<std::string> unique;
    for (const auto& candidate : raw) {
        std::string normalized;
        if (!normalize_nfkd(
                candidate.first, false, normalized, error)) {
            error = candidate.second + ": " + error;
            return false;
        }
        normalized = trim_copy(normalized);
        if (normalized.size() >= kMnemonicStride) {
            error = candidate.second + ": mnemonic exceeds 255 UTF-8 bytes";
            return false;
        }
        if (!valid_bip39(normalized)) continue;
        if (unique.insert(normalized).second) {
            mnemonics.push_back({normalized, candidate.second});
        }
    }
    if (!options.mnemonic_inputs.empty() && mnemonics.empty()) {
        error = "no checksum-valid English BIP39 mnemonics";
        return false;
    }
    return true;
}

bool load_seeds(
    const Options& options,
    std::vector<std::pair<std::vector<std::uint8_t>, std::string>>& seeds,
    std::string& error) {
    std::vector<std::pair<std::string, std::string>> raw;
    if (!load_lines_or_literal(
            options.seed_inputs, raw, error)) {
        return false;
    }
    std::unordered_set<std::string> unique;
    for (const auto& candidate : raw) {
        std::vector<std::uint8_t> seed;
        if (!decode_hex(candidate.first, seed) ||
            seed.size() < 32u || seed.size() > 64u) {
            error = candidate.second +
                ": seed must be 32..64 bytes of hex";
            return false;
        }
        const std::string identity(
            reinterpret_cast<const char*>(seed.data()),
            seed.size());
        if (unique.insert(identity).second) {
            seeds.push_back({std::move(seed), candidate.second});
        }
    }
    return true;
}

bool load_public_targets(
    const Options& options,
    std::vector<PublicTarget>& targets,
    std::uint64_t& logical,
    std::string& error) {
    std::vector<std::pair<std::string, std::string>> raw;
    if (!load_lines_or_literal(
            options.target_inputs, raw, error)) {
        return false;
    }
    std::unordered_map<std::string, std::size_t> unique;
    for (const auto& item : raw) {
        std::string token = item.first;
        const std::size_t space = token.find_first_of(" \t");
        if (space != std::string::npos) token.erase(space);
        PublicTarget target;
        if (!decode_fixed(token, target.key)) {
            error = item.second +
                ": target must be a 48-byte compressed BLS public key";
            return false;
        }
        const std::string identity(
            reinterpret_cast<const char*>(target.key.data()),
            target.key.size());
        const auto found = unique.find(identity);
        if (found == unique.end()) {
            target.origins.push_back(item.second);
            unique.emplace(identity, targets.size());
            targets.push_back(std::move(target));
        } else {
            targets[found->second].origins.push_back(item.second);
        }
        ++logical;
    }
    return !targets.empty();
}

bool parse_path(const std::string& raw,
                std::vector<std::uint32_t>& path,
                std::string& error) {
    if (raw.find('\'') != std::string::npos) {
        error = "EIP-2334 paths do not use apostrophe/hardened notation";
        return false;
    }
    std::stringstream input(raw);
    std::string token;
    if (!std::getline(input, token, '/') || token != "m") {
        error = "path must start with m/";
        return false;
    }
    while (std::getline(input, token, '/')) {
        std::uint64_t index = 0u;
        if (token.empty() || !parse_u64(token, index) ||
            index > std::numeric_limits<std::uint32_t>::max()) {
            error = "invalid EIP-2334 path component '" + token + "'";
            return false;
        }
        path.push_back(static_cast<std::uint32_t>(index));
    }
    if (path.size() < 4u || path.front() != 12381u) {
        error = "EIP-2334 path needs at least purpose/coin/account/use and purpose 12381";
        return false;
    }
    return true;
}

bool derive_path(const std::uint8_t* seed,
                 std::size_t seed_size,
                 const std::vector<std::uint32_t>& path,
                 bls12_381::SecretKey& secret,
                 std::string& error) {
    if (!bls12_381::eip2333_master(
            seed, seed_size, secret, error)) {
        return false;
    }
    for (const std::uint32_t index : path) {
        bls12_381::SecretKey child{};
        if (!bls12_381::eip2333_child(
                secret, index, child, error)) {
            bls12_381::clear_secret(secret);
            return false;
        }
        bls12_381::clear_secret(secret);
        secret = child;
    }
    return true;
}

std::uint64_t solved_public_logical(
    const std::vector<PublicTarget>& targets) {
    std::uint64_t solved = 0u;
    for (const PublicTarget& target : targets) {
        if (target.solved) solved += target.origins.size();
    }
    return solved;
}

std::uint64_t solved_keystore_logical(
    const std::vector<Target>& targets) {
    std::uint64_t solved = 0u;
    for (const Target& target : targets) {
        if (target.solved) solved += target.origins.size();
    }
    return solved;
}

std::string join_origins(const std::vector<std::string>& origins) {
    std::ostringstream output;
    for (std::size_t i = 0u; i < origins.size(); ++i) {
        if (i != 0u) output << ",";
        output << origins[i];
    }
    return output.str();
}

bool verify_seed(const std::uint8_t* seed,
                 std::size_t seed_size,
                 const std::string& source,
                 const std::vector<std::uint32_t>& path,
                 const std::string& path_text,
                 std::vector<PublicTarget>& targets,
                 std::string& line,
                 std::uint64_t& verifications,
                 std::string& error) {
    bls12_381::SecretKey secret{};
    if (!derive_path(seed, seed_size, path, secret, error)) {
        return false;
    }
    bls12_381::PublicKey public_key{};
    if (!bls12_381::public_key_compressed(
            secret, public_key, error)) {
        bls12_381::clear_secret(secret);
        return false;
    }
    ++verifications;
    for (PublicTarget& target : targets) {
        if (target.solved || target.key != public_key) continue;
        target.solved = true;
        std::ostringstream output;
        output << "mode=eth2validator source=" << source
               << " path=" << path_text
               << " seed=" << hex_string(seed, seed_size)
               << " secret=" << hex_string(
                    secret.data(), secret.size())
               << " pubkey=" << hex_string(
                    public_key.data(), public_key.size())
               << " target=" << join_origins(target.origins);
        line = output.str();
        break;
    }
    bls12_381::clear_secret(secret);
    return true;
}

std::string u256_decimal(modeinfra::U256 value) {
    if (value.is_zero()) return "0";
    std::string output;
    while (!value.is_zero()) {
        modeinfra::U256 quotient;
        std::uint64_t remainder = 0u;
        if (!modeinfra::divide(
                value, 10u, quotient, remainder)) {
            return {};
        }
        output.push_back(
            static_cast<char>('0' + remainder));
        value = quotient;
    }
    std::reverse(output.begin(), output.end());
    return output;
}

class PasswordStream {
public:
    bool initialize(const Options& options,
                    std::string& error) {
        options_ = &options;
        if (!options.mask.empty()) {
            kind_ = Kind::Mask;
            if (!parse_mask(options.mask, error) ||
                !domain_.reset(radices_, error)) {
                return false;
            }
            end_ = domain_.size();
            return true;
        }
        if (!options.start.empty()) {
            kind_ = Kind::Range;
            if (!modeinfra::parse_u256(
                    options.start, cursor_, error) ||
                !modeinfra::parse_u256(
                    options.end, end_, error) ||
                modeinfra::compare(cursor_, end_) >= 0) {
                if (error.empty()) {
                    error = "-start must be lower than -end";
                }
                return false;
            }
            return true;
        }
        kind_ = Kind::Inputs;
        if (options.candidate_inputs.empty()) {
            literals_.push_back("");
        }
        return true;
    }

    bool next(std::uint64_t maximum,
              std::vector<std::string>& output,
              std::string& error) {
        output.clear();
        if (kind_ == Kind::Mask) {
            while (output.size() < maximum &&
                   modeinfra::compare(cursor_, end_) < 0) {
                std::vector<std::uint64_t> digits;
                if (!domain_.decode(cursor_, digits, error)) {
                    return false;
                }
                std::string password;
                std::size_t digit = 0u;
                for (const MaskPart& part : parts_) {
                    password.push_back(
                        part.variable
                            ? part.alphabet[
                                static_cast<std::size_t>(
                                    digits[digit++])]
                            : part.literal);
                }
                output.push_back(std::move(password));
                modeinfra::U256 next;
                if (!modeinfra::add_checked(
                        cursor_, modeinfra::U256::from_u64(1u),
                        next)) {
                    error = "mask ordinal overflow";
                    return false;
                }
                cursor_ = next;
            }
            return true;
        }
        if (kind_ == Kind::Range) {
            while (output.size() < maximum &&
                   modeinfra::compare(cursor_, end_) < 0) {
                output.push_back(u256_decimal(cursor_));
                modeinfra::U256 next;
                if (!modeinfra::add_checked(
                        cursor_, modeinfra::U256::from_u64(1u),
                        next)) {
                    error = "numeric password ordinal overflow";
                    return false;
                }
                cursor_ = next;
            }
            return true;
        }
        while (output.size() < maximum) {
            if (!literals_.empty()) {
                output.push_back(std::move(literals_.front()));
                literals_.erase(literals_.begin());
                continue;
            }
            if (file_.is_open()) {
                std::string line;
                if (std::getline(file_, line)) {
                    if (!line.empty() && line.back() == '\r') {
                        line.pop_back();
                    }
                    output.push_back(std::move(line));
                    continue;
                }
                file_.close();
            }
            if (input_index_ >=
                options_->candidate_inputs.size()) {
                break;
            }
            const auto& item =
                options_->candidate_inputs[input_index_++];
            std::error_code filesystem_error;
            const bool is_file = item.second ||
                std::filesystem::is_regular_file(
                    item.first, filesystem_error);
            if (is_file) {
                file_.open(item.first);
                if (!file_) {
                    error = "cannot open password file '" +
                        item.first + "'";
                    return false;
                }
            } else {
                literals_.push_back(item.first);
            }
        }
        return true;
    }

private:
    enum class Kind { Inputs, Mask, Range };
    struct MaskPart {
        bool variable = false;
        char literal = 0;
        std::string alphabet;
    };
    bool parse_mask(const std::string& mask,
                    std::string& error) {
        for (std::size_t i = 0u; i < mask.size();) {
            if (mask[i] != '?') {
                parts_.push_back({false, mask[i], {}});
                ++i;
                continue;
            }
            if (i + 1u >= mask.size()) {
                error = "dangling '?' in -mask";
                return false;
            }
            const char code = mask[i + 1u];
            if (code == '?') {
                parts_.push_back({false, '?', {}});
            } else {
                std::string alphabet;
                if (code == 'd') alphabet = "0123456789";
                else if (code == 'l') alphabet = "abcdefghijklmnopqrstuvwxyz";
                else if (code == 'u') alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                else if (code == 'a') {
                    alphabet =
                        "0123456789abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                } else {
                    error = std::string(
                        "unsupported -mask token ?") + code;
                    return false;
                }
                parts_.push_back({true, 0, alphabet});
                radices_.push_back(alphabet.size());
            }
            i += 2u;
        }
        if (parts_.size() >= kPasswordStride) {
            error = "expanded mask exceeds 127 bytes";
            return false;
        }
        if (radices_.empty()) radices_.push_back(1u);
        return true;
    }
    Kind kind_ = Kind::Inputs;
    const Options* options_ = nullptr;
    std::size_t input_index_ = 0u;
    std::ifstream file_;
    std::vector<std::string> literals_;
    std::vector<MaskPart> parts_;
    std::vector<std::uint64_t> radices_;
    modeinfra::MixedRadixDomain domain_;
    modeinfra::U256 cursor_{};
    modeinfra::U256 end_{};
};

bool metal_ok(metalError_t status,
              const char* action,
              std::string& error) {
    if (status == metalSuccess) return true;
    error = std::string(action) + ": " +
        metalGetErrorString(status);
    return false;
}

template <typename T>
bool allocate_buffer(T*& pointer,
                     std::uint64_t bytes,
                     const char* action,
                     std::string& error) {
    return metal_ok(
        metalMalloc(
            reinterpret_cast<void**>(&pointer),
            static_cast<std::size_t>(
                std::max<std::uint64_t>(bytes, 1u))),
        action, error);
}

std::uint64_t align_up(std::uint64_t value,
                       std::uint64_t alignment) {
    const std::uint64_t remainder = value % alignment;
    return remainder == 0u
        ? value : value + alignment - remainder;
}

bool scrypt_stride(const GpuTarget& target,
                   std::uint64_t& stride) {
    if (target.kdf_type != kKdfScrypt) return true;
    const std::uint64_t block =
        128ull * target.scrypt_r;
    if (target.scrypt_n >
            std::numeric_limits<std::uint64_t>::max() / block ||
        target.scrypt_p >
            std::numeric_limits<std::uint64_t>::max() / block) {
        return false;
    }
    const std::uint64_t v =
        static_cast<std::uint64_t>(target.scrypt_n) * block;
    const std::uint64_t b =
        static_cast<std::uint64_t>(target.scrypt_p) * block;
    if (v > std::numeric_limits<std::uint64_t>::max() -
            b - 4u - block) {
        return false;
    }
    stride = std::max(
        stride, align_up(v + b + 4u + block, 256u));
    return true;
}

void release_buffers(DeviceBuffers& buffers) {
    if (buffers.device >= 0) (void)metalSetDevice(buffers.device);
    if (buffers.targets) metalFree(buffers.targets);
    if (buffers.solved) metalFree(buffers.solved);
    if (buffers.passwords) metalFree(buffers.passwords);
    if (buffers.lengths) metalFree(buffers.lengths);
    if (buffers.scratch) metalFree(buffers.scratch);
    if (buffers.hits) metalFree(buffers.hits);
    if (buffers.hit_count) metalFree(buffers.hit_count);
    buffers = {};
}

bool prepare_buffers(int device,
                     std::uint64_t capacity,
                     std::uint64_t stride,
                     const std::vector<Target>& targets,
                     DeviceBuffers& buffers,
                     std::string& error) {
    buffers.device = device;
    const std::uint64_t target_bytes =
        targets.size() * sizeof(GpuTarget);
    std::vector<GpuTarget> gpu_targets;
    gpu_targets.reserve(targets.size());
    for (const Target& target : targets) {
        gpu_targets.push_back(target.gpu);
    }
    if (!metal_ok(
            metalSetDevice(device),
            "select eth2validator device", error) ||
        !allocate_buffer(
            buffers.targets, target_bytes,
            "allocate eth2validator targets", error) ||
        !allocate_buffer(
            buffers.solved, targets.size(),
            "allocate eth2validator target flags", error) ||
        !allocate_buffer(
            buffers.passwords, capacity * kPasswordStride,
            "allocate eth2validator passwords", error) ||
        !allocate_buffer(
            buffers.lengths, capacity,
            "allocate eth2validator password lengths", error) ||
        !allocate_buffer(
            buffers.scratch,
            stride == 0u ? 1u : capacity * stride,
            "allocate eth2validator scrypt scratch", error) ||
        !allocate_buffer(
            buffers.hits,
            static_cast<std::uint64_t>(kHitCapacity) *
                sizeof(GpuHit),
            "allocate eth2validator hits", error) ||
        !allocate_buffer(
            buffers.hit_count, sizeof(std::uint32_t),
            "allocate eth2validator hit count", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.targets, gpu_targets.data(),
                static_cast<std::size_t>(target_bytes),
                metalMemcpyHostToDevice),
            "upload eth2validator targets", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.capacity = capacity;
    buffers.allocated =
        target_bytes + targets.size() +
        capacity * (kPasswordStride + 1u + stride) +
        static_cast<std::uint64_t>(kHitCapacity) *
            sizeof(GpuHit) + sizeof(std::uint32_t);
    return true;
}

std::uint32_t launch_grid(std::uint64_t count) {
    return static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) /
        kThreadgroupSize * kThreadgroupSize);
}

bool launch_password_batch(
    DeviceBuffers& buffers,
    const std::vector<Target>& targets,
    const std::vector<std::string>& passwords,
    std::size_t offset,
    std::size_t count,
    std::uint64_t candidate_base,
    std::uint64_t stride,
    std::vector<GpuHit>& hits,
    std::uint32_t& raw_count,
    std::uint64_t& readback_ns,
    std::string& error) {
    std::vector<char> packed(count * kPasswordStride, 0);
    std::vector<std::uint8_t> lengths(count, 0u);
    for (std::size_t i = 0u; i < count; ++i) {
        const std::string& password = passwords[offset + i];
        if (password.size() >= kPasswordStride) {
            error = "normalized password exceeds 127 UTF-8 bytes";
            return false;
        }
        lengths[i] =
            static_cast<std::uint8_t>(password.size());
        std::copy(
            password.begin(), password.end(),
            packed.begin() + i * kPasswordStride);
    }
    std::vector<std::uint8_t> solved(targets.size(), 0u);
    for (std::size_t i = 0u; i < targets.size(); ++i) {
        solved[i] = targets[i].solved ? 1u : 0u;
    }
    if (!metal_ok(
            metalSetDevice(buffers.device),
            "select eth2validator device", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.passwords, packed.data(), packed.size(),
                metalMemcpyHostToDevice),
            "upload eth2validator passwords", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.lengths, lengths.data(), lengths.size(),
                metalMemcpyHostToDevice),
            "upload eth2validator password lengths", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.solved, solved.data(), solved.size(),
                metalMemcpyHostToDevice),
            "upload eth2validator target flags", error)) {
        return false;
    }
    hits.clear();
    raw_count = 0u;
    const std::uint32_t total_targets =
        static_cast<std::uint32_t>(targets.size());
    for (std::uint32_t target_begin = 0u;
         target_begin < total_targets;) {
        const std::uint32_t target_end =
            target_begin +
            std::min<std::uint32_t>(
                kHitCapacity, total_targets - target_begin);
        const std::uint64_t target_window =
            static_cast<std::uint64_t>(target_begin) |
            (static_cast<std::uint64_t>(target_end) << 32u);
        if (!metal_ok(
                metalMemset(
                    buffers.hit_count, 0,
                    sizeof(std::uint32_t)),
                "reset eth2validator hit count", error) ||
            !metal_ok(
                metal_launch(
                    "workerEth2Validator",
                    launch_grid(count), kThreadgroupSize,
                    buffers.targets, target_window, buffers.solved,
                    buffers.passwords,
                    buffers.lengths, candidate_base,
                    static_cast<std::uint64_t>(count),
                    buffers.scratch, stride, buffers.hits,
                    buffers.hit_count, kHitCapacity),
                "launch eth2validator worker", error) ||
            !metal_ok(
                metalDeviceSynchronize(),
                "synchronize eth2validator worker", error)) {
            return false;
        }
        const auto read_start =
            std::chrono::steady_clock::now();
        std::uint32_t window_count = 0u;
        if (!metal_ok(
                metalMemcpy(
                    &window_count, buffers.hit_count,
                    sizeof(window_count),
                    metalMemcpyDeviceToHost),
                "read eth2validator hit count", error)) {
            return false;
        }
        readback_ns += static_cast<std::uint64_t>(
            std::chrono::duration_cast<
                std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() -
                read_start).count());
        raw_count = std::max(raw_count, window_count);
        if (window_count > kHitCapacity) {
            hits.clear();
            return true;
        }
        const std::size_t previous = hits.size();
        hits.resize(previous + window_count);
        if (window_count != 0u) {
            const auto hit_read_start =
                std::chrono::steady_clock::now();
            if (!metal_ok(
                    metalMemcpy(
                        hits.data() + previous, buffers.hits,
                        static_cast<std::size_t>(window_count) *
                            sizeof(GpuHit),
                        metalMemcpyDeviceToHost),
                    "read eth2validator hits", error)) {
                return false;
            }
            readback_ns += static_cast<std::uint64_t>(
                std::chrono::duration_cast<
                    std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() -
                    hit_read_start).count());
        }
        target_begin = target_end;
    }
    return true;
}

bool aes128_ctr(const std::uint8_t key[16],
                const std::uint8_t iv[16],
                const std::uint8_t* input,
                std::size_t size,
                std::uint8_t* output) {
    CCCryptorRef cryptor = nullptr;
    if (CCCryptorCreateWithMode(
            kCCDecrypt, kCCModeCTR, kCCAlgorithmAES,
            ccNoPadding, iv, key, 16u, nullptr, 0u, 0u,
            kCCModeOptionCTR_BE, &cryptor) != kCCSuccess) {
        return false;
    }
    std::size_t written = 0u;
    const CCCryptorStatus status = CCCryptorUpdate(
        cryptor, input, size, output, size, &written);
    CCCryptorRelease(cryptor);
    return status == kCCSuccess && written == size;
}

bool verify_keystore_hit(
    const GpuHit& hit,
    std::vector<Target>& targets,
    std::string& line,
    std::uint64_t& verifications,
    std::string& error) {
    if (hit.target_index >= targets.size() ||
        hit.password_len >= kPasswordStride) {
        error = "GPU returned an invalid hit index";
        return false;
    }
    Target& target = targets[hit.target_index];
    std::array<std::uint8_t, 48> preimage{};
    std::copy(
        hit.derived_key.begin() + 16u,
        hit.derived_key.end(), preimage.begin());
    std::copy(
        target.gpu.ciphertext.begin(),
        target.gpu.ciphertext.end(),
        preimage.begin() + 16u);
    std::array<std::uint8_t, 32> checksum{};
    sha256(preimage.data(), preimage.size(), checksum.data());
    if (checksum != target.gpu.checksum) return true;

    std::array<std::uint8_t, 32> secret{};
    if (!aes128_ctr(
            hit.derived_key.data(), target.gpu.iv.data(),
            target.gpu.ciphertext.data(),
            target.gpu.ciphertext.size(), secret.data())) {
        error = "host AES-128-CTR verification failed";
        return false;
    }
    if (secret != hit.secret ||
        !bls12_381::valid_secret_key(secret)) {
        return true;
    }
    bls12_381::PublicKey public_key{};
    if (!bls12_381::public_key_compressed(
            secret, public_key, error)) {
        return false;
    }
    ++verifications;
    if (public_key != target.gpu.public_key) return true;
    if (target.gpu.kdf_type == kKdfPbkdf2) {
        std::array<std::uint8_t, 32> host_key{};
        if (CCKeyDerivationPBKDF(
                kCCPBKDF2,
                reinterpret_cast<const char*>(
                    hit.password.data()),
                hit.password_len,
                target.gpu.salt.data(),
                target.gpu.salt_len,
                kCCPRFHmacAlgSHA256,
                target.gpu.iterations,
                host_key.data(), host_key.size()) !=
            kCCSuccess ||
            host_key != hit.derived_key) {
            return true;
        }
    }
    target.solved = true;
    std::ostringstream output;
    output << "mode=eth2validator source=" << target.source
           << " path=" << target.path
           << " candidate=" << hit.candidate_index
           << " password_hex="
           << hex_string(hit.password.data(), hit.password_len)
           << " secret="
           << hex_string(secret.data(), secret.size())
           << " pubkey="
           << hex_string(public_key.data(), public_key.size())
           << " target=" << join_origins(target.origins);
    line = output.str();
    bls12_381::clear_secret(secret);
    return true;
}

void release_mnemonic_buffers(MnemonicBuffers& buffers) {
    if (buffers.device >= 0) (void)metalSetDevice(buffers.device);
    if (buffers.mnemonics) metalFree(buffers.mnemonics);
    if (buffers.lengths) metalFree(buffers.lengths);
    if (buffers.salt) metalFree(buffers.salt);
    if (buffers.seeds) metalFree(buffers.seeds);
    buffers = {};
}

bool prepare_mnemonic_buffers(int device,
                              std::uint64_t capacity,
                              MnemonicBuffers& buffers,
                              std::string& error) {
    buffers.device = device;
    if (!metal_ok(
            metalSetDevice(device),
            "select eth2 mnemonic device", error) ||
        !allocate_buffer(
            buffers.mnemonics, capacity * kMnemonicStride,
            "allocate eth2 mnemonics", error) ||
        !allocate_buffer(
            buffers.lengths,
            capacity * sizeof(std::uint16_t),
            "allocate eth2 mnemonic lengths", error) ||
        !allocate_buffer(
            buffers.salt, kMnemonicStride,
            "allocate eth2 mnemonic salt", error) ||
        !allocate_buffer(
            buffers.seeds, capacity * 64u,
            "allocate eth2 mnemonic seeds", error)) {
        release_mnemonic_buffers(buffers);
        return false;
    }
    buffers.capacity = capacity;
    buffers.allocated =
        capacity * (kMnemonicStride +
                    sizeof(std::uint16_t) + 64u) +
        kMnemonicStride;
    return true;
}

bool launch_mnemonic_batch(
    MnemonicBuffers& buffers,
    const std::vector<std::pair<std::string, std::string>>& mnemonics,
    std::size_t offset,
    std::size_t count,
    const std::string& salt,
    std::vector<std::array<std::uint8_t, 64>>& seeds,
    std::uint64_t& readback_ns,
    std::string& error) {
    std::vector<char> packed(count * kMnemonicStride, 0);
    std::vector<std::uint16_t> lengths(count, 0u);
    for (std::size_t i = 0u; i < count; ++i) {
        const std::string& phrase = mnemonics[offset + i].first;
        lengths[i] =
            static_cast<std::uint16_t>(phrase.size());
        std::copy(
            phrase.begin(), phrase.end(),
            packed.begin() + i * kMnemonicStride);
    }
    const std::uint32_t salt_length =
        static_cast<std::uint32_t>(salt.size());
    if (!metal_ok(
            metalSetDevice(buffers.device),
            "select eth2 mnemonic device", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.mnemonics, packed.data(), packed.size(),
                metalMemcpyHostToDevice),
            "upload eth2 mnemonics", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.lengths, lengths.data(),
                lengths.size() * sizeof(std::uint16_t),
                metalMemcpyHostToDevice),
            "upload eth2 mnemonic lengths", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.salt, salt.data(), salt.size(),
                metalMemcpyHostToDevice),
            "upload eth2 mnemonic salt", error) ||
        !metal_ok(
            metal_launch(
                "workerEth2Mnemonic",
                launch_grid(count), kThreadgroupSize,
                buffers.mnemonics, buffers.lengths,
                static_cast<std::uint64_t>(count),
                buffers.salt, salt_length, buffers.seeds),
            "launch eth2 mnemonic worker", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize eth2 mnemonic worker", error)) {
        return false;
    }
    const auto read_start = std::chrono::steady_clock::now();
    seeds.resize(count);
    if (!metal_ok(
            metalMemcpy(
                seeds.data(), buffers.seeds,
                count * sizeof(seeds.front()),
                metalMemcpyDeviceToHost),
            "read eth2 mnemonic seeds", error)) {
        return false;
    }
    readback_ns += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() -
            read_start).count());
    return true;
}

bool open_output(const Options& options,
                 std::ofstream& output,
                 std::string& error) {
    if (!options.save && options.output_path.empty()) return true;
    const std::string path = options.output_path.empty()
        ? "result.txt" : options.output_path;
    output.open(path, std::ios::app);
    if (!output) {
        error = "cannot open output '" + path + "'";
        return false;
    }
    return true;
}

void emit_found(const Options& options,
                const RuntimeHooks& hooks,
                std::ofstream& output,
                const std::string& line,
                std::uint64_t& founds,
                modeinfra::ModeProgress& progress) {
    ++founds;
    if (hooks.credit_found) hooks.credit_found();
    progress.set_founds(founds);
    if (!options.silent) {
        std::cout << "[+] ETH2VALIDATOR_FOUND "
                  << line << "\n";
    }
    if (output) {
        output << line << "\n";
        output.flush();
    }
}

bool query_devices(const Options& options,
                   std::vector<modeinfra::MemoryDeviceInfo>& info,
                   std::string& error) {
    int count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&count),
            "query Metal devices", error)) {
        return false;
    }
    for (const int device : options.devices) {
        if (device < 0 || device >= count) {
            error = "unavailable Metal device " +
                std::to_string(device);
            return false;
        }
        metalDeviceProp properties{};
        if (!metal_ok(
                metalGetDeviceProperties(&properties, device),
                "query Metal device properties", error)) {
            return false;
        }
        info.push_back({
            properties.recommendedMaxWorkingSetSize,
            properties.currentAllocatedSize,
            properties.maxBufferLength,
            properties.hasUnifiedMemory != 0,
        });
    }
    return true;
}

int run_keystore(const Options& options,
                 const RuntimeHooks& hooks) {
    std::string error;
    std::vector<Target> targets;
    std::uint64_t logical_targets = 0u;
    if (!load_keystores(
            options, targets, logical_targets, error)) {
        std::cerr << "[!] eth2validator input error: "
                  << error << " [!]\n";
        return 2;
    }
    std::uint64_t stride = 0u;
    for (const Target& target : targets) {
        if (!scrypt_stride(target.gpu, stride)) {
            std::cerr << "[!] eth2validator input error: "
                         "scrypt scratch size overflow [!]\n";
            return 2;
        }
    }
    std::vector<modeinfra::MemoryDeviceInfo> device_info;
    if (!query_devices(options, device_info, error)) {
        std::cerr << "[!] eth2validator runtime error: "
                  << error << " [!]\n";
        return 1;
    }
    const std::uint64_t fixed =
        targets.size() * (sizeof(GpuTarget) + 1u) +
        static_cast<std::uint64_t>(kHitCapacity) *
            sizeof(GpuHit) + sizeof(std::uint32_t);
    const std::uint64_t per_candidate =
        kPasswordStride + 1u + stride;
    modeinfra::MemorySpec memory_spec;
    modeinfra::MemoryBudget budget;
    if (!modeinfra::parse_memory_spec(
            options.memory, memory_spec, error) ||
        !modeinfra::resolve_memory_budget(
            memory_spec, device_info,
            fixed + per_candidate, 0u, budget,
            error, kRuntimeReserve)) {
        std::cerr << "[!] eth2validator memory error: "
                  << error << " [!]\n";
        return 2;
    }
    std::uint64_t per_device_budget = budget.per_device_budget;
    if (!options.scrypt_memory.empty() && stride != 0u) {
        modeinfra::MemorySpec scratch_spec;
        modeinfra::MemoryBudget scratch_budget;
        if (!modeinfra::parse_memory_spec(
                options.scrypt_memory, scratch_spec, error) ||
            !modeinfra::resolve_memory_budget(
                scratch_spec, device_info, stride, 0u,
                scratch_budget, error, 0u)) {
            std::cerr << "[!] eth2validator scrypt memory error: "
                      << error << " [!]\n";
            return 2;
        }
        per_device_budget = std::min(
            per_device_budget,
            fixed + scratch_budget.per_device_budget);
    }
    if (per_device_budget <= fixed ||
        per_device_budget - fixed < per_candidate) {
        std::cerr << "[!] eth2validator memory error: selected "
                     "budget cannot hold one KDF lane [!]\n";
        return 1;
    }
    std::uint64_t capacity =
        (per_device_budget - fixed) / per_candidate;
    capacity = std::min(capacity, options.batch);
    if (stride != 0u) {
        capacity = std::min(
            capacity, budget.max_buffer_length / stride);
    }
    capacity = std::max<std::uint64_t>(1u, capacity);

    std::vector<DeviceBuffers> devices(options.devices.size());
    bool allocated = false;
    std::uint64_t resident = capacity;
    while (!allocated) {
        allocated = true;
        for (std::size_t i = 0u; i < devices.size(); ++i) {
            if (!prepare_buffers(
                    options.devices[i], resident, stride,
                    targets, devices[i], error)) {
                allocated = false;
                break;
            }
        }
        if (allocated) break;
        for (DeviceBuffers& device : devices) {
            release_buffers(device);
        }
        if (memory_spec.kind != modeinfra::MemoryKind::Auto ||
            resident == 1u) {
            std::cerr << "[!] eth2validator allocation error: "
                      << error << " [!]\n";
            return 1;
        }
        resident = std::max<std::uint64_t>(1u, resident / 2u);
    }
    std::uint64_t allocated_bytes = 0u;
    for (const DeviceBuffers& device : devices) {
        allocated_bytes += device.allocated;
    }

    std::ofstream output;
    if (!open_output(options, output, error)) {
        for (DeviceBuffers& device : devices) {
            release_buffers(device);
        }
        std::cerr << "[!] eth2validator output error: "
                  << error << " [!]\n";
        return 1;
    }
    std::cout << "[!] eth2validator EIP-2335: "
              << targets.size() << " unique/"
              << logical_targets << " logical keystores"
              << " | devices: " << devices.size()
              << " | resident/device: " << resident
              << " | scratch/lane: " << stride
              << " | working set: " << allocated_bytes
              << " bytes [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "ETH2VALIDATOR", modeinfra::ProgressUnit::Kdf,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(
        logical_targets, targets.size(), 0u);
    progress.set_allocated_working_set(allocated_bytes);

    PasswordStream stream;
    if (!stream.initialize(options, error)) {
        progress.end();
        for (DeviceBuffers& device : devices) {
            release_buffers(device);
        }
        std::cerr << "[!] eth2validator candidate error: "
                  << error << " [!]\n";
        return 2;
    }
    const std::uint64_t combined =
        resident * devices.size();
    std::uint64_t candidate_base = 0u;
    std::uint64_t founds = 0u;
    int status = 0;
    bool stop = false;
    while (!stop) {
        std::vector<std::string> raw;
        if (!stream.next(combined, raw, error)) {
            status = 2;
            break;
        }
        if (raw.empty()) break;
        std::vector<std::string> passwords;
        passwords.reserve(raw.size());
        for (const std::string& candidate : raw) {
            std::string normalized;
            if (!normalize_nfkd(
                    candidate, true, normalized, error) ||
                normalized.size() >= kPasswordStride) {
                status = 2;
                if (error.empty()) {
                    error = "normalized password exceeds 127 UTF-8 bytes";
                }
                stop = true;
                break;
            }
            passwords.push_back(std::move(normalized));
        }
        if (stop) break;
        std::size_t offset = 0u;
        while (offset < passwords.size() && !stop) {
            bool made_progress = false;
            for (DeviceBuffers& device : devices) {
                if (offset >= passwords.size() || stop) break;
                std::size_t count = std::min<std::size_t>(
                    device.capacity, passwords.size() - offset);
                for (;;) {
                    const std::uint64_t active_targets =
                        static_cast<std::uint64_t>(
                            std::count_if(
                                targets.begin(), targets.end(),
                                [](const Target& target) {
                                    return !target.solved;
                                }));
                    std::vector<GpuHit> hits;
                    std::uint32_t raw_count = 0u;
                    std::uint64_t readback_ns = 0u;
                    if (!launch_password_batch(
                            device, targets, passwords, offset,
                            count, candidate_base + offset,
                            stride, hits, raw_count, readback_ns,
                            error)) {
                        status = 1;
                        stop = true;
                        break;
                    }
                    if (raw_count > kHitCapacity) {
                        if (count == 1u) {
                            error = "hit buffer overflow at one candidate";
                            status = 1;
                            stop = true;
                            break;
                        }
                        count = std::max<std::size_t>(
                            1u, count / 2u);
                        continue;
                    }
                    std::uint64_t verifications = 0u;
                    for (const GpuHit& hit : hits) {
                        std::string line;
                        if (!verify_keystore_hit(
                                hit, targets, line,
                                verifications, error)) {
                            status = 1;
                            stop = true;
                            break;
                        }
                        if (!line.empty()) {
                            emit_found(
                                options, hooks, output, line,
                                founds, progress);
                        }
                    }
                    if (stop) break;
                    progress.credit_completed(
                        count,
                        count * std::max<std::uint64_t>(
                            1u, active_targets),
                        verifications, readback_ns);
                    if (hooks.credit_completed) {
                        hooks.credit_completed(count);
                    }
                    progress.set_targets(
                        logical_targets, targets.size(),
                        solved_keystore_logical(targets));
                    offset += count;
                    made_progress = true;
                    if (solved_keystore_logical(targets) >=
                        logical_targets) {
                        stop = true;
                    }
                    break;
                }
            }
            if (!made_progress && !stop) {
                error = "password scheduler made no progress";
                status = 1;
                stop = true;
            }
        }
        candidate_base += passwords.size();
    }
    progress.end();
    for (DeviceBuffers& device : devices) {
        release_buffers(device);
    }
    if (status != 0) {
        std::cerr << "[!] eth2validator "
                  << (status == 2 ? "candidate" : "runtime")
                  << " error: " << error << " [!]\n";
        return status;
    }
    std::cout << "[!] eth2validator search complete: found "
              << founds << " | solved "
              << solved_keystore_logical(targets)
              << "/" << logical_targets
              << " logical keystores [!]\n";
    return 0;
}

int run_derivation(const Options& options,
                   const RuntimeHooks& hooks) {
    std::string error;
    std::vector<std::pair<std::string, std::string>> mnemonics;
    std::vector<std::pair<std::vector<std::uint8_t>, std::string>> seeds;
    std::vector<PublicTarget> targets;
    std::uint64_t logical_targets = 0u;
    std::vector<std::uint32_t> path;
    if (!load_mnemonics(options, mnemonics, error) ||
        !load_seeds(options, seeds, error) ||
        !load_public_targets(
            options, targets, logical_targets, error) ||
        !parse_path(options.path, path, error)) {
        std::cerr << "[!] eth2validator input error: "
                  << error << " [!]\n";
        return 2;
    }
    std::string passphrase;
    if (!normalize_nfkd(
            options.mnemonic_passphrase, false,
            passphrase, error)) {
        std::cerr << "[!] eth2validator input error: "
                  << error << " [!]\n";
        return 2;
    }
    const std::string salt = "mnemonic" + passphrase;
    if (salt.size() >= kMnemonicStride) {
        std::cerr << "[!] eth2validator input error: normalized "
                     "mnemonic salt exceeds 255 bytes [!]\n";
        return 2;
    }
    std::vector<modeinfra::MemoryDeviceInfo> device_info;
    if (!query_devices(options, device_info, error)) {
        std::cerr << "[!] eth2validator runtime error: "
                  << error << " [!]\n";
        return 1;
    }
    modeinfra::MemorySpec memory_spec;
    modeinfra::MemoryBudget budget;
    const std::uint64_t per_candidate =
        kMnemonicStride + sizeof(std::uint16_t) + 64u;
    if (!modeinfra::parse_memory_spec(
            options.memory, memory_spec, error) ||
        !modeinfra::resolve_memory_budget(
            memory_spec, device_info, per_candidate,
            0u, budget, error, kRuntimeReserve)) {
        std::cerr << "[!] eth2validator memory error: "
                  << error << " [!]\n";
        return 2;
    }
    std::uint64_t capacity = std::min(
        options.batch,
        std::max<std::uint64_t>(
            1u, budget.per_device_budget / per_candidate));
    std::vector<MnemonicBuffers> devices(options.devices.size());
    for (std::size_t i = 0u; i < devices.size(); ++i) {
        if (!prepare_mnemonic_buffers(
                options.devices[i], capacity,
                devices[i], error)) {
            for (MnemonicBuffers& device : devices) {
                release_mnemonic_buffers(device);
            }
            std::cerr << "[!] eth2validator allocation error: "
                      << error << " [!]\n";
            return 1;
        }
    }
    std::uint64_t allocated = 0u;
    for (const MnemonicBuffers& device : devices) {
        allocated += device.allocated;
    }
    std::ofstream output;
    if (!open_output(options, output, error)) {
        for (MnemonicBuffers& device : devices) {
            release_mnemonic_buffers(device);
        }
        std::cerr << "[!] eth2validator output error: "
                  << error << " [!]\n";
        return 1;
    }
    std::cout << "[!] eth2validator EIP-2333/2334: "
              << mnemonics.size() << " mnemonic + "
              << seeds.size() << " raw seed candidates"
              << " | targets: " << targets.size()
              << " unique/" << logical_targets
              << " logical | path: " << options.path
              << " | devices: " << devices.size()
              << " | working set: " << allocated
              << " bytes [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "ETH2VALIDATOR", modeinfra::ProgressUnit::Kdf,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(
        logical_targets, targets.size(), 0u);
    progress.set_allocated_working_set(allocated);
    std::uint64_t founds = 0u;
    bool stop = false;

    std::size_t offset = 0u;
    while (offset < mnemonics.size() && !stop) {
        for (MnemonicBuffers& device : devices) {
            if (offset >= mnemonics.size() || stop) break;
            const std::size_t count =
                std::min<std::size_t>(
                    device.capacity,
                    mnemonics.size() - offset);
            std::vector<std::array<std::uint8_t, 64>> batch_seeds;
            std::uint64_t readback_ns = 0u;
            if (!launch_mnemonic_batch(
                    device, mnemonics, offset, count, salt,
                    batch_seeds, readback_ns, error)) {
                progress.end();
                for (MnemonicBuffers& item : devices) {
                    release_mnemonic_buffers(item);
                }
                std::cerr << "[!] eth2validator runtime error: "
                          << error << " [!]\n";
                return 1;
            }
            std::uint64_t verifications = 0u;
            for (std::size_t i = 0u; i < count; ++i) {
                std::string line;
                if (!verify_seed(
                        batch_seeds[i].data(),
                        batch_seeds[i].size(),
                        mnemonics[offset + i].second,
                        path, options.path, targets, line,
                        verifications, error)) {
                    progress.end();
                    for (MnemonicBuffers& item : devices) {
                        release_mnemonic_buffers(item);
                    }
                    std::cerr << "[!] eth2validator verification "
                                 "error: " << error << " [!]\n";
                    return 1;
                }
                if (!line.empty()) {
                    emit_found(
                        options, hooks, output, line,
                        founds, progress);
                }
            }
            progress.credit_completed(
                count, count, verifications, readback_ns);
            if (hooks.credit_completed) {
                hooks.credit_completed(count);
            }
            progress.set_targets(
                logical_targets, targets.size(),
                solved_public_logical(targets));
            offset += count;
            if (solved_public_logical(targets) >=
                logical_targets) {
                stop = true;
            }
        }
    }
    for (const auto& seed : seeds) {
        if (stop) break;
        std::uint64_t verifications = 0u;
        std::string line;
        if (!verify_seed(
                seed.first.data(), seed.first.size(),
                seed.second, path, options.path,
                targets, line, verifications, error)) {
            progress.end();
            for (MnemonicBuffers& item : devices) {
                release_mnemonic_buffers(item);
            }
            std::cerr << "[!] eth2validator verification error: "
                      << error << " [!]\n";
            return 1;
        }
        if (!line.empty()) {
            emit_found(
                options, hooks, output, line,
                founds, progress);
        }
        progress.credit_completed(1u, 1u, verifications, 0u);
        if (hooks.credit_completed) hooks.credit_completed(1u);
        progress.set_targets(
            logical_targets, targets.size(),
            solved_public_logical(targets));
        if (solved_public_logical(targets) >= logical_targets) {
            stop = true;
        }
    }
    progress.end();
    for (MnemonicBuffers& device : devices) {
        release_mnemonic_buffers(device);
    }
    std::cout << "[!] eth2validator derivation complete: found "
              << founds << " | solved "
              << solved_public_logical(targets)
              << "/" << logical_targets
              << " logical targets [!]\n";
    return 0;
}

}  // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-eth2validator") {
            return true;
        }
    }
    return false;
}

void print_help() {
    std::cout << R"HELP(
[!] ============== ETH2VALIDATOR MODE ==============
[!]
[!] -eth2validator FILE...          Recover EIP-2335 validator keystore passwords.
[!] -keystore FILE                 Repeatable explicit v4 EIP-2335 JSON file.
[!]
[!] Password candidates:
[!] -pass VALUE|FILE               Literal password or existing text file.
[!] -i FILE                        Streaming password dictionary; repeatable.
[!] -mask MASK                     ?d, ?l, ?u, ?a and ?? masks.
[!] -start N -end N                Decimal-string passwords in [START,END).
[!] Passwords are NFKD-normalized, C0/C1/DEL-stripped and UTF-8 encoded
[!] exactly as required by EIP-2335.
[!]
[!] Mnemonic / seed recovery:
[!] -mnemonic VALUE|FILE           English checksum-valid BIP39 phrase(s).
[!] -i FILE -target PUBKEY         In derivation form, -i is a mnemonic file.
[!] -seed HEX|FILE                 32..64-byte seed(s), repeatable.
[!] -target PUBKEY|FILE            48-byte compressed BLS key(s), repeatable.
[!] -path PATH                     EIP-2334 path; default m/12381/3600/0/0/0.
[!] -passphrase VALUE              Optional NFKD BIP39 passphrase.
[!]
[!] GPU / memory / MultiGPU:
[!] -wallet-mem auto|all|NN%|SIZE  Unified-memory working-set budget.
[!] -wallet-scrypt-mem SPEC        Optional stricter scrypt scratch limit.
[!] -n N                           Resident candidate window, 1..4096.
[!] -device LIST                   Metal devices, for example 0 or 0,1.
[!] auto uses at most 50% of free recommended working set; all leaves
[!] 512 MiB for runtime. EIP-2335 scrypt scratch is memory-derived.
[!]
[!] Statistics:
[!] The common SpeedThreadFunc is the only statistics writer. It reports
[!] KDF/s, primitive KDF work, exact BLS verifications, target state,
[!] allocated Metal working set and readback time after completed work.
[!]
[!] Output:
[!] -save                          Append independently verified hits.
[!] -o FILE                        Output path (also enables saving).
[!] -silent                        Suppress found lines on the console.
[!]
[!] Examples:
[!]   ./METAL_CRYPTO_TOOLKIT -eth2validator validator-keystore.json \
[!]     -i passwords.txt -wallet-mem auto -save
[!]   ./METAL_CRYPTO_TOOLKIT -eth2validator -keystore validator.json \
[!]     -mask "secret?d?d" -wallet-mem all
[!]   ./METAL_CRYPTO_TOOLKIT -eth2validator -i mnemonics.txt \
[!]     -target validator_pubkeys.txt -path m/12381/3600/0/0/0
[!]   ./METAL_CRYPTO_TOOLKIT -eth2validator -seed seed.hex \
[!]     -target PUBKEY -path m/12381/3600/0/0
[!]
[!] Limitations:
[!] EIP-2335 v4 supports PBKDF2-HMAC-SHA256 or scrypt (r <= 8),
[!] SHA-256 checksum, AES-128-CTR and 32-byte BLS secrets. Mnemonic
[!] recovery accepts checksum-valid English BIP39 candidates; it does not
[!] materialize unknown-word permutations. EIP-2334 apostrophes are invalid.
[!] Every GPU hit is rechecked by SHA-256, AES-CTR and the BLS public key
[!] on the host before output.
[!]
[!] Errors:
[!] CLI/input errors return 2; Metal/runtime errors return 1; an exhausted
[!] valid search returns 0 even when no candidate is found.
[!] ==================================================
[!] End of detailed help for -eth2validator [!]
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] eth2validator CLI error: "
                  << error << " [!]\n";
        return 2;
    }
    if (!options.keystores.empty()) {
        return run_keystore(options, hooks);
    }
    return run_derivation(options, hooks);
}

}  // namespace eth2validator_mode
