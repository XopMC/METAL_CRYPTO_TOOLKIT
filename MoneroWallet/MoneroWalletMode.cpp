#include "MoneroWalletMode.h"

#include "../MetalBackend.h"

extern "C" {
#include "../Monero/third_party/crypto-ops.h"
void chacha8(const void*, size_t, const std::uint8_t*,
             const std::uint8_t*, char*);
void chacha20(const void*, size_t, const std::uint8_t*,
              const std::uint8_t*, char*);
void hash_extra_blake(const void*, size_t, char*);
void hash_extra_groestl(const void*, size_t, char*);
void hash_extra_jh(const void*, size_t, char*);
void hash_extra_skein(const void*, size_t, char*);
}

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace monero_wallet_mode {
namespace {

constexpr std::uint32_t kThreadgroupSize = 32u;
constexpr std::uint32_t kPasswordStride = 128u;
constexpr std::uint64_t kScratchStride = 1ull << 21u;
constexpr std::uint32_t kMixIterations = 1u << 19u;
constexpr std::uint32_t kMixChunk = 1u << 13u;
constexpr std::uint64_t kRuntimeReserve = 512ull * 1024ull * 1024ull;

struct alignas(16) GpuCnState {
    std::array<std::uint8_t, 200> state{};
    std::uint64_t a0 = 0u;
    std::uint64_t a1 = 0u;
    std::uint64_t b0 = 0u;
    std::uint64_t b1 = 0u;
    std::uint32_t valid = 0u;
    std::array<std::uint32_t, 5> reserved{};
};

static_assert(sizeof(GpuCnState) == 256u);

struct Options {
    struct CandidateInput {
        std::string value;
        bool file_required = false;
    };

    std::vector<std::string> wallet_paths;
    std::vector<CandidateInput> candidate_inputs;
    std::vector<int> devices{0};
    std::string memory = "auto";
    std::string output_path;
    std::uint64_t kdf_rounds = 1u;
    std::uint64_t lanes = 0u;
    bool lanes_explicit = false;
    bool save = false;
    bool silent = false;
};

struct WalletArtifact {
    std::string source;
    std::array<std::uint8_t, 8> iv{};
    std::vector<std::uint8_t> ciphertext;
    bool solved = false;
};

struct AccountRecord {
    std::array<std::uint8_t, 32> spend_public{};
    std::array<std::uint8_t, 32> view_public{};
    std::array<std::uint8_t, 32> spend_secret{};
    std::array<std::uint8_t, 32> view_secret{};
    std::array<std::uint8_t, 8> encryption_iv{};
    bool encrypted_secret_keys = false;
    bool watch_only = false;
    bool legacy = false;
};

struct DeviceBuffers {
    int device = -1;
    std::uint8_t* passwords = nullptr;
    std::uint8_t* lengths = nullptr;
    std::uint8_t* scratch = nullptr;
    GpuCnState* states = nullptr;
    std::uint64_t capacity = 0u;
    std::uint64_t allocated = 0u;
};

std::string trim_copy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1u);
}

bool parse_u64(const std::string& raw, std::uint64_t& value) {
    const std::string text = trim_copy(raw);
    if (text.empty()) return false;
    std::size_t used = 0u;
    try {
        value = std::stoull(text, &used, 0);
    } catch (...) {
        return false;
    }
    return used == text.size();
}

bool parse_devices(const std::string& raw, std::vector<int>& devices,
                   std::string& error) {
    std::set<int> unique;
    std::stringstream input(raw);
    std::string token;
    while (std::getline(input, token, ',')) {
        std::uint64_t value = 0u;
        if (!parse_u64(token, value) ||
            value > static_cast<std::uint64_t>(
                std::numeric_limits<int>::max())) {
            error = "-device expects non-negative comma-separated indexes";
            return false;
        }
        unique.insert(static_cast<int>(value));
    }
    if (unique.empty()) {
        error = "-device selected no Metal device";
        return false;
    }
    devices.assign(unique.begin(), unique.end());
    return true;
}

bool parse_options(int argc, char** argv, Options& options,
                   std::string& error) {
    bool after_mode = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i] == nullptr ? "" : argv[i];
        auto require_value = [&](const char* name) -> const char* {
            if (i + 1 >= argc || argv[i + 1] == nullptr) {
                error = std::string(name) + " requires a value";
                return nullptr;
            }
            return argv[++i];
        };
        if (arg == "-monerowallet") {
            after_mode = true;
        } else if (arg == "-f") {
            const char* value = require_value("-f");
            if (!value) return false;
            options.wallet_paths.emplace_back(value);
        } else if (arg == "-pass" || arg == "-i") {
            const char* value = require_value(arg.c_str());
            if (!value) return false;
            options.candidate_inputs.push_back({
                value, arg == "-i"});
        } else if (arg == "-wallet-mem") {
            const char* value = require_value("-wallet-mem");
            if (!value) return false;
            options.memory = value;
        } else if (arg == "-monero-kdf-rounds") {
            const char* value = require_value("-monero-kdf-rounds");
            if (!value || !parse_u64(value, options.kdf_rounds) ||
                options.kdf_rounds == 0u ||
                options.kdf_rounds > 1024u) {
                error = "-monero-kdf-rounds expects 1..1024";
                return false;
            }
        } else if (arg == "-device") {
            const char* value = require_value("-device");
            if (!value ||
                !parse_devices(value, options.devices, error)) {
                return false;
            }
        } else if (arg == "-n") {
            const char* value = require_value("-n");
            if (!value || !parse_u64(value, options.lanes) ||
                options.lanes == 0u ||
                options.lanes > std::numeric_limits<std::uint32_t>::max()) {
                error = "-n expects a positive active-lane count";
                return false;
            }
            options.lanes_explicit = true;
        } else if (arg == "-o") {
            const char* value = require_value("-o");
            if (!value) return false;
            options.output_path = value;
        } else if (arg == "-save") {
            options.save = true;
        } else if (arg == "-silent") {
            options.silent = true;
        } else if (arg == "-help" || arg == "--help" ||
                   arg == "-h" || arg == "help") {
            continue;
        } else if (!arg.empty() && arg[0] != '-' && after_mode) {
            options.wallet_paths.push_back(arg);
        } else {
            error = "unsupported -monerowallet argument '" + arg + "'";
            return false;
        }
    }
    if (options.wallet_paths.empty()) {
        error = "-monerowallet requires at least one .keys file via -f";
        return false;
    }
    if (options.candidate_inputs.empty()) {
        error = "-monerowallet requires password candidates via -pass or -i";
        return false;
    }
    return true;
}

bool read_file(const std::string& path,
               std::vector<std::uint8_t>& bytes,
               std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "cannot open '" + path + "'";
        return false;
    }
    input.seekg(0, std::ios::end);
    const std::streamoff size = input.tellg();
    if (size < 0 || size > 64 * 1024 * 1024) {
        error = "unsupported .keys size for '" + path + "'";
        return false;
    }
    input.seekg(0, std::ios::beg);
    bytes.resize(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()), size);
    }
    if (!input) {
        error = "failed while reading '" + path + "'";
        return false;
    }
    return true;
}

bool read_leb128(const std::vector<std::uint8_t>& bytes,
                 std::size_t& offset, std::uint64_t& value) {
    value = 0u;
    unsigned shift = 0u;
    for (unsigned i = 0u; i < 10u && offset < bytes.size(); ++i) {
        const std::uint8_t byte = bytes[offset++];
        if (shift == 63u && (byte & 0xfeu) != 0u) return false;
        value |= static_cast<std::uint64_t>(byte & 0x7fu) << shift;
        if ((byte & 0x80u) == 0u) return true;
        shift += 7u;
    }
    return false;
}

bool load_wallets(const Options& options,
                  std::vector<WalletArtifact>& wallets,
                  std::string& error) {
    std::set<std::string> unique;
    for (const std::string& path : options.wallet_paths) {
        if (!unique.insert(path).second) continue;
        std::vector<std::uint8_t> bytes;
        if (!read_file(path, bytes, error)) return false;
        if (bytes.size() < 10u) {
            error = "'" + path + "' is too short for a Monero .keys file";
            return false;
        }
        WalletArtifact wallet;
        wallet.source = path;
        std::copy(bytes.begin(), bytes.begin() + 8u, wallet.iv.begin());
        std::size_t offset = 8u;
        std::uint64_t cipher_size = 0u;
        if (!read_leb128(bytes, offset, cipher_size) ||
            cipher_size == 0u ||
            cipher_size != bytes.size() - offset) {
            error = "'" + path +
                "' has an invalid Monero keys_file_data envelope";
            return false;
        }
        wallet.ciphertext.assign(bytes.begin() + offset, bytes.end());
        wallets.push_back(std::move(wallet));
    }
    return !wallets.empty();
}

struct PasswordSource {
    std::string value;
    bool is_file = false;
};

class PasswordStream {
public:
    bool prepare(const Options& options, std::string& error) {
        sources_.clear();
        total_ = 0u;
        for (const auto& input : options.candidate_inputs) {
            std::ifstream file(input.value, std::ios::binary);
            const bool is_file = static_cast<bool>(file);
            if (input.file_required && !is_file) {
                error = "cannot open password file '" + input.value + "'";
                return false;
            }
            if (!is_file) {
                if (input.value.size() >= kPasswordStride) {
                    error = "literal password exceeds 127 bytes";
                    return false;
                }
                if (total_ == std::numeric_limits<std::uint64_t>::max()) {
                    error = "password candidate count exceeds U64";
                    return false;
                }
                sources_.push_back({input.value, false});
                ++total_;
                continue;
            }
            std::string line;
            std::uint64_t line_number = 0u;
            while (std::getline(file, line)) {
                ++line_number;
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty() || line[0] == '#') continue;
                if (line.size() >= kPasswordStride) {
                    error = input.value + "#" +
                        std::to_string(line_number) +
                        ": password exceeds 127 bytes";
                    return false;
                }
                if (total_ == std::numeric_limits<std::uint64_t>::max()) {
                    error = "password candidate count exceeds U64";
                    return false;
                }
                ++total_;
            }
            if (!file.eof()) {
                error = "failed while reading password file '" +
                    input.value + "'";
                return false;
            }
            sources_.push_back({input.value, true});
        }
        if (total_ == 0u) {
            error = "no password candidates were loaded";
            return false;
        }
        return true;
    }

    std::uint64_t total() const { return total_; }

    bool next(std::size_t limit, std::vector<std::string>& batch,
              std::string& error) {
        batch.clear();
        while (batch.size() < limit && source_index_ < sources_.size()) {
            const PasswordSource& source = sources_[source_index_];
            if (!source.is_file) {
                batch.push_back(source.value);
                ++source_index_;
                continue;
            }
            if (!file_.is_open()) {
                file_.open(source.value, std::ios::binary);
                line_number_ = 0u;
                if (!file_) {
                    error = "cannot reopen password file '" +
                        source.value + "'";
                    return false;
                }
            }
            std::string line;
            while (batch.size() < limit && std::getline(file_, line)) {
                ++line_number_;
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty() || line[0] == '#') continue;
                if (line.size() >= kPasswordStride) {
                    error = source.value + "#" +
                        std::to_string(line_number_) +
                        ": password exceeds 127 bytes";
                    return false;
                }
                batch.push_back(std::move(line));
            }
            if (!file_.eof() && file_.fail()) {
                error = "failed while streaming password file '" +
                    source.value + "'";
                return false;
            }
            if (file_.eof()) {
                file_.close();
                file_.clear();
                ++source_index_;
            }
        }
        return true;
    }

private:
    std::vector<PasswordSource> sources_;
    std::ifstream file_;
    std::size_t source_index_ = 0u;
    std::uint64_t line_number_ = 0u;
    std::uint64_t total_ = 0u;
};

std::string hex_lower(const std::uint8_t* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t i = 0u; i < size; ++i) {
        output << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return output.str();
}

std::string quoted_password(const std::string& password) {
    std::ostringstream output;
    output << '"';
    for (const unsigned char ch : password) {
        if (ch == '\\' || ch == '"') output << '\\' << char(ch);
        else if (ch >= 0x20u && ch <= 0x7eu) output << char(ch);
        else {
            output << "\\x" << std::hex << std::setw(2)
                   << std::setfill('0') << unsigned(ch) << std::dec;
        }
    }
    output << '"';
    return output.str();
}

void final_extra_hash(const std::array<std::uint8_t, 200>& state,
                      std::array<std::uint8_t, 32>& hash) {
    switch (state[0] & 3u) {
    case 0u:
        hash_extra_blake(state.data(), state.size(),
                         reinterpret_cast<char*>(hash.data()));
        break;
    case 1u:
        hash_extra_groestl(state.data(), state.size(),
                           reinterpret_cast<char*>(hash.data()));
        break;
    case 2u:
        hash_extra_jh(state.data(), state.size(),
                      reinterpret_cast<char*>(hash.data()));
        break;
    default:
        hash_extra_skein(state.data(), state.size(),
                         reinterpret_cast<char*>(hash.data()));
        break;
    }
}

struct StorageNode {
    enum class Kind { Empty, String, Object } kind = Kind::Empty;
    std::vector<std::uint8_t> string;
    std::map<std::string, StorageNode> object;
};

class PortableReader {
public:
    PortableReader(const std::uint8_t* data, std::size_t size)
        : data_(data), size_(size) {}

    bool parse(StorageNode& root, std::string& error) {
        if (size_ < 9u ||
            load32(0u) != 0x01011101u ||
            load32(4u) != 0x01020101u ||
            data_[8] != 1u) {
            error = "portable-storage signature/version mismatch";
            return false;
        }
        offset_ = 9u;
        if (!parse_section(root, 0u, error)) return false;
        if (offset_ != size_) {
            error = "portable-storage has trailing bytes";
            return false;
        }
        return true;
    }

private:
    std::uint32_t load32(std::size_t offset) const {
        return std::uint32_t(data_[offset]) |
            (std::uint32_t(data_[offset + 1u]) << 8u) |
            (std::uint32_t(data_[offset + 2u]) << 16u) |
            (std::uint32_t(data_[offset + 3u]) << 24u);
    }

    bool take(std::size_t count, const std::uint8_t*& value) {
        if (count > size_ - offset_) return false;
        value = data_ + offset_;
        offset_ += count;
        return true;
    }

    bool portable_varint(std::uint64_t& value) {
        if (offset_ >= size_) return false;
        const unsigned selector = data_[offset_] & 3u;
        const std::size_t width = std::size_t(1u) << selector;
        const std::uint8_t* bytes = nullptr;
        if (!take(width, bytes)) return false;
        value = 0u;
        for (std::size_t i = 0u; i < width; ++i) {
            value |= std::uint64_t(bytes[i]) << (i * 8u);
        }
        value >>= 2u;
        return true;
    }

    bool parse_section(StorageNode& node, unsigned depth,
                       std::string& error) {
        if (depth > 32u) {
            error = "portable-storage recursion limit";
            return false;
        }
        std::uint64_t count = 0u;
        if (!portable_varint(count) || count > 4096u) {
            error = "portable-storage field count is invalid";
            return false;
        }
        node.kind = StorageNode::Kind::Object;
        for (std::uint64_t i = 0u; i < count; ++i) {
            const std::uint8_t* name_len = nullptr;
            if (!take(1u, name_len) || *name_len == 0u) {
                error = "portable-storage field name is invalid";
                return false;
            }
            const std::uint8_t* name_bytes = nullptr;
            if (!take(*name_len, name_bytes)) {
                error = "portable-storage field name is truncated";
                return false;
            }
            const std::string name(
                reinterpret_cast<const char*>(name_bytes), *name_len);
            if (node.object.count(name) != 0u) {
                error = "portable-storage duplicate field '" + name + "'";
                return false;
            }
            const std::uint8_t* type = nullptr;
            if (!take(1u, type)) {
                error = "portable-storage field type is truncated";
                return false;
            }
            StorageNode value;
            if (!parse_value(*type, value, depth + 1u, error)) return false;
            node.object.emplace(name, std::move(value));
        }
        return true;
    }

    bool skip_fixed(std::size_t width, std::string& error) {
        const std::uint8_t* ignored = nullptr;
        if (!take(width, ignored)) {
            error = "portable-storage scalar is truncated";
            return false;
        }
        return true;
    }

    bool parse_value(std::uint8_t type, StorageNode& node,
                     unsigned depth, std::string& error) {
        constexpr std::uint8_t array_flag = 0x80u;
        if ((type & array_flag) != 0u) {
            const std::uint8_t base = type & ~array_flag;
            std::uint64_t count = 0u;
            if (!portable_varint(count) || count > 1u << 20u) {
                error = "portable-storage array size is invalid";
                return false;
            }
            for (std::uint64_t i = 0u; i < count; ++i) {
                StorageNode ignored;
                if (!parse_value(base, ignored, depth + 1u, error)) {
                    return false;
                }
            }
            return true;
        }
        switch (type) {
        case 1u: case 5u: case 9u:
            return skip_fixed(8u, error);
        case 2u: case 6u:
            return skip_fixed(4u, error);
        case 3u: case 7u:
            return skip_fixed(2u, error);
        case 4u: case 8u: case 11u:
            return skip_fixed(1u, error);
        case 10u: {
            std::uint64_t length = 0u;
            if (!portable_varint(length) ||
                length > size_ - offset_) {
                error = "portable-storage string length is invalid";
                return false;
            }
            const std::uint8_t* bytes = nullptr;
            if (!take(static_cast<std::size_t>(length), bytes)) return false;
            node.kind = StorageNode::Kind::String;
            node.string.assign(bytes, bytes + length);
            return true;
        }
        case 12u:
            return parse_section(node, depth + 1u, error);
        case 13u: {
            const std::uint8_t* nested_type = nullptr;
            if (!take(1u, nested_type) ||
                (*nested_type & array_flag) == 0u) {
                error = "portable-storage nested array is invalid";
                return false;
            }
            return parse_value(*nested_type, node, depth + 1u, error);
        }
        default:
            error = "portable-storage unknown type " +
                std::to_string(type);
            return false;
        }
    }

    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0u;
    std::size_t offset_ = 0u;
};

const StorageNode* field(const StorageNode& node,
                         const std::string& name) {
    if (node.kind != StorageNode::Kind::Object) return nullptr;
    const auto found = node.object.find(name);
    return found == node.object.end() ? nullptr : &found->second;
}

bool copy_string_field(const StorageNode& node, const std::string& name,
                       std::uint8_t* output, std::size_t size) {
    const StorageNode* value = field(node, name);
    if (value == nullptr || value->kind != StorageNode::Kind::String ||
        value->string.size() != size) return false;
    std::copy(value->string.begin(), value->string.end(), output);
    return true;
}

bool parse_account(const std::vector<std::uint8_t>& bytes,
                   AccountRecord& account, std::string& error) {
    StorageNode root;
    PortableReader reader(bytes.data(), bytes.size());
    if (!reader.parse(root, error)) return false;
    const StorageNode* keys = field(root, "m_keys");
    const StorageNode* address =
        keys == nullptr ? nullptr : field(*keys, "m_account_address");
    if (keys == nullptr || address == nullptr ||
        !copy_string_field(
            *address, "m_spend_public_key",
            account.spend_public.data(), account.spend_public.size()) ||
        !copy_string_field(
            *address, "m_view_public_key",
            account.view_public.data(), account.view_public.size()) ||
        !copy_string_field(
            *keys, "m_spend_secret_key",
            account.spend_secret.data(), account.spend_secret.size()) ||
        !copy_string_field(
            *keys, "m_view_secret_key",
            account.view_secret.data(), account.view_secret.size())) {
        error = "portable account is missing exact spend/view key fields";
        return false;
    }
    const StorageNode* encryption_iv = field(*keys, "m_encryption_iv");
    if (encryption_iv != nullptr) {
        if (encryption_iv->kind != StorageNode::Kind::String ||
            encryption_iv->string.size() != account.encryption_iv.size()) {
            error = "portable account has an invalid key-encryption IV";
            return false;
        }
        std::copy(
            encryption_iv->string.begin(), encryption_iv->string.end(),
            account.encryption_iv.begin());
    }
    return true;
}

bool json_unescape_string(const std::string& json, std::size_t start,
                          std::vector<std::uint8_t>& value,
                          std::size_t& end, std::string& error) {
    if (start >= json.size() || json[start] != '"') return false;
    value.clear();
    for (std::size_t i = start + 1u; i < json.size(); ++i) {
        const unsigned char ch = json[i];
        if (ch == '"') {
            end = i + 1u;
            return true;
        }
        if (ch != '\\') {
            value.push_back(ch);
            continue;
        }
        if (++i >= json.size()) break;
        const char escaped = json[i];
        switch (escaped) {
        case '"': case '\\': case '/':
            value.push_back(static_cast<std::uint8_t>(escaped));
            break;
        case 'b': value.push_back('\b'); break;
        case 'f': value.push_back('\f'); break;
        case 'n': value.push_back('\n'); break;
        case 'r': value.push_back('\r'); break;
        case 't': value.push_back('\t'); break;
        case 'u': {
            if (i + 4u >= json.size()) {
                error = "key_data contains a truncated JSON escape";
                return false;
            }
            unsigned code = 0u;
            bool valid = true;
            for (unsigned j = 0u; j < 4u; ++j) {
                const char digit = json[++i];
                unsigned nibble = 0u;
                if (digit >= '0' && digit <= '9') nibble = digit - '0';
                else if (digit >= 'a' && digit <= 'f')
                    nibble = digit - 'a' + 10u;
                else if (digit >= 'A' && digit <= 'F')
                    nibble = digit - 'A' + 10u;
                else valid = false;
                code = (code << 4u) | nibble;
            }
            if (!valid || code > 0xffu) {
                error = "key_data contains a non-byte JSON escape";
                return false;
            }
            value.push_back(static_cast<std::uint8_t>(code));
            break;
        }
        default:
            error = "key_data contains an invalid JSON escape";
            return false;
        }
    }
    error = "unterminated JSON key_data string";
    return false;
}

bool json_integer(const std::string& json, const std::string& key,
                  std::uint64_t default_value, std::uint64_t& value) {
    const std::string marker = "\"" + key + "\"";
    const auto found = json.find(marker);
    if (found == std::string::npos) {
        value = default_value;
        return true;
    }
    const auto colon = json.find(':', found + marker.size());
    if (colon == std::string::npos) return false;
    std::size_t begin = colon + 1u;
    while (begin < json.size() &&
           std::isspace(static_cast<unsigned char>(json[begin]))) ++begin;
    std::size_t end = begin;
    while (end < json.size() &&
           std::isdigit(static_cast<unsigned char>(json[end]))) ++end;
    if (end == begin) return false;
    return parse_u64(json.substr(begin, end - begin), value);
}

bool parse_modern_json(const std::vector<std::uint8_t>& plain,
                       AccountRecord& account, std::string& error) {
    const std::string json(
        reinterpret_cast<const char*>(plain.data()), plain.size());
    const auto first = json.find_first_not_of(" \t\r\n");
    const auto last = json.find_last_not_of(" \t\r\n");
    if (first == std::string::npos || json[first] != '{' ||
        last == std::string::npos || json[last] != '}') {
        return false;
    }
    const std::string marker = "\"key_data\"";
    const auto key = json.find(marker);
    if (key == std::string::npos) return false;
    const auto colon = json.find(':', key + marker.size());
    if (colon == std::string::npos) return false;
    const auto quote = json.find('"', colon + 1u);
    if (quote == std::string::npos) return false;
    std::vector<std::uint8_t> account_data;
    std::size_t ignored_end = 0u;
    if (!json_unescape_string(
            json, quote, account_data, ignored_end, error)) {
        return false;
    }
    std::uint64_t encrypted = 0u;
    std::uint64_t watch_only = 0u;
    if (!json_integer(json, "encrypted_secret_keys", 0u, encrypted) ||
        !json_integer(json, "watch_only", 0u, watch_only) ||
        encrypted > 1u || watch_only > 1u) {
        error = "Monero wallet JSON has invalid version flags";
        return false;
    }
    if (!parse_account(account_data, account, error)) return false;
    account.encrypted_secret_keys = encrypted != 0u;
    account.watch_only = watch_only != 0u;
    account.legacy = false;
    return true;
}

bool scalar_matches_public(
    const std::array<std::uint8_t, 32>& secret,
    const std::array<std::uint8_t, 32>& expected) {
    if (std::all_of(
            secret.begin(), secret.end(),
            [](std::uint8_t byte) { return byte == 0u; })) {
        return false;
    }
    if (sc_check(secret.data()) != 0) return false;
    ge_p3 point{};
    std::array<std::uint8_t, 32> actual{};
    ge_scalarmult_base(&point, secret.data());
    ge_p3_tobytes(actual.data(), &point);
    return actual == expected;
}

bool verify_account(const AccountRecord& account) {
    if (!scalar_matches_public(
            account.view_secret, account.view_public)) {
        return false;
    }
    if (account.watch_only) {
        return std::all_of(
            account.spend_secret.begin(), account.spend_secret.end(),
            [](std::uint8_t byte) { return byte == 0u; });
    }
    return scalar_matches_public(
        account.spend_secret, account.spend_public);
}

bool decrypt_outer(const WalletArtifact& wallet,
                   const std::array<std::uint8_t, 32>& key,
                   AccountRecord& account, std::string& error) {
    std::vector<std::uint8_t> plain(wallet.ciphertext.size());
    chacha20(
        wallet.ciphertext.data(), wallet.ciphertext.size(),
        key.data(), wallet.iv.data(),
        reinterpret_cast<char*>(plain.data()));
    std::string modern_error;
    if (parse_modern_json(plain, account, modern_error)) return true;

    chacha8(
        wallet.ciphertext.data(), wallet.ciphertext.size(),
        key.data(), wallet.iv.data(),
        reinterpret_cast<char*>(plain.data()));
    if (parse_account(plain, account, error)) {
        account.legacy = true;
        account.encrypted_secret_keys = false;
        account.watch_only = std::all_of(
            account.spend_secret.begin(), account.spend_secret.end(),
            [](std::uint8_t byte) { return byte == 0u; });
        return true;
    }
    error = "password did not produce modern JSON or legacy account data";
    return false;
}

void decrypt_secret_keys(
    AccountRecord& account,
    const std::array<std::uint8_t, 32>& memory_key) {
    std::array<std::uint8_t, 64> zero{};
    std::array<std::uint8_t, 64> stream{};
    chacha20(
        zero.data(), zero.size(), memory_key.data(),
        account.encryption_iv.data(),
        reinterpret_cast<char*>(stream.data()));
    for (std::size_t i = 0u; i < 32u; ++i) {
        account.spend_secret[i] ^= stream[i];
        account.view_secret[i] ^= stream[32u + i];
    }
    account.encrypted_secret_keys = false;
}

bool metal_ok(metalError_t status, const char* action,
              std::string& error) {
    if (status == metalSuccess) return true;
    error = std::string(action) + ": " + metalGetErrorString(status);
    return false;
}

template <typename T>
bool allocate(T*& pointer, std::size_t bytes,
              const char* action, std::string& error) {
    return metal_ok(
        metalMalloc(
            reinterpret_cast<void**>(&pointer),
            std::max<std::size_t>(bytes, 1u)),
        action, error);
}

void release_buffers(DeviceBuffers& buffers) {
    if (buffers.device >= 0) (void)metalSetDevice(buffers.device);
    if (buffers.passwords) metalFree(buffers.passwords);
    if (buffers.lengths) metalFree(buffers.lengths);
    if (buffers.scratch) metalFree(buffers.scratch);
    if (buffers.states) metalFree(buffers.states);
    buffers = {};
}

bool prepare_buffers(int device, std::uint64_t capacity,
                     DeviceBuffers& buffers, std::string& error) {
    buffers.device = device;
    if (!metal_ok(
            metalSetDevice(device), "select Monero wallet device", error) ||
        !allocate(
            buffers.passwords,
            static_cast<std::size_t>(capacity) * kPasswordStride,
            "allocate Monero wallet passwords", error) ||
        !allocate(
            buffers.lengths, static_cast<std::size_t>(capacity),
            "allocate Monero wallet password lengths", error) ||
        !allocate(
            buffers.scratch,
            static_cast<std::size_t>(capacity * kScratchStride),
            "allocate Monero wallet CryptoNight scratch", error) ||
        !allocate(
            buffers.states,
            static_cast<std::size_t>(capacity) * sizeof(GpuCnState),
            "allocate Monero wallet CryptoNight states", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.capacity = capacity;
    buffers.allocated =
        capacity * (kPasswordStride + 1u + kScratchStride +
                    sizeof(GpuCnState));
    return true;
}

bool run_cn_round(DeviceBuffers& buffers,
                  const std::vector<std::string>& inputs,
                  std::vector<std::array<std::uint8_t, 32>>& hashes,
                  std::uint64_t& readback_ns,
                  std::string& error) {
    if (inputs.empty() || inputs.size() > buffers.capacity) {
        error = "invalid CryptoNight input batch";
        return false;
    }
    std::vector<std::uint8_t> password_bytes(
        inputs.size() * kPasswordStride, 0u);
    std::vector<std::uint8_t> lengths(inputs.size(), 0u);
    for (std::size_t i = 0u; i < inputs.size(); ++i) {
        if (inputs[i].size() >= kPasswordStride) {
            error = "CryptoNight input exceeds 127 bytes";
            return false;
        }
        lengths[i] = static_cast<std::uint8_t>(inputs[i].size());
        std::copy(
            inputs[i].begin(), inputs[i].end(),
            password_bytes.begin() + i * kPasswordStride);
    }
    const std::uint64_t count = inputs.size();
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) / kThreadgroupSize *
        kThreadgroupSize);
    if (!metal_ok(
            metalSetDevice(buffers.device),
            "select Monero wallet device", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.passwords, password_bytes.data(),
                password_bytes.size(), metalMemcpyHostToDevice),
            "upload Monero wallet passwords", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.lengths, lengths.data(), lengths.size(),
                metalMemcpyHostToDevice),
            "upload Monero wallet lengths", error) ||
        !metal_ok(
            metal_launch(
                "workerMoneroWalletCnInit", grid, kThreadgroupSize,
                buffers.passwords, buffers.lengths, count,
                buffers.scratch, buffers.states),
            "launch CryptoNight init", error)) {
        return false;
    }
    for (std::uint32_t offset = 0u; offset < kMixIterations;
         offset += kMixChunk) {
        const std::uint32_t iterations =
            std::min(kMixChunk, kMixIterations - offset);
        if (!metal_ok(
                metal_launch(
                    "workerMoneroWalletCnMix", grid, kThreadgroupSize,
                    count, iterations, buffers.scratch, buffers.states),
                "launch CryptoNight mix", error)) {
            return false;
        }
    }
    if (!metal_ok(
            metal_launch(
                "workerMoneroWalletCnFinal", grid, kThreadgroupSize,
                count, buffers.scratch, buffers.states),
            "launch CryptoNight final", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize CryptoNight pipeline", error)) {
        return false;
    }
    const auto started = std::chrono::steady_clock::now();
    std::vector<GpuCnState> states(inputs.size());
    if (!metal_ok(
            metalMemcpy(
                states.data(), buffers.states,
                states.size() * sizeof(GpuCnState),
                metalMemcpyDeviceToHost),
            "read CryptoNight states", error)) {
        return false;
    }
    readback_ns += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started).count());
    hashes.resize(inputs.size());
    for (std::size_t i = 0u; i < states.size(); ++i) {
        if (states[i].valid == 0u) {
            error = "CryptoNight pipeline rejected a valid input";
            return false;
        }
        final_extra_hash(states[i].state, hashes[i]);
    }
    return true;
}

bool run_kdf(DeviceBuffers& buffers,
             const std::vector<std::string>& passwords,
             std::uint64_t rounds,
             std::vector<std::array<std::uint8_t, 32>>& keys,
             std::uint64_t& readback_ns,
             std::string& error) {
    std::vector<std::string> inputs = passwords;
    for (std::uint64_t round = 0u; round < rounds; ++round) {
        if (!run_cn_round(
                buffers, inputs, keys, readback_ns, error)) {
            return false;
        }
        if (round + 1u != rounds) {
            inputs.clear();
            inputs.reserve(keys.size());
            for (const auto& key : keys) {
                inputs.emplace_back(
                    reinterpret_cast<const char*>(key.data()), key.size());
            }
        }
    }
    return true;
}

std::uint64_t saturating_add(std::uint64_t left,
                             std::uint64_t right) {
    return std::numeric_limits<std::uint64_t>::max() - left < right
        ? std::numeric_limits<std::uint64_t>::max()
        : left + right;
}

} // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr &&
            std::strcmp(argv[i], "-monerowallet") == 0) {
            return true;
        }
    }
    return false;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -monerowallet  (Monero .keys password recovery)
[!] ======================================================================
[!] Purpose:
[!] Test password candidates against official Monero .keys containers with
[!] the exact CryptoNight-v0 password KDF on Metal. Modern ChaCha20/JSON and
[!] legacy ChaCha8 account formats are detected independently. Every result
[!] is confirmed by parsing the full account and recomputing spend/view
[!] Ed25519 public keys before output.
[!]
[!] Required inputs:
[!] -f WALLET.keys          Repeatable Monero .keys artifact.
[!] WALLET.keys             Existing positional .keys paths are also accepted.
[!] -pass VALUE|FILE        Repeatable literal password or password file.
[!] -i FILE                 Additional password file.
[!]
[!] Optional arguments:
[!] -monero-kdf-rounds N    Wallet KDF rounds; default 1. This setting is not
[!]                         stored inside .keys and must match wallet creation.
[!] -wallet-mem auto|all|NN%|SIZE
[!]                         Hard unified-memory ceiling; number means MiB.
[!] -n N                    Exact active CryptoNight lanes (2 MiB each).
[!] -device LIST            Metal indexes, for example 0 or 0,1.
[!] -o FILE                 Append verified results.
[!] -save                   Use MONEROWALLET_FOUND.txt by default.
[!] -silent                 Suppress found-result lines on stdout.
[!]
[!] GPU / memory / MultiGPU:
[!] CryptoNight is a staged init/mix/final Metal pipeline with one 2 MiB
[!] scratchpad per active password. auto uses at most half the currently free
[!] recommended working set; all uses the remainder minus 512 MiB. Allocation
[!] failure reduces automatic concurrency, while explicit -n is strict.
[!] Candidate windows are assigned without overlap across selected devices.
[!]
[!] Statistics:
[!] SpeedThreadFunc is the only live statistics printer and reports KDF/s.
[!] Work is credited only after the Metal pipeline and readback complete.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -monerowallet -f wallet.keys \
[!]   -pass passwords.txt -wallet-mem auto -save
[!] ./METAL_CRYPTO_TOOLKIT -monerowallet wallet.keys \
[!]   -pass "correct horse battery staple" -wallet-mem all -device 0
[!] ./METAL_CRYPTO_TOOLKIT -help -monerowallet
[!]
[!] Limitations:
[!] Passwords are limited to 127 bytes. Standard modern and legacy software
[!] wallets are supported; hardware-device and custom-background-password
[!] containers are rejected rather than guessed. Full search spaces remain
[!] computationally expensive. CLI errors return 2, runtime failures return 1,
[!] and a completed search returns 0 even when no password is found.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] Monero wallet CLI error: " << error << " [!]\n";
        return 2;
    }
    std::vector<WalletArtifact> wallets;
    PasswordStream passwords;
    if (!load_wallets(options, wallets, error)) {
        std::cerr << "[!] Monero wallet artifact error: "
                  << error << " [!]\n";
        return 2;
    }
    if (!passwords.prepare(options, error)) {
        std::cerr << "[!] Monero wallet password error: "
                  << error << " [!]\n";
        return 2;
    }

    int device_count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&device_count),
            "query Metal devices", error)) {
        std::cerr << "[!] Monero wallet runtime error: "
                  << error << " [!]\n";
        return 1;
    }
    std::vector<modeinfra::MemoryDeviceInfo> device_info;
    for (const int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] Monero wallet CLI error: unavailable device "
                      << device << " [!]\n";
            return 2;
        }
        metalDeviceProp properties{};
        if (!metal_ok(
                metalGetDeviceProperties(&properties, device),
                "query Metal device properties", error)) {
            std::cerr << "[!] Monero wallet runtime error: "
                      << error << " [!]\n";
            return 1;
        }
        device_info.push_back({
            properties.recommendedMaxWorkingSetSize,
            properties.currentAllocatedSize,
            properties.maxBufferLength,
            properties.hasUnifiedMemory != 0,
        });
    }
    modeinfra::MemorySpec memory_spec;
    modeinfra::MemoryBudget budget;
    if (!modeinfra::parse_memory_spec(
            options.memory, memory_spec, error) ||
        !modeinfra::resolve_memory_budget(
            memory_spec, device_info,
            kScratchStride + sizeof(GpuCnState) +
                kPasswordStride + 1u,
            0u, budget, error, kRuntimeReserve)) {
        std::cerr << "[!] Monero wallet memory error: "
                  << error << " [!]\n";
        return 2;
    }
    const std::uint64_t bytes_per_lane =
        kScratchStride + sizeof(GpuCnState) + kPasswordStride + 1u;
    std::uint64_t capacity = std::min<std::uint64_t>({
        budget.per_device_budget / bytes_per_lane,
        budget.max_buffer_length / kScratchStride,
        std::numeric_limits<std::uint32_t>::max(),
    });
    if (options.lanes_explicit) {
        if (options.lanes > capacity) {
            std::cerr << "[!] Monero wallet memory error: explicit -n "
                      << options.lanes << " lanes require "
                      << options.lanes * bytes_per_lane
                      << " bytes per device, above the selected budget [!]\n";
            return 2;
        }
        capacity = options.lanes;
    } else {
        capacity = std::min<std::uint64_t>(
            capacity, std::max<std::uint64_t>(
                1u, std::min<std::uint64_t>(passwords.total(), 4096u)));
    }
    if (capacity == 0u) {
        std::cerr << "[!] Monero wallet memory error: one CryptoNight "
                     "lane does not fit [!]\n";
        return 2;
    }

    std::vector<DeviceBuffers> devices;
    for (const int device : options.devices) {
        DeviceBuffers buffers;
        std::uint64_t attempt = capacity;
        while (attempt != 0u &&
               !prepare_buffers(device, attempt, buffers, error)) {
            if (options.lanes_explicit) break;
            attempt /= 2u;
        }
        if (buffers.capacity == 0u) {
            for (auto& item : devices) release_buffers(item);
            std::cerr << "[!] Monero wallet allocation error: "
                      << error << " [!]\n";
            return options.lanes_explicit ? 2 : 1;
        }
        capacity = std::min(capacity, buffers.capacity);
        devices.push_back(std::move(buffers));
    }
    std::uint64_t allocated = 0u;
    for (const auto& device : devices) {
        allocated = saturating_add(allocated, device.allocated);
    }

    std::ofstream output;
    if (options.save || !options.output_path.empty()) {
        const std::string path = options.output_path.empty()
            ? "MONEROWALLET_FOUND.txt" : options.output_path;
        output.open(path, std::ios::app);
        if (!output) {
            for (auto& device : devices) release_buffers(device);
            std::cerr << "[!] Monero wallet runtime error: cannot open '"
                      << path << "' [!]\n";
            return 1;
        }
    }

    std::cout << "[!] Monero wallets: " << wallets.size()
              << " | password candidates: " << passwords.total()
              << " | KDF rounds: " << options.kdf_rounds
              << " | lanes/device: " << capacity
              << " | working set: " << allocated << " bytes [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "MONEROWALLET", modeinfra::ProgressUnit::Kdf,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(wallets.size(), wallets.size(), 0u);
    progress.set_allocated_working_set(allocated);

    std::uint64_t founds = 0u;
    std::uint64_t solved = 0u;
    std::size_t device_slot = 0u;
    int result = 0;
    std::vector<std::string> batch;
    while (solved < wallets.size()) {
        if (!passwords.next(
                static_cast<std::size_t>(capacity),
                batch, error)) {
            result = 1;
            break;
        }
        if (batch.empty()) break;
        const std::size_t count = batch.size();
        DeviceBuffers& device = devices[device_slot];
        std::vector<std::array<std::uint8_t, 32>> keys;
        std::uint64_t readback_ns = 0u;
        if (!run_kdf(
                device, batch, options.kdf_rounds,
                keys, readback_ns, error)) {
            result = 1;
            break;
        }
        std::uint64_t exact = 0u;
        for (std::size_t candidate = 0u;
             candidate < batch.size(); ++candidate) {
            for (WalletArtifact& wallet : wallets) {
                if (wallet.solved) continue;
                AccountRecord account;
                std::string candidate_error;
                if (!decrypt_outer(
                        wallet, keys[candidate],
                        account, candidate_error)) {
                    continue;
                }
                ++exact;
                if (account.encrypted_secret_keys) {
                    std::string material(
                        reinterpret_cast<const char*>(
                            keys[candidate].data()),
                        keys[candidate].size());
                    material.push_back('k');
                    std::vector<std::array<std::uint8_t, 32>> memory_keys;
                    std::uint64_t extra_readback = 0u;
                    if (!run_kdf(
                            device, {material}, 1u, memory_keys,
                            extra_readback, error)) {
                        result = 1;
                        break;
                    }
                    readback_ns =
                        saturating_add(readback_ns, extra_readback);
                    decrypt_secret_keys(account, memory_keys.front());
                }
                if (!verify_account(account)) continue;

                wallet.solved = true;
                ++solved;
                ++founds;
                if (hooks.increment_found) hooks.increment_found();
                const std::string profile =
                    account.legacy
                    ? "monero-keys-v0-chacha8"
                    : "monero-keys-json-chacha20";
                const std::string line =
                    "[+] MONEROWALLET_FOUND SOURCE:" + wallet.source +
                    " PASSWORD:" + quoted_password(batch[candidate]) +
                    " PASSWORD_HEX:" +
                    hex_lower(
                        reinterpret_cast<const std::uint8_t*>(
                            batch[candidate].data()),
                        batch[candidate].size()) +
                    " SPEND_PRIVATE:" +
                    hex_lower(
                        account.spend_secret.data(),
                        account.spend_secret.size()) +
                    " VIEW_PRIVATE:" +
                    hex_lower(
                        account.view_secret.data(),
                        account.view_secret.size()) +
                    " SPEND_PUBLIC:" +
                    hex_lower(
                        account.spend_public.data(),
                        account.spend_public.size()) +
                    " VIEW_PUBLIC:" +
                    hex_lower(
                        account.view_public.data(),
                        account.view_public.size()) +
                    " PROFILE:" + profile;
                if (!options.silent) std::cout << line << '\n';
                if (output) {
                    output << line << '\n';
                    output.flush();
                }
            }
            if (result != 0) break;
        }
        if (result != 0) break;
        progress.credit_completed(
            count,
            count * options.kdf_rounds,
            exact, readback_ns);
        progress.set_targets(wallets.size(), wallets.size(), solved);
        progress.set_founds(founds);
        if (hooks.add_completed) hooks.add_completed(count);
        device_slot = (device_slot + 1u) % devices.size();
    }

    progress.end();
    for (auto& device : devices) release_buffers(device);
    if (result != 0) {
        std::cerr << "[!] Monero wallet runtime error: "
                  << error << " [!]\n";
        return result;
    }
    std::cout << "[!] Monero wallet search complete: solved "
              << solved << "/" << wallets.size()
              << " artifacts [!]\n";
    return 0;
}

} // namespace monero_wallet_mode
