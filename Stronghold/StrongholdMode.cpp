#include "StrongholdMode.h"

#include "../MetalBackend.h"
#include "../tools/common/Hashes.h"

#include <algorithm>
#include <array>
#include <atomic>
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
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace stronghold_mode {
namespace {

constexpr std::uint32_t kRegularThreadgroup = 256u;
constexpr std::uint32_t kArgonThreadsPerLane = 32u;
constexpr std::uint64_t kMaximumBatch = 4096u;
constexpr std::uint32_t kPasswordStride = 128u;
constexpr std::uint32_t kSaltStride = 64u;
constexpr std::uint64_t kRuntimeReserve =
    512ull * 1024ull * 1024ull;
constexpr std::array<std::uint8_t, 5> kMagic{
    0x50u, 0x41u, 0x52u, 0x54u, 0x49u};
constexpr std::array<std::uint8_t, 2> kVersion{
    0x02u, 0x00u};

enum class Profile {
    Unset,
    Blake2b,
    Argon2Default,
    TauriExample,
};

struct Options {
    std::vector<std::string> snapshot_values;
    std::vector<std::pair<std::string, bool>> password_inputs;
    std::vector<std::string> target_values;
    std::string directory;
    std::string profile;
    std::string salt;
    std::string mask;
    std::string start;
    std::string end;
    std::string memory = "auto";
    std::string scratch_memory;
    std::string output_path;
    std::vector<int> devices{0};
    std::uint64_t batch = kMaximumBatch;
    bool save = false;
    bool silent = false;
};

struct Snapshot {
    std::string source;
    std::array<std::uint8_t, 32> ephemeral_public{};
    std::array<std::uint8_t, 16> tag{};
    std::vector<std::uint8_t> ciphertext;
    bool solved = false;
};

struct Target {
    std::array<std::uint8_t, 32> digest{};
    std::vector<std::string> origins;
    bool solved = false;
};

struct StrongholdArgon2Options {
    std::uint32_t type = 2u;
    std::uint32_t version = 0x13u;
    std::uint32_t iterations = 0u;
    std::uint32_t parallelism = 1u;
    std::uint32_t memory_usage_in_kib = 0u;
    std::uint32_t segment_length = 0u;
    std::uint32_t lane_length = 0u;
    std::uint32_t memory_block_count = 0u;
    std::uint32_t digest_len = 32u;
    std::uint32_t password_stride = kPasswordStride;
    std::uint32_t salt_len = 0u;
    std::uint32_t candidate_count = 0u;
};

static_assert(sizeof(StrongholdArgon2Options) == 48u);

struct DeviceBuffers {
    int device = -1;
    std::uint8_t* passwords = nullptr;
    std::uint8_t* password_lengths = nullptr;
    std::uint8_t* salt = nullptr;
    std::uint8_t* scratch = nullptr;
    std::uint8_t* derived_keys = nullptr;
    std::uint64_t capacity = 0u;
    std::uint64_t allocated = 0u;
};

std::string trim_copy(std::string text) {
    const std::size_t first =
        text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const std::size_t last =
        text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1u);
}

std::string lower_copy(std::string text) {
    std::transform(
        text.begin(), text.end(), text.begin(),
        [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
    return text;
}

bool parse_u64(
    const std::string& text, std::uint64_t& value) {
    try {
        std::size_t consumed = 0u;
        value = std::stoull(text, &consumed, 0);
        return consumed == text.size();
    } catch (...) {
        return false;
    }
}

bool parse_devices(
    const std::string& raw,
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
        for (std::uint64_t value = first;
             value <= last; ++value) {
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

bool parse_options(
    int argc, char** argv,
    Options& options, std::string& error) {
    bool after_mode = false;
    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];
        if (arg == "-stronghold") {
            after_mode = true;
            continue;
        }
        const auto require_value =
            [&](const char* flag) -> const char* {
            if (index + 1 >= argc) {
                error = std::string(flag) +
                    " requires a value";
                return nullptr;
            }
            return argv[++index];
        };
        if (arg == "-f") {
            const char* value = require_value("-f");
            if (!value) return false;
            options.directory = value;
        } else if (arg == "-pass") {
            const char* value = require_value("-pass");
            if (!value) return false;
            options.password_inputs.push_back({value, false});
        } else if (arg == "-i") {
            const char* value = require_value("-i");
            if (!value) return false;
            options.password_inputs.push_back({value, true});
        } else if (arg == "-target") {
            const char* value = require_value("-target");
            if (!value) return false;
            options.target_values.emplace_back(value);
        } else if (arg == "-profile") {
            const char* value = require_value("-profile");
            if (!value) return false;
            options.profile = value;
        } else if (arg == "-stronghold-salt") {
            const char* value =
                require_value("-stronghold-salt");
            if (!value) return false;
            options.salt = value;
        } else if (arg == "-mask") {
            const char* value = require_value("-mask");
            if (!value) return false;
            options.mask = value;
        } else if (arg == "-start") {
            const char* value = require_value("-start");
            if (!value) return false;
            options.start = value;
        } else if (arg == "-end") {
            const char* value = require_value("-end");
            if (!value) return false;
            options.end = value;
        } else if (arg == "-wallet-mem") {
            const char* value =
                require_value("-wallet-mem");
            if (!value) return false;
            options.memory = value;
        } else if (arg == "-wallet-scrypt-mem") {
            const char* value =
                require_value("-wallet-scrypt-mem");
            if (!value) return false;
            options.scratch_memory = value;
        } else if (arg == "-n") {
            const char* value = require_value("-n");
            if (!value ||
                !parse_u64(value, options.batch) ||
                options.batch == 0u ||
                options.batch > kMaximumBatch) {
                error = "-n must be in 1..4096";
                return false;
            }
        } else if (arg == "-device") {
            const char* value = require_value("-device");
            if (!value ||
                !parse_devices(
                    value, options.devices, error)) {
                return false;
            }
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
        } else if (!arg.empty() && arg[0] != '-' &&
                   after_mode) {
            options.snapshot_values.push_back(arg);
        } else {
            error = "unsupported -stronghold argument '" +
                arg + "'";
            return false;
        }
    }
    if (options.snapshot_values.empty() &&
        options.directory.empty()) {
        error = "-stronghold requires a snapshot file or -f DIR";
        return false;
    }
    if (options.profile.empty()) {
        error =
            "-stronghold requires an explicit -profile "
            "blake2b|argon2id|tauri-argon2id";
        return false;
    }
    const int candidate_modes =
        (!options.password_inputs.empty() ? 1 : 0) +
        (!options.mask.empty() ? 1 : 0) +
        ((!options.start.empty() ||
          !options.end.empty()) ? 1 : 0);
    if (candidate_modes != 1) {
        error =
            "choose exactly one password source: "
            "-pass/-i, -mask, or -start/-end";
        return false;
    }
    if ((!options.start.empty() || !options.end.empty()) &&
        (options.start.empty() || options.end.empty())) {
        error =
            "numeric password search requires both "
            "-start and -end";
        return false;
    }
    return true;
}

bool decode_hex(
    const std::string& raw,
    std::vector<std::uint8_t>& output) {
    std::string text = trim_copy(raw);
    if (text.size() >= 2u && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X')) {
        text.erase(0u, 2u);
    }
    if (text.empty() ||
        (text.size() & 1u) != 0u) {
        return false;
    }
    const auto digit = [](char value) -> int {
        if (value >= '0' && value <= '9') {
            return value - '0';
        }
        if (value >= 'a' && value <= 'f') {
            return value - 'a' + 10;
        }
        if (value >= 'A' && value <= 'F') {
            return value - 'A' + 10;
        }
        return -1;
    };
    output.clear();
    output.reserve(text.size() / 2u);
    for (std::size_t index = 0u;
         index < text.size(); index += 2u) {
        const int high = digit(text[index]);
        const int low = digit(text[index + 1u]);
        if (high < 0 || low < 0) return false;
        output.push_back(static_cast<std::uint8_t>(
            (high << 4u) | low));
    }
    return true;
}

std::string hex_string(
    const std::uint8_t* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0u;
         index < size; ++index) {
        output << std::setw(2)
               << static_cast<unsigned>(data[index]);
    }
    return output.str();
}

bool read_binary(
    const std::filesystem::path& path,
    std::vector<std::uint8_t>& output,
    std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "cannot open '" + path.string() + "'";
        return false;
    }
    input.seekg(0, std::ios::end);
    const std::streamoff end = input.tellg();
    if (end < 0 ||
        static_cast<std::uint64_t>(end) >
            1024ull * 1024ull * 1024ull) {
        error = "unsupported snapshot size in '" +
            path.string() + "'";
        return false;
    }
    input.seekg(0, std::ios::beg);
    output.resize(static_cast<std::size_t>(end));
    if (!output.empty()) {
        input.read(
            reinterpret_cast<char*>(output.data()),
            static_cast<std::streamsize>(output.size()));
    }
    if (!input) {
        error = "cannot read '" + path.string() + "'";
        return false;
    }
    return true;
}

bool parse_snapshot(
    const std::filesystem::path& path,
    Snapshot& snapshot, std::string& error) {
    std::vector<std::uint8_t> bytes;
    if (!read_binary(path, bytes, error)) return false;
    if (bytes.size() < 55u) {
        error = path.string() +
            ": file is too short for Stronghold v2";
        return false;
    }
    if (!std::equal(
            kMagic.begin(), kMagic.end(),
            bytes.begin())) {
        error = path.string() +
            ": invalid Stronghold magic (expected PARTI)";
        return false;
    }
    if (!std::equal(
            kVersion.begin(), kVersion.end(),
            bytes.begin() + 5u)) {
        error = path.string() +
            ": unsupported Stronghold snapshot version " +
            hex_string(bytes.data() + 5u, 2u) +
            " (only 0200 is supported)";
        return false;
    }
    snapshot.source = path.string();
    std::copy_n(
        bytes.begin() + 7u, 32u,
        snapshot.ephemeral_public.begin());
    std::copy_n(
        bytes.begin() + 39u, 16u,
        snapshot.tag.begin());
    snapshot.ciphertext.assign(
        bytes.begin() + 55u, bytes.end());
    return true;
}

bool load_snapshots(
    const Options& options,
    std::vector<Snapshot>& snapshots,
    std::string& error) {
    std::vector<std::filesystem::path> paths;
    for (const std::string& value :
         options.snapshot_values) {
        paths.emplace_back(value);
    }
    if (!options.directory.empty()) {
        std::error_code filesystem_error;
        if (!std::filesystem::is_directory(
                options.directory, filesystem_error)) {
            error = "-f path is not a directory";
            return false;
        }
        for (const auto& entry :
             std::filesystem::recursive_directory_iterator(
                 options.directory,
                 std::filesystem::directory_options::
                    skip_permission_denied,
                 filesystem_error)) {
            if (filesystem_error) {
                error = "cannot scan -f directory";
                return false;
            }
            if (entry.is_regular_file()) {
                paths.push_back(entry.path());
            }
        }
    }
    std::sort(paths.begin(), paths.end());
    paths.erase(
        std::unique(paths.begin(), paths.end()),
        paths.end());
    for (const auto& path : paths) {
        Snapshot snapshot;
        std::string parse_error;
        if (!parse_snapshot(path, snapshot, parse_error)) {
            if (!options.directory.empty() &&
                std::find(
                    options.snapshot_values.begin(),
                    options.snapshot_values.end(),
                    path.string()) ==
                    options.snapshot_values.end()) {
                continue;
            }
            error = parse_error;
            return false;
        }
        snapshots.push_back(std::move(snapshot));
    }
    if (snapshots.empty()) {
        error = "no supported Stronghold v2 snapshots";
        return false;
    }
    return true;
}

bool load_text_values(
    const std::string& value,
    std::vector<std::pair<std::string, std::string>>& lines,
    std::string& error) {
    std::error_code filesystem_error;
    if (!std::filesystem::is_regular_file(
            value, filesystem_error)) {
        lines.push_back({value, "cli"});
        return true;
    }
    std::ifstream input(value);
    if (!input) {
        error = "cannot open '" + value + "'";
        return false;
    }
    std::string line;
    std::size_t number = 0u;
    while (std::getline(input, line)) {
        ++number;
        const std::size_t comment = line.find('#');
        if (comment != std::string::npos) {
            line.erase(comment);
        }
        line = trim_copy(line);
        if (line.empty()) continue;
        std::istringstream tokens(line);
        std::string token;
        tokens >> token;
        lines.push_back({
            token, value + ":" + std::to_string(number)});
    }
    return true;
}

bool load_targets(
    const Options& options,
    std::vector<Target>& targets,
    std::uint64_t& logical_targets,
    std::string& error) {
    std::unordered_map<std::string, std::size_t> index;
    logical_targets = 0u;
    for (const std::string& value :
         options.target_values) {
        std::vector<std::pair<std::string, std::string>> lines;
        if (!load_text_values(value, lines, error)) return false;
        for (const auto& line : lines) {
            std::vector<std::uint8_t> decoded;
            if (!decode_hex(line.first, decoded) ||
                decoded.size() != 32u) {
                error = line.second +
                    ": Stronghold target must be "
                    "SHA256(decompressed snapshot plaintext)";
                return false;
            }
            ++logical_targets;
            const std::string key = hex_string(
                decoded.data(), decoded.size());
            const auto found = index.find(key);
            if (found != index.end()) {
                targets[found->second].origins.push_back(
                    line.second);
                continue;
            }
            Target target;
            std::copy(
                decoded.begin(), decoded.end(),
                target.digest.begin());
            target.origins.push_back(line.second);
            index.emplace(key, targets.size());
            targets.push_back(std::move(target));
        }
    }
    return true;
}

Profile parse_profile(
    const std::string& raw,
    StrongholdArgon2Options& config,
    std::string& error) {
    const std::string profile = lower_copy(raw);
    if (profile == "blake2b" ||
        profile == "stronghold-blake2b") {
        config.iterations = 0u;
        config.parallelism = 1u;
        return Profile::Blake2b;
    }
    if (profile == "argon2id" ||
        profile == "stronghold-argon2id" ||
        profile == "tauri-argon2id-default") {
        config.iterations = 2u;
        config.parallelism = 1u;
        config.memory_usage_in_kib = 19u * 1024u;
        return Profile::Argon2Default;
    }
    if (profile == "tauri-argon2id" ||
        profile == "tauri-example") {
        config.iterations = 10u;
        config.parallelism = 4u;
        config.memory_usage_in_kib = 10000u;
        return Profile::TauriExample;
    }
    error = "unsupported Stronghold profile '" + raw +
        "' (use blake2b, argon2id, or tauri-argon2id)";
    return Profile::Unset;
}

bool load_salt(
    const Options& options,
    Profile profile,
    std::vector<std::uint8_t>& salt,
    std::string& error) {
    if (profile == Profile::Blake2b) {
        if (!options.salt.empty()) {
            error =
                "-stronghold-salt is not used by "
                "the blake2b profile";
            return false;
        }
        return true;
    }
    if (options.salt.empty()) {
        error =
            "Argon2 Stronghold profiles require "
            "-stronghold-salt HEX|FILE";
        return false;
    }
    std::error_code filesystem_error;
    if (std::filesystem::is_regular_file(
            options.salt, filesystem_error)) {
        if (!read_binary(options.salt, salt, error)) return false;
    } else if (!decode_hex(options.salt, salt)) {
        error =
            "-stronghold-salt must be hex or an existing file";
        return false;
    }
    if (salt.size() < 8u || salt.size() > kSaltStride) {
        error = "Stronghold Argon2 salt must be 8..64 bytes";
        return false;
    }
    return true;
}

bool printable_password(
    const std::string& password, std::string& error) {
    if (password.size() >= kPasswordStride) {
        error =
            "Stronghold passwords must be shorter than "
            "128 bytes";
        return false;
    }
    for (const unsigned char byte : password) {
        if (byte < 0x20u || byte > 0x7eu) {
            error =
                "Stronghold passwords must use printable ASCII";
            return false;
        }
    }
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
        output.push_back(static_cast<char>(
            '0' + remainder));
        value = quotient;
    }
    std::reverse(output.begin(), output.end());
    return output;
}

class PasswordStream {
public:
    bool initialize(
        const Options& options, std::string& error) {
        options_ = &options;
        if (!options.mask.empty()) {
            kind_ = Kind::Mask;
            if (!parse_mask(options.mask, error)) return false;
            if (!domain_.reset(radices_, error)) return false;
            end_ = domain_.size();
            return true;
        }
        if (!options.start.empty()) {
            kind_ = Kind::Range;
            if (!modeinfra::parse_u256(
                    options.start, cursor_, error) ||
                !modeinfra::parse_u256(
                    options.end, end_, error)) {
                return false;
            }
            if (modeinfra::compare(cursor_, end_) >= 0) {
                error = "-start must be lower than -end";
                return false;
            }
            return true;
        }
        kind_ = Kind::Inputs;
        return true;
    }

    bool next(
        std::uint64_t maximum,
        std::vector<std::string>& output,
        std::string& error) {
        output.clear();
        if (kind_ == Kind::Mask) {
            return next_mask(maximum, output, error);
        }
        if (kind_ == Kind::Range) {
            return next_range(maximum, output, error);
        }
        return next_inputs(maximum, output, error);
    }

private:
    enum class Kind { Inputs, Mask, Range };
    struct MaskPart {
        bool variable = false;
        char literal = 0;
        std::string alphabet;
    };

    bool parse_mask(
        const std::string& mask, std::string& error) {
        for (std::size_t index = 0u;
             index < mask.size();) {
            if (mask[index] != '?') {
                parts_.push_back(
                    {false, mask[index++], {}});
                continue;
            }
            if (index + 1u >= mask.size()) {
                error = "dangling '?' in -mask";
                return false;
            }
            const char code = mask[index + 1u];
            if (code == '?') {
                parts_.push_back({false, '?', {}});
            } else {
                std::string alphabet;
                if (code == 'd') {
                    alphabet = "0123456789";
                } else if (code == 'l') {
                    alphabet = "abcdefghijklmnopqrstuvwxyz";
                } else if (code == 'u') {
                    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                } else if (code == 'a') {
                    alphabet =
                        "0123456789abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                } else {
                    error =
                        std::string("unsupported -mask token ?") +
                        code;
                    return false;
                }
                parts_.push_back({true, 0, alphabet});
                radices_.push_back(alphabet.size());
            }
            index += 2u;
        }
        if (parts_.size() >= kPasswordStride) {
            error = "expanded -mask password is too long";
            return false;
        }
        if (radices_.empty()) radices_.push_back(1u);
        return true;
    }

    std::string render_mask(
        const std::vector<std::uint64_t>& digits) const {
        std::string output;
        output.reserve(parts_.size());
        std::size_t digit = 0u;
        for (const MaskPart& part : parts_) {
            output.push_back(
                part.variable
                ? part.alphabet[
                    static_cast<std::size_t>(
                        digits[digit++])]
                : part.literal);
        }
        return output;
    }

    bool next_mask(
        std::uint64_t maximum,
        std::vector<std::string>& output,
        std::string& error) {
        while (output.size() < maximum &&
               modeinfra::compare(cursor_, end_) < 0) {
            std::vector<std::uint64_t> digits;
            if (!domain_.decode(
                    cursor_, digits, error)) {
                return false;
            }
            output.push_back(render_mask(digits));
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

    bool next_range(
        std::uint64_t maximum,
        std::vector<std::string>& output,
        std::string& error) {
        while (output.size() < maximum &&
               modeinfra::compare(cursor_, end_) < 0) {
            const std::string value = u256_decimal(cursor_);
            if (value.empty() ||
                !printable_password(value, error)) {
                if (error.empty()) {
                    error =
                        "numeric password conversion failed";
                }
                return false;
            }
            output.push_back(value);
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

    bool open_next(std::string& error) {
        while (input_index_ <
               options_->password_inputs.size()) {
            const auto& entry =
                options_->password_inputs[input_index_++];
            std::error_code filesystem_error;
            const bool file =
                entry.second ||
                std::filesystem::is_regular_file(
                    entry.first, filesystem_error);
            if (!file) {
                if (!printable_password(
                        entry.first, error)) {
                    return false;
                }
                literals_.push_back(entry.first);
                return true;
            }
            file_.close();
            file_.clear();
            file_.open(entry.first);
            if (!file_) {
                error =
                    "cannot open password file '" +
                    entry.first + "'";
                return false;
            }
            return true;
        }
        exhausted_ = true;
        return true;
    }

    bool next_inputs(
        std::uint64_t maximum,
        std::vector<std::string>& output,
        std::string& error) {
        while (output.size() < maximum) {
            if (!literals_.empty()) {
                output.push_back(
                    std::move(literals_.front()));
                literals_.erase(literals_.begin());
                continue;
            }
            if (file_.is_open()) {
                std::string line;
                if (std::getline(file_, line)) {
                    if (!line.empty() &&
                        line.back() == '\r') {
                        line.pop_back();
                    }
                    if (!printable_password(line, error)) {
                        return false;
                    }
                    output.push_back(std::move(line));
                    continue;
                }
                file_.close();
            }
            if (exhausted_) break;
            if (!open_next(error)) return false;
        }
        return true;
    }

    Kind kind_ = Kind::Inputs;
    const Options* options_ = nullptr;
    std::size_t input_index_ = 0u;
    bool exhausted_ = false;
    std::ifstream file_;
    std::vector<std::string> literals_;
    std::vector<MaskPart> parts_;
    std::vector<std::uint64_t> radices_;
    modeinfra::MixedRadixDomain domain_;
    modeinfra::U256 cursor_{};
    modeinfra::U256 end_{};
};

using Gf = std::array<std::int64_t, 16>;
constexpr Gf kCurve121665{
    0xdb41, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0};

void curve_carry(Gf& value) {
    for (std::size_t index = 0u;
         index < 16u; ++index) {
        value[index] += 1ll << 16;
        const std::int64_t carry =
            value[index] >> 16;
        if (index < 15u) {
            value[index + 1u] += carry - 1;
        } else {
            value[0] += 38 * (carry - 1);
        }
        value[index] -= carry << 16;
    }
}

void curve_select(
    Gf& left, Gf& right, std::int64_t bit) {
    const std::int64_t mask = ~(bit - 1);
    for (std::size_t index = 0u;
         index < 16u; ++index) {
        const std::int64_t value =
            mask & (left[index] ^ right[index]);
        left[index] ^= value;
        right[index] ^= value;
    }
}

void curve_pack(
    std::array<std::uint8_t, 32>& output,
    const Gf& input) {
    Gf temporary = input;
    Gf reduced{};
    curve_carry(temporary);
    curve_carry(temporary);
    curve_carry(temporary);
    for (int round = 0; round < 2; ++round) {
        reduced[0] = temporary[0] - 0xffed;
        for (std::size_t index = 1u;
             index < 15u; ++index) {
            reduced[index] =
                temporary[index] - 0xffff -
                ((reduced[index - 1u] >> 16) & 1);
            reduced[index - 1u] &= 0xffff;
        }
        reduced[15] =
            temporary[15] - 0x7fff -
            ((reduced[14] >> 16) & 1);
        const std::int64_t bit =
            (reduced[15] >> 16) & 1;
        reduced[14] &= 0xffff;
        curve_select(temporary, reduced, 1 - bit);
    }
    for (std::size_t index = 0u;
         index < 16u; ++index) {
        output[index * 2u] =
            static_cast<std::uint8_t>(temporary[index]);
        output[index * 2u + 1u] =
            static_cast<std::uint8_t>(
                temporary[index] >> 8);
    }
}

void curve_unpack(
    Gf& output,
    const std::array<std::uint8_t, 32>& input) {
    for (std::size_t index = 0u;
         index < 16u; ++index) {
        output[index] =
            input[index * 2u] +
            (static_cast<std::int64_t>(
                input[index * 2u + 1u]) << 8);
    }
    output[15] &= 0x7fff;
}

void curve_add(
    Gf& output, const Gf& left, const Gf& right) {
    for (std::size_t index = 0u;
         index < 16u; ++index) {
        output[index] = left[index] + right[index];
    }
}

void curve_sub(
    Gf& output, const Gf& left, const Gf& right) {
    for (std::size_t index = 0u;
         index < 16u; ++index) {
        output[index] = left[index] - right[index];
    }
}

void curve_mul(
    Gf& output, const Gf& left, const Gf& right) {
    std::array<std::int64_t, 31> product{};
    for (std::size_t i = 0u; i < 16u; ++i) {
        for (std::size_t j = 0u; j < 16u; ++j) {
            product[i + j] += left[i] * right[j];
        }
    }
    for (std::size_t index = 0u;
         index < 15u; ++index) {
        product[index] += 38 * product[index + 16u];
    }
    for (std::size_t index = 0u;
         index < 16u; ++index) {
        output[index] = product[index];
    }
    curve_carry(output);
    curve_carry(output);
}

void curve_square(Gf& output, const Gf& input) {
    curve_mul(output, input, input);
}

void curve_inverse(Gf& output, const Gf& input) {
    Gf value = input;
    for (int power = 253; power >= 0; --power) {
        curve_square(value, value);
        if (power != 2 && power != 4) {
            curve_mul(value, value, input);
        }
    }
    output = value;
}

std::array<std::uint8_t, 32> x25519(
    const std::array<std::uint8_t, 32>& secret,
    const std::array<std::uint8_t, 32>& point) {
    std::array<std::uint8_t, 32> scalar = secret;
    scalar[0] &= 248u;
    scalar[31] &= 127u;
    scalar[31] |= 64u;
    Gf x{};
    curve_unpack(x, point);
    Gf a{};
    Gf b = x;
    Gf c{};
    Gf d{};
    a[0] = 1;
    d[0] = 1;
    Gf e{};
    Gf f{};
    for (int bit_index = 254;
         bit_index >= 0; --bit_index) {
        const std::int64_t bit =
            (scalar[static_cast<std::size_t>(
                bit_index >> 3)] >>
             (bit_index & 7)) & 1;
        curve_select(a, b, bit);
        curve_select(c, d, bit);
        curve_add(e, a, c);
        curve_sub(a, a, c);
        curve_add(c, b, d);
        curve_sub(b, b, d);
        curve_square(d, e);
        curve_square(f, a);
        curve_mul(a, c, a);
        curve_mul(c, b, e);
        curve_add(e, a, c);
        curve_sub(a, a, c);
        curve_square(b, a);
        curve_sub(c, d, f);
        curve_mul(a, c, kCurve121665);
        curve_add(a, a, d);
        curve_mul(c, c, a);
        curve_mul(a, d, f);
        curve_mul(d, b, x);
        curve_square(b, e);
        curve_select(a, b, bit);
        curve_select(c, d, bit);
    }
    curve_inverse(c, c);
    curve_mul(a, a, c);
    std::array<std::uint8_t, 32> output{};
    curve_pack(output, a);
    return output;
}

std::uint32_t load32(
    const std::uint8_t* input) {
    return static_cast<std::uint32_t>(input[0]) |
        (static_cast<std::uint32_t>(input[1]) << 8u) |
        (static_cast<std::uint32_t>(input[2]) << 16u) |
        (static_cast<std::uint32_t>(input[3]) << 24u);
}

void store32(
    std::uint8_t* output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8u);
    output[2] = static_cast<std::uint8_t>(value >> 16u);
    output[3] = static_cast<std::uint8_t>(value >> 24u);
}

std::uint32_t rotate_left(
    std::uint32_t value, unsigned shift) {
    return (value << shift) | (value >> (32u - shift));
}

void chacha_rounds(std::uint32_t state[16]) {
    const auto quarter =
        [](std::uint32_t& a, std::uint32_t& b,
           std::uint32_t& c, std::uint32_t& d) {
        a += b; d = rotate_left(d ^ a, 16u);
        c += d; b = rotate_left(b ^ c, 12u);
        a += b; d = rotate_left(d ^ a, 8u);
        c += d; b = rotate_left(b ^ c, 7u);
    };
    for (unsigned round = 0u; round < 10u; ++round) {
        quarter(state[0], state[4], state[8], state[12]);
        quarter(state[1], state[5], state[9], state[13]);
        quarter(state[2], state[6], state[10], state[14]);
        quarter(state[3], state[7], state[11], state[15]);
        quarter(state[0], state[5], state[10], state[15]);
        quarter(state[1], state[6], state[11], state[12]);
        quarter(state[2], state[7], state[8], state[13]);
        quarter(state[3], state[4], state[9], state[14]);
    }
}

std::array<std::uint8_t, 32> hchacha20(
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 24>& nonce) {
    std::uint32_t state[16]{
        0x61707865u, 0x3320646eu,
        0x79622d32u, 0x6b206574u};
    for (std::size_t index = 0u;
         index < 8u; ++index) {
        state[index + 4u] =
            load32(key.data() + index * 4u);
    }
    for (std::size_t index = 0u;
         index < 4u; ++index) {
        state[index + 12u] =
            load32(nonce.data() + index * 4u);
    }
    chacha_rounds(state);
    std::array<std::uint8_t, 32> output{};
    const std::uint32_t selected[8]{
        state[0], state[1], state[2], state[3],
        state[12], state[13], state[14], state[15]};
    for (std::size_t index = 0u;
         index < 8u; ++index) {
        store32(output.data() + index * 4u, selected[index]);
    }
    return output;
}

std::array<std::uint8_t, 64> chacha20_block(
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 12>& nonce,
    std::uint32_t counter) {
    std::uint32_t state[16]{
        0x61707865u, 0x3320646eu,
        0x79622d32u, 0x6b206574u};
    for (std::size_t index = 0u;
         index < 8u; ++index) {
        state[index + 4u] =
            load32(key.data() + index * 4u);
    }
    state[12] = counter;
    state[13] = load32(nonce.data());
    state[14] = load32(nonce.data() + 4u);
    state[15] = load32(nonce.data() + 8u);
    std::uint32_t working[16];
    std::copy_n(state, 16u, working);
    chacha_rounds(working);
    std::array<std::uint8_t, 64> output{};
    for (std::size_t index = 0u;
         index < 16u; ++index) {
        store32(
            output.data() + index * 4u,
            working[index] + state[index]);
    }
    return output;
}

struct Poly1305 {
    std::array<std::uint32_t, 5> r{};
    std::array<std::uint32_t, 4> pad{};
    std::array<std::uint32_t, 5> h{};
};

void poly1305_init(
    Poly1305& context,
    const std::array<std::uint8_t, 64>& block) {
    context.r[0] = load32(block.data()) & 0x3ffffffu;
    context.r[1] =
        (load32(block.data() + 3u) >> 2u) & 0x3ffff03u;
    context.r[2] =
        (load32(block.data() + 6u) >> 4u) & 0x3ffc0ffu;
    context.r[3] =
        (load32(block.data() + 9u) >> 6u) & 0x3f03fffu;
    context.r[4] =
        (load32(block.data() + 12u) >> 8u) & 0x00fffffu;
    for (std::size_t index = 0u;
         index < 4u; ++index) {
        context.pad[index] =
            load32(block.data() + 16u + index * 4u);
    }
}

void poly1305_blocks(
    Poly1305& context,
    const std::uint8_t* message,
    std::size_t bytes,
    std::uint32_t high_bit) {
    const std::uint64_t r0 = context.r[0];
    const std::uint64_t r1 = context.r[1];
    const std::uint64_t r2 = context.r[2];
    const std::uint64_t r3 = context.r[3];
    const std::uint64_t r4 = context.r[4];
    const std::uint64_t r1_5 = r1 * 5u;
    const std::uint64_t r2_5 = r2 * 5u;
    const std::uint64_t r3_5 = r3 * 5u;
    const std::uint64_t r4_5 = r4 * 5u;
    while (bytes >= 16u) {
        const std::uint32_t t0 = load32(message);
        const std::uint32_t t1 = load32(message + 4u);
        const std::uint32_t t2 = load32(message + 8u);
        const std::uint32_t t3 = load32(message + 12u);
        std::uint64_t h0 =
            context.h[0] + (t0 & 0x3ffffffu);
        std::uint64_t h1 =
            context.h[1] +
            (((t0 >> 26u) |
              (static_cast<std::uint64_t>(t1) << 6u)) &
             0x3ffffffu);
        std::uint64_t h2 =
            context.h[2] +
            (((t1 >> 20u) |
              (static_cast<std::uint64_t>(t2) << 12u)) &
             0x3ffffffu);
        std::uint64_t h3 =
            context.h[3] +
            (((t2 >> 14u) |
              (static_cast<std::uint64_t>(t3) << 18u)) &
             0x3ffffffu);
        std::uint64_t h4 =
            context.h[4] + (t3 >> 8u) + high_bit;
        std::uint64_t d0 =
            h0 * r0 + h1 * r4_5 + h2 * r3_5 +
            h3 * r2_5 + h4 * r1_5;
        std::uint64_t d1 =
            h0 * r1 + h1 * r0 + h2 * r4_5 +
            h3 * r3_5 + h4 * r2_5;
        std::uint64_t d2 =
            h0 * r2 + h1 * r1 + h2 * r0 +
            h3 * r4_5 + h4 * r3_5;
        std::uint64_t d3 =
            h0 * r3 + h1 * r2 + h2 * r1 +
            h3 * r0 + h4 * r4_5;
        std::uint64_t d4 =
            h0 * r4 + h1 * r3 + h2 * r2 +
            h3 * r1 + h4 * r0;
        std::uint64_t carry = d0 >> 26u;
        context.h[0] = d0 & 0x3ffffffu;
        d1 += carry;
        carry = d1 >> 26u;
        context.h[1] = d1 & 0x3ffffffu;
        d2 += carry;
        carry = d2 >> 26u;
        context.h[2] = d2 & 0x3ffffffu;
        d3 += carry;
        carry = d3 >> 26u;
        context.h[3] = d3 & 0x3ffffffu;
        d4 += carry;
        carry = d4 >> 26u;
        context.h[4] = d4 & 0x3ffffffu;
        context.h[0] +=
            static_cast<std::uint32_t>(carry * 5u);
        carry = context.h[0] >> 26u;
        context.h[0] &= 0x3ffffffu;
        context.h[1] +=
            static_cast<std::uint32_t>(carry);
        message += 16u;
        bytes -= 16u;
    }
}

std::array<std::uint8_t, 16> poly1305_finish(
    Poly1305& context) {
    std::uint64_t carry = context.h[1] >> 26u;
    context.h[1] &= 0x3ffffffu;
    context.h[2] += carry;
    carry = context.h[2] >> 26u;
    context.h[2] &= 0x3ffffffu;
    context.h[3] += carry;
    carry = context.h[3] >> 26u;
    context.h[3] &= 0x3ffffffu;
    context.h[4] += carry;
    carry = context.h[4] >> 26u;
    context.h[4] &= 0x3ffffffu;
    context.h[0] += carry * 5u;
    carry = context.h[0] >> 26u;
    context.h[0] &= 0x3ffffffu;
    context.h[1] += carry;
    std::uint32_t g0 = context.h[0] + 5u;
    carry = g0 >> 26u; g0 &= 0x3ffffffu;
    std::uint32_t g1 =
        context.h[1] + static_cast<std::uint32_t>(carry);
    carry = g1 >> 26u; g1 &= 0x3ffffffu;
    std::uint32_t g2 =
        context.h[2] + static_cast<std::uint32_t>(carry);
    carry = g2 >> 26u; g2 &= 0x3ffffffu;
    std::uint32_t g3 =
        context.h[3] + static_cast<std::uint32_t>(carry);
    carry = g3 >> 26u; g3 &= 0x3ffffffu;
    std::uint32_t g4 =
        context.h[4] + static_cast<std::uint32_t>(carry) -
        (1u << 26u);
    std::uint32_t mask = (g4 >> 31u) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask;
    g3 &= mask; g4 &= mask;
    mask = ~mask;
    context.h[0] = (context.h[0] & mask) | g0;
    context.h[1] = (context.h[1] & mask) | g1;
    context.h[2] = (context.h[2] & mask) | g2;
    context.h[3] = (context.h[3] & mask) | g3;
    context.h[4] = (context.h[4] & mask) | g4;
    std::uint64_t f0 =
        (context.h[0] |
         (static_cast<std::uint64_t>(
              context.h[1]) << 26u)) &
        0xffffffffull;
    std::uint64_t f1 =
        ((context.h[1] >> 6u) |
         (static_cast<std::uint64_t>(
              context.h[2]) << 20u)) &
        0xffffffffull;
    std::uint64_t f2 =
        ((context.h[2] >> 12u) |
         (static_cast<std::uint64_t>(
              context.h[3]) << 14u)) &
        0xffffffffull;
    std::uint64_t f3 =
        ((context.h[3] >> 18u) |
         (static_cast<std::uint64_t>(
              context.h[4]) << 8u)) &
        0xffffffffull;
    f0 += context.pad[0];
    f1 += context.pad[1] + (f0 >> 32u);
    f0 &= 0xffffffffull;
    f2 += context.pad[2] + (f1 >> 32u);
    f1 &= 0xffffffffull;
    f3 += context.pad[3] + (f2 >> 32u);
    f2 &= 0xffffffffull;
    std::array<std::uint8_t, 16> tag{};
    store32(tag.data(), static_cast<std::uint32_t>(f0));
    store32(tag.data() + 4u, static_cast<std::uint32_t>(f1));
    store32(tag.data() + 8u, static_cast<std::uint32_t>(f2));
    store32(tag.data() + 12u, static_cast<std::uint32_t>(f3));
    return tag;
}

std::array<std::uint8_t, 16> poly1305_ciphertext(
    const std::array<std::uint8_t, 64>& block0,
    const std::vector<std::uint8_t>& ciphertext) {
    Poly1305 context;
    poly1305_init(context, block0);
    const std::size_t full =
        ciphertext.size() & ~std::size_t(15u);
    if (full != 0u) {
        poly1305_blocks(
            context, ciphertext.data(), full, 1u << 24u);
    }
    const std::size_t remaining =
        ciphertext.size() - full;
    if (remaining != 0u) {
        std::array<std::uint8_t, 16> block{};
        std::copy_n(
            ciphertext.begin() +
                static_cast<std::ptrdiff_t>(full),
            remaining, block.begin());
        poly1305_blocks(
            context, block.data(), block.size(),
            1u << 24u);
    }
    std::array<std::uint8_t, 16> lengths{};
    std::uint64_t size = ciphertext.size();
    for (std::size_t index = 0u;
         index < 8u; ++index) {
        lengths[8u + index] =
            static_cast<std::uint8_t>(size >> (index * 8u));
    }
    poly1305_blocks(
        context, lengths.data(), lengths.size(),
        1u << 24u);
    return poly1305_finish(context);
}

bool constant_equal(
    const std::uint8_t* left,
    const std::uint8_t* right,
    std::size_t size) {
    std::uint8_t difference = 0u;
    for (std::size_t index = 0u;
         index < size; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0u;
}

bool xchacha_decrypt(
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 24>& nonce,
    const std::array<std::uint8_t, 16>& expected_tag,
    const std::vector<std::uint8_t>& ciphertext,
    std::vector<std::uint8_t>& plaintext) {
    const auto subkey = hchacha20(key, nonce);
    std::array<std::uint8_t, 12> short_nonce{};
    std::copy_n(
        nonce.begin() + 16u, 8u,
        short_nonce.begin() + 4u);
    const auto block0 =
        chacha20_block(subkey, short_nonce, 0u);
    const auto actual_tag =
        poly1305_ciphertext(block0, ciphertext);
    if (!constant_equal(
            actual_tag.data(), expected_tag.data(),
            expected_tag.size())) {
        return false;
    }
    plaintext.resize(ciphertext.size());
    std::uint32_t counter = 1u;
    std::size_t offset = 0u;
    while (offset < ciphertext.size()) {
        const auto block =
            chacha20_block(subkey, short_nonce, counter++);
        const std::size_t count =
            std::min<std::size_t>(
                64u, ciphertext.size() - offset);
        for (std::size_t index = 0u;
             index < count; ++index) {
            plaintext[offset + index] =
                ciphertext[offset + index] ^ block[index];
        }
        offset += count;
    }
    return true;
}

bool decompress_stronghold(
    const std::vector<std::uint8_t>& input,
    std::vector<std::uint8_t>& output) {
    output.clear();
    std::size_t cursor = 0u;
    while (cursor < input.size()) {
        const std::uint8_t token = input[cursor++];
        std::size_t literal = token >> 4u;
        if (literal == 15u) {
            while (true) {
                if (cursor >= input.size()) return false;
                const std::uint8_t extra = input[cursor++];
                if (literal >
                    std::numeric_limits<std::size_t>::max() -
                    extra) {
                    return false;
                }
                literal += extra;
                if (extra != 0xffu) break;
            }
        }
        if (literal > input.size() - cursor ||
            output.size() >
                1024ull * 1024ull * 1024ull - literal) {
            return false;
        }
        output.insert(
            output.end(),
            input.begin() +
                static_cast<std::ptrdiff_t>(cursor),
            input.begin() +
                static_cast<std::ptrdiff_t>(cursor + literal));
        cursor += literal;
        if (cursor == input.size()) break;
        if (input.size() - cursor < 2u) return false;
        const std::uint16_t distance =
            static_cast<std::uint16_t>(input[cursor]) |
            (static_cast<std::uint16_t>(
                 input[cursor + 1u]) << 8u);
        cursor += 2u;
        if (distance == 0u ||
            distance > output.size()) {
            return false;
        }
        std::size_t length = 4u + (token & 0x0fu);
        if ((token & 0x0fu) == 15u) {
            while (true) {
                if (cursor >= input.size()) return false;
                const std::uint8_t extra = input[cursor++];
                if (length >
                    std::numeric_limits<std::size_t>::max() -
                    extra) {
                    return false;
                }
                length += extra;
                if (extra != 0xffu) break;
            }
        }
        if (output.size() >
            1024ull * 1024ull * 1024ull - length) {
            return false;
        }
        const std::size_t start =
            output.size() - distance;
        for (std::size_t index = 0u;
             index < length; ++index) {
            output.push_back(
                output[start + index]);
        }
    }
    return !output.empty();
}

bool verify_snapshot(
    const std::array<std::uint8_t, 32>& snapshot_key,
    Snapshot& snapshot,
    std::vector<Target>& targets,
    std::string& matched_target,
    std::array<std::uint8_t, 32>& plaintext_digest) {
    std::array<std::uint8_t, 32> base{};
    base[0] = 9u;
    const auto public_key = x25519(snapshot_key, base);
    const auto shared =
        x25519(snapshot_key, snapshot.ephemeral_public);
    std::array<std::uint8_t, 64> nonce_input{};
    std::copy(
        snapshot.ephemeral_public.begin(),
        snapshot.ephemeral_public.end(),
        nonce_input.begin());
    std::copy(
        public_key.begin(), public_key.end(),
        nonce_input.begin() + 32u);
    const std::vector<std::uint8_t> nonce_hash =
        address_tools::blake2b(
            nonce_input.data(), nonce_input.size(), 32u);
    std::array<std::uint8_t, 24> nonce{};
    std::copy_n(
        nonce_hash.begin(), nonce.size(), nonce.begin());
    std::vector<std::uint8_t> compressed;
    if (!xchacha_decrypt(
            shared, nonce, snapshot.tag,
            snapshot.ciphertext, compressed)) {
        return false;
    }
    std::vector<std::uint8_t> plaintext;
    if (!decompress_stronghold(
            compressed, plaintext)) {
        return false;
    }
    plaintext_digest =
        address_tools::sha256(
            plaintext.data(), plaintext.size());
    if (targets.empty()) {
        matched_target = "authenticated-snapshot";
        return true;
    }
    std::vector<std::string> origins;
    for (Target& target : targets) {
        if (constant_equal(
                target.digest.data(),
                plaintext_digest.data(),
                target.digest.size())) {
            target.solved = true;
            origins.insert(
                origins.end(),
                target.origins.begin(),
                target.origins.end());
        }
    }
    if (origins.empty()) return false;
    std::ostringstream joined;
    for (std::size_t index = 0u;
         index < origins.size(); ++index) {
        if (index != 0u) joined << ",";
        joined << origins[index];
    }
    matched_target = joined.str();
    return true;
}

bool metal_ok(
    metalError_t status,
    const char* action,
    std::string& error) {
    if (status == metalSuccess) return true;
    error = std::string(action) + ": " +
        metalGetErrorString(status);
    return false;
}

template <typename T>
bool allocate_buffer(
    T*& pointer,
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

void release_buffers(DeviceBuffers& buffers) {
    if (buffers.device >= 0) {
        (void)metalSetDevice(buffers.device);
    }
    if (buffers.passwords) metalFree(buffers.passwords);
    if (buffers.password_lengths) {
        metalFree(buffers.password_lengths);
    }
    if (buffers.salt) metalFree(buffers.salt);
    if (buffers.scratch) metalFree(buffers.scratch);
    if (buffers.derived_keys) metalFree(buffers.derived_keys);
    buffers = {};
}

bool prepare_buffers(
    int device,
    std::uint64_t capacity,
    std::uint64_t scratch_per_candidate,
    DeviceBuffers& buffers,
    std::string& error) {
    buffers.device = device;
    if (!metal_ok(
            metalSetDevice(device),
            "select Stronghold device", error) ||
        !allocate_buffer(
            buffers.passwords,
            capacity * kPasswordStride,
            "allocate Stronghold passwords", error) ||
        !allocate_buffer(
            buffers.password_lengths, capacity,
            "allocate Stronghold password lengths", error) ||
        !allocate_buffer(
            buffers.salt, kSaltStride,
            "allocate Stronghold salt", error) ||
        !allocate_buffer(
            buffers.scratch,
            capacity * scratch_per_candidate,
            "allocate Stronghold Argon2 scratch", error) ||
        !allocate_buffer(
            buffers.derived_keys, capacity * 32u,
            "allocate Stronghold derived keys", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.capacity = capacity;
    buffers.allocated =
        capacity *
            (kPasswordStride + 1u + 32u +
             scratch_per_candidate) +
        kSaltStride;
    return true;
}

std::uint32_t round_grid(
    std::uint64_t count,
    std::uint32_t threadgroup) {
    return static_cast<std::uint32_t>(
        (count + threadgroup - 1u) /
        threadgroup * threadgroup);
}

bool derive_batch(
    DeviceBuffers& buffers,
    StrongholdArgon2Options config,
    const std::vector<std::string>& passwords,
    std::size_t offset,
    std::size_t count,
    const std::vector<std::uint8_t>& salt,
    std::vector<std::array<std::uint8_t, 32>>& keys,
    std::uint64_t& readback_ns,
    std::string& error) {
    std::vector<std::uint8_t> packed(
        count * kPasswordStride, 0u);
    std::vector<std::uint8_t> lengths(count, 0u);
    for (std::size_t index = 0u;
         index < count; ++index) {
        const std::string& password =
            passwords[offset + index];
        lengths[index] =
            static_cast<std::uint8_t>(password.size());
        std::copy(
            password.begin(), password.end(),
            packed.begin() +
                static_cast<std::ptrdiff_t>(
                    index * kPasswordStride));
    }
    std::array<std::uint8_t, kSaltStride> salt_buffer{};
    std::copy(
        salt.begin(), salt.end(), salt_buffer.begin());
    config.candidate_count =
        static_cast<std::uint32_t>(count);
    if (!metal_ok(
            metalSetDevice(buffers.device),
            "select Stronghold device", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.passwords, packed.data(),
                packed.size(), metalMemcpyHostToDevice),
            "upload Stronghold passwords", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.password_lengths, lengths.data(),
                lengths.size(), metalMemcpyHostToDevice),
            "upload Stronghold password lengths", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.salt, salt_buffer.data(),
                salt_buffer.size(), metalMemcpyHostToDevice),
            "upload Stronghold salt", error) ||
        !metal_ok(
            metal_launch(
                "workerStrongholdInit",
                round_grid(count, kRegularThreadgroup),
                kRegularThreadgroup,
                config, buffers.passwords,
                buffers.password_lengths, buffers.salt,
                buffers.scratch, buffers.derived_keys),
            "launch Stronghold init", error)) {
        return false;
    }
    if (config.iterations != 0u) {
        const std::uint32_t threads =
            config.parallelism * kArgonThreadsPerLane;
        for (std::uint32_t pass = 0u;
             pass < config.iterations; ++pass) {
            for (std::uint32_t slice = 0u;
                 slice < 4u; ++slice) {
                if (!metal_ok(
                        metal_launch(
                            "workerStrongholdFill",
                            static_cast<std::uint32_t>(
                                count) * threads,
                            threads, config, pass, slice,
                            buffers.scratch),
                        "launch Stronghold Argon2 fill",
                        error)) {
                    return false;
                }
            }
        }
        if (!metal_ok(
                metal_launch(
                    "workerStrongholdFinal",
                    round_grid(count, kRegularThreadgroup),
                    kRegularThreadgroup,
                    config, buffers.scratch,
                    buffers.derived_keys),
                "launch Stronghold final", error)) {
            return false;
        }
    }
    if (!metal_ok(
            metalDeviceSynchronize(),
            "synchronize Stronghold pipeline", error)) {
        return false;
    }
    keys.resize(count);
    const auto read_started =
        std::chrono::steady_clock::now();
    if (!metal_ok(
            metalMemcpy(
                keys.data(), buffers.derived_keys,
                count * 32u, metalMemcpyDeviceToHost),
            "read Stronghold derived keys", error)) {
        return false;
    }
    readback_ns += static_cast<std::uint64_t>(
        std::chrono::duration_cast<
            std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() -
            read_started).count());
    return true;
}

std::uint64_t saturating_add(
    std::uint64_t left, std::uint64_t right) {
    return right >
        std::numeric_limits<std::uint64_t>::max() - left
        ? std::numeric_limits<std::uint64_t>::max()
        : left + right;
}

std::uint64_t solved_snapshots(
    const std::vector<Snapshot>& snapshots) {
    return static_cast<std::uint64_t>(
        std::count_if(
            snapshots.begin(), snapshots.end(),
            [](const Snapshot& snapshot) {
                return snapshot.solved;
            }));
}

std::string quote_password(const std::string& password) {
    std::ostringstream output;
    output << std::quoted(password);
    return output.str();
}

}  // namespace

bool requested(int argc, char** argv) {
    for (int index = 1; index < argc; ++index) {
        if (std::string(argv[index]) == "-stronghold") {
            return true;
        }
    }
    return false;
}

void print_help() {
    std::cout << R"HELP(
[!] ================= STRONGHOLD MODE =================
[!]
[!] -stronghold FILE1 ...            Recover IOTA/Tauri Stronghold passwords.
[!] -f DIR                           Recursively scan supported snapshots.
[!]
[!] Required profile:
[!] -profile blake2b                 Core Blake2b-256 passphrase profile.
[!] -profile argon2id                rust-argon2 default: id/v19, 19 MiB,
[!]                                  t=2, p=1, 32-byte output.
[!] -profile tauri-argon2id          Published Tauri example: id/v19,
[!]                                  10000 KiB, t=10, p=4.
[!] -stronghold-salt HEX|FILE        Required by Argon2 profiles. The Tauri
[!]                                  with_argon2 helper normally stores a
[!]                                  separate raw 32-byte salt file.
[!]
[!] Password candidates:
[!] -pass VALUE|FILE                 Literal password or existing text file.
[!] -i FILE                          Streaming dictionary; repeatable.
[!] -mask MASK                       ?d, ?l, ?u, ?a and ?? masks.
[!] -start N -end N                  Decimal-string passwords in [START,END).
[!]
[!] Optional verification:
[!] -target HEX|FILE                 SHA256 of decompressed snapshot plaintext.
[!] Without targets, a valid XChaCha20-Poly1305 tag plus successful exact
[!] Stronghold LZ4 decompression is the recovery proof.
[!]
[!] GPU / memory:
[!] -wallet-mem auto|all|NN%|SIZE    Unified-memory working-set budget.
[!] -wallet-scrypt-mem SPEC          Optional stricter KDF scratch ceiling.
[!] -n N                             Maximum resident candidates, 1..4096.
[!] -device LIST                     Metal devices, for example 0 or 0,1.
[!] auto uses at most 50% of the current free recommended working set.
[!] all leaves 512 MiB for runtime. Allocation is lazy and may reduce
[!] residency after an automatic allocation failure.
[!]
[!] Statistics:
[!] The common SpeedThreadFunc is the only statistics writer. It reports
[!] KDF/s, exact host verifications, actual Metal working set and readback.
[!]
[!] Output:
[!] -save                            Append independently verified hits.
[!] -o FILE                          Output path (also enables saving).
[!] -silent                          Suppress found lines on the console.
[!]
[!] Examples:
[!]   ./METAL_CRYPTO_TOOLKIT -stronghold vault.stronghold \
[!]     -profile blake2b -pass passwords.txt -save
[!]   ./METAL_CRYPTO_TOOLKIT -stronghold vault.stronghold \
[!]     -profile argon2id -stronghold-salt salt.bin \
[!]     -i passwords.txt -wallet-mem all
[!]   ./METAL_CRYPTO_TOOLKIT -stronghold vault.stronghold \
[!]     -profile tauri-argon2id \
[!]     -stronghold-salt 00112233445566778899aabbccddeeff \
[!]     -mask "secret?d?d" -target snapshot.sha256
[!]
[!] Limitations:
[!] Only Stronghold snapshot header PARTI/version 02 00 and the three named
[!] KDF profiles are accepted. A snapshot does not encode its application KDF
[!] or salt, so the correct external profile metadata is mandatory. Unknown
[!] versions and guessed/custom KDFs are rejected before GPU work.
[!]
[!] Errors:
[!] CLI/input errors return 2; Metal/runtime errors return 1; an exhausted
[!] valid search returns 0 even when no password is found.
[!] ====================================================
[!] End of detailed help for -stronghold [!]
)HELP";
}

int run(
    int argc, char** argv,
    const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] Stronghold CLI error: "
                  << error << " [!]\n";
        return 2;
    }
    std::vector<Snapshot> snapshots;
    if (!load_snapshots(options, snapshots, error)) {
        std::cerr << "[!] Stronghold input error: "
                  << error << " [!]\n";
        return 2;
    }
    std::vector<Target> targets;
    std::uint64_t logical_targets = 0u;
    if (!load_targets(
            options, targets, logical_targets, error)) {
        std::cerr << "[!] Stronghold target error: "
                  << error << " [!]\n";
        return 2;
    }
    StrongholdArgon2Options config;
    const Profile profile =
        parse_profile(options.profile, config, error);
    if (profile == Profile::Unset) {
        std::cerr << "[!] Stronghold profile error: "
                  << error << " [!]\n";
        return 2;
    }
    std::vector<std::uint8_t> salt;
    if (!load_salt(options, profile, salt, error)) {
        std::cerr << "[!] Stronghold salt error: "
                  << error << " [!]\n";
        return 2;
    }
    config.salt_len =
        static_cast<std::uint32_t>(salt.size());
    if (config.iterations != 0u) {
        const std::uint32_t quantum =
            4u * config.parallelism;
        config.memory_block_count =
            config.memory_usage_in_kib / quantum * quantum;
        config.segment_length =
            config.memory_block_count / quantum;
        config.lane_length =
            config.segment_length * 4u;
        if (config.memory_block_count < 8u ||
            config.segment_length < 2u) {
            std::cerr
                << "[!] Stronghold profile error: "
                   "invalid Argon2 geometry [!]\n";
            return 2;
        }
    }

    int device_count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&device_count),
            "query Stronghold devices", error)) {
        std::cerr << "[!] Stronghold runtime error: "
                  << error << " [!]\n";
        return 1;
    }
    std::vector<modeinfra::MemoryDeviceInfo> device_info;
    for (const int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr
                << "[!] Stronghold CLI error: unavailable "
                   "device " << device << " [!]\n";
            return 2;
        }
        metalDeviceProp properties{};
        if (!metal_ok(
                metalGetDeviceProperties(
                    &properties, device),
                "query Stronghold device properties",
                error)) {
            std::cerr
                << "[!] Stronghold runtime error: "
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
    const std::uint64_t scratch_per_candidate =
        static_cast<std::uint64_t>(
            config.memory_block_count) * 1024ull;
    const std::uint64_t one_candidate =
        scratch_per_candidate +
        kPasswordStride + 1u + 32u;
    modeinfra::MemorySpec memory_spec;
    modeinfra::MemoryBudget budget;
    if (!modeinfra::parse_memory_spec(
            options.memory, memory_spec, error) ||
        !modeinfra::resolve_memory_budget(
            memory_spec, device_info,
            one_candidate + kSaltStride, 0u,
            budget, error, kRuntimeReserve)) {
        std::cerr << "[!] Stronghold memory error: "
                  << error << " [!]\n";
        return 2;
    }
    std::uint64_t per_device_budget =
        budget.per_device_budget;
    if (!options.scratch_memory.empty()) {
        modeinfra::MemorySpec scratch_spec;
        modeinfra::MemoryBudget scratch_budget;
        if (!modeinfra::parse_memory_spec(
                options.scratch_memory,
                scratch_spec, error) ||
            !modeinfra::resolve_memory_budget(
                scratch_spec, device_info,
                one_candidate, 0u,
                scratch_budget, error, 0u)) {
            std::cerr
                << "[!] Stronghold KDF memory error: "
                << error << " [!]\n";
            return 2;
        }
        per_device_budget = std::min(
            per_device_budget,
            scratch_budget.per_device_budget);
    }
    std::uint64_t capacity_ceiling =
        per_device_budget / one_candidate;
    capacity_ceiling = std::min<std::uint64_t>(
        capacity_ceiling, options.batch);
    if (scratch_per_candidate != 0u) {
        capacity_ceiling = std::min<std::uint64_t>(
            capacity_ceiling,
            budget.max_buffer_length /
                scratch_per_candidate);
    }
    if (capacity_ceiling == 0u) {
        std::cerr
            << "[!] Stronghold memory error: selected budget "
               "cannot hold one KDF job [!]\n";
        return 2;
    }

    PasswordStream stream;
    if (!stream.initialize(options, error)) {
        std::cerr << "[!] Stronghold candidate error: "
                  << error << " [!]\n";
        return 2;
    }
    std::vector<DeviceBuffers> devices(
        options.devices.size());
    std::ofstream output;
    if (options.save || !options.output_path.empty()) {
        const std::string path =
            options.output_path.empty()
            ? "result.txt" : options.output_path;
        output.open(path, std::ios::app);
        if (!output) {
            std::cerr
                << "[!] Stronghold runtime error: cannot open '"
                << path << "' [!]\n";
            return 1;
        }
    }
    std::cout
        << "[!] Stronghold v2 snapshots: " << snapshots.size()
        << " | profile: " << lower_copy(options.profile)
        << " | targets: " << targets.size()
        << " unique/" << logical_targets
        << " logical | resident ceiling/device: "
        << capacity_ceiling
        << " | scratch/job: " << scratch_per_candidate
        << " [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "STRONGHOLD", modeinfra::ProgressUnit::Kdf,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(
        snapshots.size(), snapshots.size(), 0u);

    std::uint64_t allocated_bytes = 0u;
    std::uint64_t founds = 0u;
    std::uint64_t candidate_base = 0u;
    bool stop = false;
    int status = 0;
    const std::uint64_t combined_capacity =
        capacity_ceiling * devices.size();
    while (!stop) {
        std::vector<std::string> passwords;
        if (!stream.next(
                combined_capacity, passwords, error)) {
            std::cerr
                << "[!] Stronghold candidate error: "
                << error << " [!]\n";
            status = 2;
            break;
        }
        if (passwords.empty()) break;
        if (devices.front().capacity == 0u) {
            std::uint64_t resident =
                (passwords.size() + devices.size() - 1u) /
                devices.size();
            resident = std::min(
                resident, capacity_ceiling);
            bool allocated = false;
            while (!allocated) {
                allocated = true;
                for (std::size_t index = 0u;
                     index < devices.size(); ++index) {
                    if (!prepare_buffers(
                            options.devices[index],
                            resident,
                            scratch_per_candidate,
                            devices[index], error)) {
                        allocated = false;
                        break;
                    }
                }
                if (allocated) break;
                for (DeviceBuffers& buffers : devices) {
                    release_buffers(buffers);
                }
                if (memory_spec.kind !=
                        modeinfra::MemoryKind::Auto ||
                    resident == 1u) {
                    std::cerr
                        << "[!] Stronghold allocation error: "
                        << error << " [!]\n";
                    status = 1;
                    stop = true;
                    break;
                }
                resident =
                    std::max<std::uint64_t>(
                        1u, resident / 2u);
            }
            if (stop) break;
            allocated_bytes = 0u;
            for (const DeviceBuffers& buffers : devices) {
                allocated_bytes = saturating_add(
                    allocated_bytes, buffers.allocated);
            }
            progress.set_allocated_working_set(
                allocated_bytes);
            std::cout
                << "[!] Stronghold pipeline: resident/device "
                << resident << " | working set "
                << allocated_bytes << " bytes [!]\n";
        }
        std::size_t offset = 0u;
        while (offset < passwords.size() && !stop) {
            for (DeviceBuffers& buffers : devices) {
                if (offset >= passwords.size()) break;
                const std::size_t count =
                    std::min<std::size_t>(
                        buffers.capacity,
                        passwords.size() - offset);
                std::vector<
                    std::array<std::uint8_t, 32>> keys;
                std::uint64_t readback_ns = 0u;
                if (!derive_batch(
                        buffers, config, passwords,
                        offset, count, salt, keys,
                        readback_ns, error)) {
                    std::cerr
                        << "[!] Stronghold runtime error: "
                        << error << " [!]\n";
                    status = 1;
                    stop = true;
                    break;
                }
                std::uint64_t verifications = 0u;
                for (std::size_t key_index = 0u;
                     key_index < keys.size() && !stop;
                     ++key_index) {
                    for (Snapshot& snapshot : snapshots) {
                        if (snapshot.solved) continue;
                        ++verifications;
                        std::string matched_target;
                        std::array<std::uint8_t, 32>
                            plaintext_digest{};
                        if (!verify_snapshot(
                                keys[key_index], snapshot,
                                targets, matched_target,
                                plaintext_digest)) {
                            continue;
                        }
                        snapshot.solved = true;
                        ++founds;
                        if (hooks.credit_found) {
                            hooks.credit_found();
                        }
                        progress.set_founds(founds);
                        const std::string line =
                            "mode=stronghold"
                            " source=" + snapshot.source +
                            " candidate=" +
                            std::to_string(
                                candidate_base + offset +
                                key_index) +
                            " password=" +
                            quote_password(
                                passwords[
                                    offset + key_index]) +
                            " profile=" +
                            lower_copy(options.profile) +
                            " key=" +
                            hex_string(
                                keys[key_index].data(), 32u) +
                            " plaintext_sha256=" +
                            hex_string(
                                plaintext_digest.data(), 32u) +
                            " target=" + matched_target;
                        if (!options.silent) {
                            std::cout
                                << "[+] STRONGHOLD_FOUND "
                                << line << "\n";
                        }
                        if (output) {
                            output << line << "\n";
                            output.flush();
                        }
                        if (solved_snapshots(snapshots) >=
                            snapshots.size()) {
                            stop = true;
                            break;
                        }
                    }
                }
                progress.credit_completed(
                    count,
                    count *
                        std::max<std::uint32_t>(
                            1u, config.iterations),
                    verifications, readback_ns);
                if (hooks.credit_completed) {
                    hooks.credit_completed(count);
                }
                progress.set_targets(
                    snapshots.size(), snapshots.size(),
                    solved_snapshots(snapshots));
                offset += count;
                if (stop) break;
            }
        }
        candidate_base += passwords.size();
    }
    progress.end();
    for (DeviceBuffers& buffers : devices) {
        release_buffers(buffers);
    }
    if (status != 0) return status;
    std::cout
        << "[!] Stronghold search complete: found "
        << founds << " | solved "
        << solved_snapshots(snapshots) << "/"
        << snapshots.size() << " snapshots [!]\n";
    return 0;
}

}  // namespace stronghold_mode
