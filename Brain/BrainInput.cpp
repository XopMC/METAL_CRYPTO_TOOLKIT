#include "BrainInput.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <unordered_set>
#include <utility>

namespace brain_input {
namespace {

constexpr std::uintmax_t kResidentRightDictionaryLimit = 64u * 1024u * 1024u;
std::atomic<std::uint64_t> g_skipped_candidates{0u};

std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool read_dictionary_line(std::istream& stream, std::string& line) {
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            return true;
        }
    }
    return false;
}

int position_value(const char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'A' && value <= 'Z') return value - 'A' + 10;
    if (value >= 'a' && value <= 'z') return value - 'a' + 10;
    return -1;
}

bool parse_hex_nibble(const char value, std::uint8_t& out) {
    const int parsed = position_value(value);
    if (parsed < 0 || parsed > 15) return false;
    out = static_cast<std::uint8_t>(parsed);
    return true;
}

bool read_rule_literal(const std::string& source,
                       std::size_t& offset,
                       std::uint8_t& value,
                       std::string& error) {
    if (offset >= source.size()) {
        error = "rule operator is missing its character argument";
        return false;
    }
    if (source[offset] != '\\') {
        value = static_cast<std::uint8_t>(
            static_cast<unsigned char>(source[offset++]));
        return true;
    }
    if (offset + 3u >= source.size() || source[offset + 1u] != 'x') {
        error = "rule escapes must use \\\\xNN";
        return false;
    }
    std::uint8_t high = 0u;
    std::uint8_t low = 0u;
    if (!parse_hex_nibble(source[offset + 2u], high) ||
        !parse_hex_nibble(source[offset + 3u], low)) {
        error = "rule contains an invalid \\\\xNN escape";
        return false;
    }
    value = static_cast<std::uint8_t>((high << 4u) | low);
    offset += 4u;
    return true;
}

bool read_rule_position(const std::string& source,
                        std::size_t& offset,
                        std::uint8_t& value,
                        std::string& error) {
    if (offset >= source.size()) {
        error = "rule operator is missing its position argument";
        return false;
    }
    const int parsed = position_value(source[offset++]);
    if (parsed < 0) {
        error = "rule positions must use base-36 0-9/A-Z";
        return false;
    }
    value = static_cast<std::uint8_t>(parsed);
    return true;
}

bool compile_rule(const std::string& source,
                  CompiledRule& compiled,
                  std::string& error) {
    compiled = CompiledRule{};
    compiled.source = source;
    std::size_t offset = 0u;
    while (offset < source.size()) {
        RuleOperation operation;
        const char command = source[offset++];
        switch (command) {
            case ':': operation.code = RuleOperation::Code::Noop; break;
            case 'l': operation.code = RuleOperation::Code::Lower; break;
            case 'u': operation.code = RuleOperation::Code::Upper; break;
            case 'c': operation.code = RuleOperation::Code::Capitalize; break;
            case 'C': operation.code = RuleOperation::Code::InvertCapitalize; break;
            case 't': operation.code = RuleOperation::Code::ToggleAll; break;
            case 'r': operation.code = RuleOperation::Code::Reverse; break;
            case 'd': operation.code = RuleOperation::Code::Duplicate; break;
            case 'f': operation.code = RuleOperation::Code::Reflect; break;
            case 'q': operation.code = RuleOperation::Code::DuplicateCharacters; break;
            case '{': operation.code = RuleOperation::Code::RotateLeft; break;
            case '}': operation.code = RuleOperation::Code::RotateRight; break;
            case '[': operation.code = RuleOperation::Code::DeleteFirst; break;
            case ']': operation.code = RuleOperation::Code::DeleteLast; break;
            case 'k': operation.code = RuleOperation::Code::SwapFirst; break;
            case 'K': operation.code = RuleOperation::Code::SwapLast; break;
            case '$':
                operation.code = RuleOperation::Code::Append;
                if (!read_rule_literal(source, offset, operation.first, error)) return false;
                break;
            case '^':
                operation.code = RuleOperation::Code::Prepend;
                if (!read_rule_literal(source, offset, operation.first, error)) return false;
                break;
            case 'T':
                operation.code = RuleOperation::Code::ToggleAt;
                if (!read_rule_position(source, offset, operation.first, error)) return false;
                break;
            case 'D':
                operation.code = RuleOperation::Code::DeleteAt;
                if (!read_rule_position(source, offset, operation.first, error)) return false;
                break;
            case '\'':
                operation.code = RuleOperation::Code::Truncate;
                if (!read_rule_position(source, offset, operation.first, error)) return false;
                break;
            case 'x':
                operation.code = RuleOperation::Code::Extract;
                if (!read_rule_position(source, offset, operation.first, error) ||
                    !read_rule_position(source, offset, operation.second, error)) return false;
                break;
            case 's':
                operation.code = RuleOperation::Code::Substitute;
                if (!read_rule_literal(source, offset, operation.first, error) ||
                    !read_rule_literal(source, offset, operation.second, error)) return false;
                break;
            case '@':
                operation.code = RuleOperation::Code::Purge;
                if (!read_rule_literal(source, offset, operation.first, error)) return false;
                break;
            case 'i':
                operation.code = RuleOperation::Code::Insert;
                if (!read_rule_position(source, offset, operation.first, error) ||
                    !read_rule_literal(source, offset, operation.second, error)) return false;
                break;
            case 'o':
                operation.code = RuleOperation::Code::Overwrite;
                if (!read_rule_position(source, offset, operation.first, error) ||
                    !read_rule_literal(source, offset, operation.second, error)) return false;
                break;
            case 'z':
                operation.code = RuleOperation::Code::DuplicateFirst;
                if (!read_rule_position(source, offset, operation.first, error)) return false;
                break;
            case 'Z':
                operation.code = RuleOperation::Code::DuplicateLast;
                if (!read_rule_position(source, offset, operation.first, error)) return false;
                break;
            case 'p':
                operation.code = RuleOperation::Code::DuplicateN;
                if (!read_rule_position(source, offset, operation.first, error)) return false;
                break;
            default:
                error = "unsupported rule command '" + std::string(1u, command) + "'";
                return false;
        }
        compiled.operations.push_back(operation);
        if (compiled.operations.size() > 64u) {
            error = "one rule may contain at most 64 operations";
            return false;
        }
    }
    if (compiled.operations.empty()) {
        compiled.operations.push_back(RuleOperation{});
    }
    return true;
}

bool append_bounded(std::string& value, const std::string& suffix) {
    if (suffix.size() > kMaximumCandidateBytes - value.size()) return false;
    value.append(suffix);
    return true;
}

bool repeat_bounded(std::string& value, const std::string& fragment, std::size_t count) {
    if (fragment.empty() || count == 0u) return true;
    if (fragment.size() > (kMaximumCandidateBytes - value.size()) / count) return false;
    for (std::size_t i = 0u; i < count; ++i) value.append(fragment);
    return true;
}

char ascii_lower(const char value) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
}

char ascii_upper(const char value) {
    return static_cast<char>(std::toupper(static_cast<unsigned char>(value)));
}

char ascii_toggle(const char value) {
    const unsigned char current = static_cast<unsigned char>(value);
    if (std::islower(current) != 0) return ascii_upper(value);
    if (std::isupper(current) != 0) return ascii_lower(value);
    return value;
}

bool apply_rule(const std::string& base,
                const CompiledRule& rule,
                std::string& result) {
    if (base.size() > kMaximumCandidateBytes) return false;
    result = base;
    for (const RuleOperation& operation : rule.operations) {
        const std::size_t first = operation.first;
        const std::size_t second = operation.second;
        switch (operation.code) {
            case RuleOperation::Code::Noop:
                break;
            case RuleOperation::Code::Lower:
                std::transform(result.begin(), result.end(), result.begin(), ascii_lower);
                break;
            case RuleOperation::Code::Upper:
                std::transform(result.begin(), result.end(), result.begin(), ascii_upper);
                break;
            case RuleOperation::Code::Capitalize:
                std::transform(result.begin(), result.end(), result.begin(), ascii_lower);
                if (!result.empty()) result[0] = ascii_upper(result[0]);
                break;
            case RuleOperation::Code::InvertCapitalize:
                std::transform(result.begin(), result.end(), result.begin(), ascii_upper);
                if (!result.empty()) result[0] = ascii_lower(result[0]);
                break;
            case RuleOperation::Code::ToggleAll:
                std::transform(result.begin(), result.end(), result.begin(), ascii_toggle);
                break;
            case RuleOperation::Code::Reverse:
                std::reverse(result.begin(), result.end());
                break;
            case RuleOperation::Code::Duplicate: {
                const std::string original = result;
                if (!append_bounded(result, original)) return false;
                break;
            }
            case RuleOperation::Code::DuplicateN: {
                const std::string original = result;
                if (!repeat_bounded(result, original, first)) return false;
                break;
            }
            case RuleOperation::Code::Reflect: {
                std::string reflected = result;
                std::reverse(reflected.begin(), reflected.end());
                if (!append_bounded(result, reflected)) return false;
                break;
            }
            case RuleOperation::Code::DuplicateCharacters: {
                if (result.size() > kMaximumCandidateBytes / 2u) return false;
                std::string doubled;
                doubled.reserve(result.size() * 2u);
                for (const char value : result) {
                    doubled.push_back(value);
                    doubled.push_back(value);
                }
                result.swap(doubled);
                break;
            }
            case RuleOperation::Code::RotateLeft:
                if (!result.empty()) std::rotate(result.begin(), result.begin() + 1, result.end());
                break;
            case RuleOperation::Code::RotateRight:
                if (!result.empty()) std::rotate(result.begin(), result.end() - 1, result.end());
                break;
            case RuleOperation::Code::DeleteFirst:
                if (result.empty()) return false;
                result.erase(result.begin());
                break;
            case RuleOperation::Code::DeleteLast:
                if (result.empty()) return false;
                result.pop_back();
                break;
            case RuleOperation::Code::SwapFirst:
                if (result.size() < 2u) return false;
                std::swap(result[0], result[1]);
                break;
            case RuleOperation::Code::SwapLast:
                if (result.size() < 2u) return false;
                std::swap(result[result.size() - 1u], result[result.size() - 2u]);
                break;
            case RuleOperation::Code::Append:
                if (result.size() >= kMaximumCandidateBytes) return false;
                result.push_back(static_cast<char>(operation.first));
                break;
            case RuleOperation::Code::Prepend:
                if (result.size() >= kMaximumCandidateBytes) return false;
                result.insert(result.begin(), static_cast<char>(operation.first));
                break;
            case RuleOperation::Code::ToggleAt:
                if (first >= result.size()) return false;
                result[first] = ascii_toggle(result[first]);
                break;
            case RuleOperation::Code::DeleteAt:
                if (first >= result.size()) return false;
                result.erase(result.begin() + static_cast<std::ptrdiff_t>(first));
                break;
            case RuleOperation::Code::Truncate:
                if (first > result.size()) return false;
                result.resize(first);
                break;
            case RuleOperation::Code::Extract:
                if (first > result.size() || second > result.size() - first) return false;
                result = result.substr(first, second);
                break;
            case RuleOperation::Code::Substitute:
                std::replace(result.begin(), result.end(),
                             static_cast<char>(operation.first),
                             static_cast<char>(operation.second));
                break;
            case RuleOperation::Code::Purge:
                result.erase(std::remove(result.begin(), result.end(),
                                         static_cast<char>(operation.first)),
                             result.end());
                break;
            case RuleOperation::Code::Insert:
                if (first > result.size() || result.size() >= kMaximumCandidateBytes) return false;
                result.insert(result.begin() + static_cast<std::ptrdiff_t>(first),
                              static_cast<char>(operation.second));
                break;
            case RuleOperation::Code::Overwrite:
                if (first >= result.size()) return false;
                result[first] = static_cast<char>(operation.second);
                break;
            case RuleOperation::Code::DuplicateFirst:
                if (result.empty() ||
                    first > kMaximumCandidateBytes - result.size()) return false;
                result.insert(0u, first, result.front());
                break;
            case RuleOperation::Code::DuplicateLast:
                if (result.empty() ||
                    first > kMaximumCandidateBytes - result.size()) return false;
                result.append(first, result.back());
                break;
        }
    }
    return result.size() <= kMaximumCandidateBytes;
}

bool compose_candidate(const std::string& left,
                       const std::string& separator,
                       const std::string& right,
                       std::string& out) {
    if (left.size() > kMaximumCandidateBytes ||
        separator.size() > kMaximumCandidateBytes - left.size() ||
        right.size() > kMaximumCandidateBytes - left.size() - separator.size()) {
        return false;
    }
    out.clear();
    out.reserve(left.size() + separator.size() + right.size());
    out.append(left);
    out.append(separator);
    out.append(right);
    return true;
}

} // namespace

bool resolve_profile(const std::string& value,
                     ProfileSelection& selection,
                     std::string& error) {
    const std::string profile = lower_copy(value);
    selection = ProfileSelection{};
    if (profile == "sha256" || profile == "brainflayer-sha256" ||
        profile == "brainwallet.org" || profile == "bitaddress" ||
        profile == "bitcoinjs") {
        selection.canonical_name =
            (profile == "sha256") ? "sha256" : profile;
        return true;
    }
    if (profile == "sha256d") {
        selection.iterations = {2u};
        selection.canonical_name = profile;
        return true;
    }
    if (profile == "sha256-hex") {
        selection.iterations = {2u};
        selection.hexadecimal_iterations = true;
        selection.canonical_name = profile;
        return true;
    }
    if (profile == "sha3-256" || profile == "sha3-256d") {
        selection.mode = 1u;
        selection.iterations = {(profile.back() == 'd') ? 2u : 1u};
        selection.canonical_name = profile;
        return true;
    }
    if (profile == "keccak256" || profile == "keccak256d") {
        selection.mode = 2u;
        selection.iterations = {(profile.back() == 'd') ? 2u : 1u};
        selection.canonical_name = profile;
        return true;
    }
    if (profile == "blake2b-256" || profile == "blake2b-256d") {
        selection.mode = 3u;
        selection.iterations = {(profile.back() == 'd') ? 2u : 1u};
        selection.canonical_name = profile;
        return true;
    }
    if (profile == "raw") {
        selection.mode = 4u;
        selection.canonical_name = profile;
        return true;
    }
    error = "unsupported -brain-profile '" + value + "'";
    return false;
}

bool prepare_configuration(const std::string& rules_path,
                           const std::string& combine_path,
                           const std::string& combine_mode,
                           const bool insert_space,
                           Configuration& configuration,
                           std::string& error) {
    configuration = Configuration{};
    configuration.rules_path = rules_path;
    configuration.combine_path = combine_path;
    configuration.separator = insert_space ? " " : "";

    const std::string order = lower_copy(combine_mode.empty() ? "lr" : combine_mode);
    if (order == "lr" || order == "left-right") {
        configuration.combine_order = CombineOrder::LeftRight;
    } else if (order == "rl" || order == "right-left") {
        configuration.combine_order = CombineOrder::RightLeft;
    } else if (order == "both") {
        configuration.combine_order = CombineOrder::Both;
    } else {
        error = "-brain-combine-mode must be lr, rl, or both";
        return false;
    }

    if (rules_path.empty()) {
        CompiledRule passthrough;
        passthrough.source = ":";
        passthrough.operations.push_back(RuleOperation{});
        configuration.rules.push_back(std::move(passthrough));
    } else {
        std::ifstream rules(rules_path, std::ios::binary);
        if (!rules) {
            error = "failed to open -brain-rules file '" + rules_path + "'";
            return false;
        }
        std::unordered_set<std::string> seen;
        std::string line;
        std::size_t line_number = 0u;
        while (std::getline(rules, line)) {
            ++line_number;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line.front() == '#') continue;
            if (!seen.emplace(line).second) continue;
            CompiledRule compiled;
            std::string parse_error;
            if (!compile_rule(line, compiled, parse_error)) {
                error = "invalid rule at " + rules_path + ":" +
                        std::to_string(line_number) + ": " + parse_error;
                return false;
            }
            configuration.rules.push_back(std::move(compiled));
            if (configuration.rules.size() > 1'000'000u) {
                error = "-brain-rules contains more than 1000000 unique rules";
                return false;
            }
        }
        if (configuration.rules.empty()) {
            error = "-brain-rules contains no executable rules";
            return false;
        }
    }

    if (!combine_path.empty()) {
        std::error_code filesystem_error;
        const std::uintmax_t size =
            std::filesystem::file_size(combine_path, filesystem_error);
        if (filesystem_error) {
            error = "failed to inspect -brain-combine file '" + combine_path + "'";
            return false;
        }
        std::ifstream right(combine_path, std::ios::binary);
        if (!right) {
            error = "failed to open -brain-combine file '" + combine_path + "'";
            return false;
        }
        if (size <= kResidentRightDictionaryLimit) {
            std::string line;
            while (read_dictionary_line(right, line)) {
                if (line.size() <= kMaximumCandidateBytes) {
                    configuration.resident_right_words.push_back(line);
                }
            }
            if (configuration.resident_right_words.empty()) {
                error = "-brain-combine file contains no usable words";
                return false;
            }
            configuration.right_dictionary_resident = true;
        } else {
            std::string probe;
            if (!read_dictionary_line(right, probe)) {
                error = "-brain-combine file contains no usable words";
                return false;
            }
            configuration.right_dictionary_resident = false;
        }
    }
    return true;
}

struct Expander::State {
    explicit State(const Configuration& source) : configuration(source) {}

    const Configuration& configuration;
    std::string base;
    std::string right;
    std::string composed;
    std::ifstream right_stream;
    std::size_t resident_right_index = 0u;
    std::size_t rule_index = 0u;
    unsigned direction_index = 0u;
    bool base_active = false;
    bool right_active = false;
    bool composed_active = false;

    void begin_base(std::string value) {
        base = std::move(value);
        base_active = true;
        right_active = false;
        composed_active = false;
        resident_right_index = 0u;
        rule_index = 0u;
        direction_index = 0u;
        if (!configuration.combine_path.empty() &&
            !configuration.right_dictionary_resident) {
            right_stream.close();
            right_stream.clear();
            right_stream.open(configuration.combine_path, std::ios::binary);
        }
    }

    bool next_right(std::string& error) {
        if (configuration.combine_path.empty()) {
            if (right_active) return false;
            right.clear();
            right_active = true;
            return true;
        }
        if (configuration.right_dictionary_resident) {
            while (resident_right_index < configuration.resident_right_words.size()) {
                right = configuration.resident_right_words[resident_right_index++];
                if (!right.empty()) {
                    right_active = true;
                    return true;
                }
            }
            return false;
        }
        if (!right_stream) {
            error = "failed to reopen -brain-combine file '" +
                    configuration.combine_path + "'";
            return false;
        }
        while (read_dictionary_line(right_stream, right)) {
            if (right.size() <= kMaximumCandidateBytes) {
                right_active = true;
                return true;
            }
            g_skipped_candidates.fetch_add(1u, std::memory_order_relaxed);
        }
        return false;
    }

    bool next_composed(std::string& error) {
        while (base_active) {
            if (!right_active && !next_right(error)) {
                base_active = false;
                return false;
            }
            if (!error.empty()) return false;

            const CombineOrder order = configuration.combine_order;
            const bool no_combine = configuration.combine_path.empty();
            bool valid = false;
            if (no_combine) {
                if (direction_index > 0u) {
                    right_active = false;
                    continue;
                }
                composed = base;
                valid = composed.size() <= kMaximumCandidateBytes;
                ++direction_index;
            } else if (order == CombineOrder::LeftRight ||
                       (order == CombineOrder::Both && direction_index == 0u)) {
                valid = compose_candidate(
                    base, configuration.separator, right, composed);
                ++direction_index;
            } else {
                valid = compose_candidate(
                    right, configuration.separator, base, composed);
                ++direction_index;
            }

            const unsigned direction_count =
                (order == CombineOrder::Both && !no_combine) ? 2u : 1u;
            if (direction_index >= direction_count) {
                direction_index = 0u;
                right_active = false;
                if (no_combine) {
                    base_active = false;
                }
            }
            if (!valid) {
                g_skipped_candidates.fetch_add(1u, std::memory_order_relaxed);
                continue;
            }
            composed_active = true;
            rule_index = 0u;
            return true;
        }
        return false;
    }
};

Expander::Expander(const Configuration& configuration)
    : state_(std::make_unique<State>(configuration)) {}

Expander::~Expander() = default;

bool Expander::next(const ReadBase& read_base,
                    std::string& candidate,
                    std::string& error) {
    error.clear();
    for (;;) {
        if (state_->composed_active) {
            while (state_->rule_index < state_->configuration.rules.size()) {
                const CompiledRule& rule =
                    state_->configuration.rules[state_->rule_index++];
                if (apply_rule(state_->composed, rule, candidate)) {
                    return true;
                }
                g_skipped_candidates.fetch_add(1u, std::memory_order_relaxed);
            }
            state_->composed_active = false;
        }
        if (state_->next_composed(error)) {
            continue;
        }
        if (!error.empty()) return false;

        std::string base;
        if (!read_base(base)) return false;
        if (base.empty()) continue;
        if (base.size() > kMaximumCandidateBytes) {
            g_skipped_candidates.fetch_add(1u, std::memory_order_relaxed);
            continue;
        }
        state_->begin_base(std::move(base));
    }
}

std::uint64_t skipped_candidates() {
    return g_skipped_candidates.load(std::memory_order_relaxed);
}

void reset_skipped_candidates() {
    g_skipped_candidates.store(0u, std::memory_order_relaxed);
}

} // namespace brain_input
