#ifndef METAL_CRYPTO_BRAIN_INPUT_H
#define METAL_CRYPTO_BRAIN_INPUT_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace brain_input {

constexpr std::size_t kMaximumCandidateBytes = 512u;

struct ProfileSelection {
    std::uint8_t mode = 0u;
    std::vector<std::uint32_t> iterations{1u};
    bool hexadecimal_iterations = false;
    std::string canonical_name = "sha256";
};

bool resolve_profile(const std::string& value,
                     ProfileSelection& selection,
                     std::string& error);

enum class CombineOrder {
    LeftRight,
    RightLeft,
    Both,
};

struct RuleOperation {
    enum class Code : std::uint8_t {
        Noop,
        Lower,
        Upper,
        Capitalize,
        InvertCapitalize,
        ToggleAll,
        Reverse,
        Duplicate,
        DuplicateN,
        Reflect,
        DuplicateCharacters,
        RotateLeft,
        RotateRight,
        DeleteFirst,
        DeleteLast,
        SwapFirst,
        SwapLast,
        Append,
        Prepend,
        ToggleAt,
        DeleteAt,
        Truncate,
        Extract,
        Substitute,
        Purge,
        Insert,
        Overwrite,
        DuplicateFirst,
        DuplicateLast,
    };

    Code code = Code::Noop;
    std::uint8_t first = 0u;
    std::uint8_t second = 0u;
};

struct CompiledRule {
    std::string source;
    std::vector<RuleOperation> operations;
};

struct Configuration {
    std::vector<CompiledRule> rules;
    std::vector<std::string> resident_right_words;
    std::string rules_path;
    std::string combine_path;
    CombineOrder combine_order = CombineOrder::LeftRight;
    std::string separator;
    bool right_dictionary_resident = false;

    bool expands_candidates() const {
        return !rules_path.empty() || !combine_path.empty();
    }
};

bool prepare_configuration(const std::string& rules_path,
                           const std::string& combine_path,
                           const std::string& combine_mode,
                           bool insert_space,
                           Configuration& configuration,
                           std::string& error);

class Expander {
public:
    using ReadBase = std::function<bool(std::string&)>;

    explicit Expander(const Configuration& configuration);
    ~Expander();

    Expander(const Expander&) = delete;
    Expander& operator=(const Expander&) = delete;

    bool next(const ReadBase& read_base,
              std::string& candidate,
              std::string& error);

private:
    struct State;
    std::unique_ptr<State> state_;
};

std::uint64_t skipped_candidates();
void reset_skipped_candidates();

} // namespace brain_input

#endif
