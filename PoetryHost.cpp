#include "KernelRuntime.h"
#include "PoetryHost.h"
#include "lib/hash/sha256.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <utility>

namespace {

enum class PoetryInputKind {
	Inline,
	File,
	Stdin
};

struct PoetryInputSpec {
	PoetryInputKind kind;
	std::string value;
};

std::vector<PoetryInputSpec> g_poetry_inputs;
bool g_poetry_mode = false;

bool is_flag_token(const char* value)
{
	return value != nullptr && value[0] == '-' && value[1] != 0;
}

std::string normalize_token(const std::string& input)
{
	std::string output = input;
	for (char& c : output) {
		if (static_cast<unsigned char>(c) >= 128U) {
			return input;
		}
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	return output;
}

std::vector<std::string> split_tokens(const std::string& phrase)
{
	std::vector<std::string> result;
	std::istringstream stream(phrase);
	std::string token;
	while (stream >> token) {
		result.emplace_back(std::move(token));
	}
	return result;
}

size_t levenshtein(const std::string& a, const std::string& b)
{
	const size_t n = a.size();
	const size_t m = b.size();
	if (n == 0) return m;
	if (m == 0) return n;

	std::vector<size_t> previous(m + 1U);
	std::vector<size_t> current(m + 1U);
	for (size_t j = 0; j <= m; ++j) previous[j] = j;
	for (size_t i = 1; i <= n; ++i) {
		current[0] = i;
		for (size_t j = 1; j <= m; ++j) {
			const size_t cost = a[i - 1U] == b[j - 1U] ? 0U : 1U;
			current[j] = std::min(
				std::min(previous[j] + 1U, current[j - 1U] + 1U),
				previous[j - 1U] + cost);
		}
		previous.swap(current);
	}
	return previous[m];
}

int find_best_word_id(
	const std::unordered_map<std::string, int>& exact,
	const std::string& token,
	size_t* distance)
{
	const auto found = exact.find(token);
	if (found != exact.end()) {
		if (distance != nullptr) *distance = 0;
		return found->second;
	}

	size_t best_distance = std::numeric_limits<size_t>::max();
	int best_id = -1;
	for (uint32_t i = 0; i < POETRY_WORD_COUNT; ++i) {
		const size_t candidate_distance = levenshtein(token, wordsOLD[i]);
		if (candidate_distance < best_distance) {
			best_distance = candidate_distance;
			best_id = static_cast<int>(i);
			if (best_distance == 1U) {
				break;
			}
		}
	}
	if (distance != nullptr) *distance = best_distance;
	return best_id;
}

bool build_dictionary(PoetryDictionaryHost& dictionary, std::string& error)
{
	dictionary = PoetryDictionaryHost{};
	dictionary.offsets.resize(POETRY_WORD_COUNT);
	dictionary.lengths.resize(POETRY_WORD_COUNT);

	std::string checksum_input;
	size_t maximum_length = 0;
	for (uint32_t i = 0; i < POETRY_WORD_COUNT; ++i) {
		if (wordsOLD[i] == nullptr) {
			error = "embedded Poetry dictionary contains a null entry";
			return false;
		}
		const size_t length = std::strlen(wordsOLD[i]);
		maximum_length = std::max(maximum_length, length);
		if (length != word_lengths[i] || length > std::numeric_limits<uint8_t>::max()) {
			error = "embedded Poetry dictionary length table does not match the words";
			return false;
		}
		if (dictionary.blob.size() > std::numeric_limits<uint16_t>::max()) {
			error = "embedded Poetry dictionary blob exceeds uint16 offsets";
			return false;
		}
		dictionary.offsets[i] = static_cast<uint16_t>(dictionary.blob.size());
		dictionary.lengths[i] = static_cast<uint8_t>(length);
		dictionary.blob.insert(dictionary.blob.end(), wordsOLD[i], wordsOLD[i] + length);
		if (i != 0) checksum_input.push_back('\n');
		checksum_input.append(wordsOLD[i], length);
	}
	if (maximum_length != 12U) {
		error = "embedded Poetry dictionary maximum word length is not 12";
		return false;
	}

	uint8_t digest[32];
	sha256(reinterpret_cast<uint8_t*>(&checksum_input[0]), checksum_input.size(), digest);
	static const uint8_t expected[32] = {
		0xb3, 0x29, 0xce, 0xa7, 0x82, 0xbd, 0xd8, 0xb1,
		0xde, 0x49, 0xbb, 0xb9, 0xfb, 0xde, 0xf9, 0xe8,
		0x23, 0x0e, 0x15, 0xeb, 0x08, 0xf0, 0xd7, 0x95,
		0x26, 0x13, 0x99, 0x22, 0x46, 0xc3, 0x8f, 0x96
	};
	if (std::memcmp(digest, expected, sizeof(expected)) != 0) {
		error = "embedded Poetry dictionary SHA-256 mismatch";
		return false;
	}
	return true;
}

bool append_input_lines(
	const PoetryInputSpec& input,
	std::vector<std::pair<std::string, std::pair<std::string, size_t>>>& lines,
	std::string& error)
{
	if (input.kind == PoetryInputKind::Inline) {
		lines.emplace_back(input.value, std::make_pair(std::string("command line"), 0U));
		return true;
	}

	std::istream* stream = &std::cin;
	std::ifstream file;
	std::string source = "stdin";
	if (input.kind == PoetryInputKind::File) {
		file.open(input.value, std::ios::in);
		if (!file.is_open()) {
			error = "cannot open Poetry input file: " + input.value;
			return false;
		}
		stream = &file;
		source = input.value;
	}

	std::string line;
	size_t line_number = 0;
	while (std::getline(*stream, line)) {
		++line_number;
		if (!split_tokens(line).empty()) {
			lines.emplace_back(std::move(line), std::make_pair(source, line_number));
		}
	}
	return true;
}

std::string combination_count_decimal(uint8_t wildcard_count)
{
	std::string count = "1";
	for (uint8_t exponent = 0; exponent < wildcard_count; ++exponent) {
		uint32_t carry = 0;
		for (auto digit = count.rbegin(); digit != count.rend(); ++digit) {
			const uint32_t product = static_cast<uint32_t>(*digit - '0') * POETRY_WORD_COUNT + carry;
			*digit = static_cast<char>('0' + product % 10U);
			carry = product / 10U;
		}
		while (carry != 0U) {
			count.insert(count.begin(), static_cast<char>('0' + carry % 10U));
			carry /= 10U;
		}
	}
	return count;
}

bool prepare_one(
	const std::string& phrase,
	const std::string& source,
	size_t line_number,
	const std::unordered_map<std::string, int>& exact,
	PoetryPreparedTemplate& output,
	std::string& error)
{
	std::vector<std::string> tokens = split_tokens(phrase);
	if (tokens.size() < 3U || tokens.size() > POETRY_MAX_WORDS || tokens.size() % 3U != 0U) {
		error = "Poetry phrase must contain 3, 6, 9, 12, 15, 18, 21, or 24 words";
		return false;
	}

	output = PoetryPreparedTemplate{};
	output.source = source;
	output.line_number = line_number;
	output.device.word_count = static_cast<uint8_t>(tokens.size());
	for (uint32_t i = 0; i < POETRY_MAX_WORDS; ++i) {
		output.device.words[i] = 0;
		output.device.wildcard_positions[i] = 0;
	}

	for (size_t i = 0; i < tokens.size(); ++i) {
		if (tokens[i] == "*") {
			const uint8_t wildcard = output.device.wildcard_count++;
			output.device.words[i] = POETRY_WILDCARD_ID;
			output.device.wildcard_positions[wildcard] = static_cast<uint8_t>(i);
			continue;
		}

		const std::string normalized = normalize_token(tokens[i]);
		size_t distance = 0;
		const int word_id = find_best_word_id(exact, normalized, &distance);
		if (word_id < 0) {
			error = "failed to find replacement for token: " + tokens[i];
			return false;
		}
		if (distance != 0U || normalized != wordsOLD[word_id]) {
			std::printf("[!] Recovery replace: '%s' -> '%s' [!]\n", tokens[i].c_str(), wordsOLD[word_id]);
		}
		tokens[i] = wordsOLD[word_id];
		output.device.words[i] = static_cast<uint16_t>(word_id);
	}
	output.combination_count = combination_count_decimal(output.device.wildcard_count);

	std::ostringstream joined;
	for (size_t i = 0; i < tokens.size(); ++i) {
		if (i != 0) joined << ' ';
		joined << tokens[i];
	}
	output.normalized_phrase = joined.str();
	return true;
}

} // namespace

bool poetry_cli_consume(int argc, char** argv, int& argument_index, std::string& error)
{
	g_poetry_mode = true;
	++argument_index;
	if (argument_index < argc && std::strcmp(argv[argument_index], "-i") == 0) {
		++argument_index;
		if (argument_index >= argc || is_flag_token(argv[argument_index])) {
			error = "-poetry -i requires a file path";
			return false;
		}
		g_poetry_inputs.push_back({ PoetryInputKind::File, argv[argument_index++] });
		return true;
	}
	if (argument_index < argc && !is_flag_token(argv[argument_index])) {
		g_poetry_inputs.push_back({ PoetryInputKind::Inline, argv[argument_index++] });
		return true;
	}
	g_poetry_inputs.push_back({ PoetryInputKind::Stdin, std::string() });
	return true;
}

bool poetry_mode_selected()
{
	return g_poetry_mode;
}

bool poetry_validate_cli_surface(int argc, char** argv, std::string& error)
{
	if (!g_poetry_mode) {
		error = "Poetry mode requires -poetry";
		return false;
	}
	static const char* const disallowed[] = {
		"-mnemonic", "-brain", "-minikey", "-minikeys", "-mini", "-priv", "-old", "-armory", "-root",
		"-entropy", "-seed", "-hmac", "-bip32", "-hexset", "-hex", "-seq", "-backward",
		"-both", "-prng", "-prng64", "-recovery", "-wordlist", "-comb", "-mutation",
		"-gen", "-mode", "-byte", "-shift", "-start", "-end", "-step", "-back", "-s", "-e",
		"-f", "-d", "-d-dot", "-d-type", "-pass", "-passbrute", "-space", "-rep", "-delete", "-all",
		"-size", "-sizes", "-pass_thread", "-der_thread",
		"-profanity", "-xp", "-keystore", "-walletdat", "-browservault",
		"-blockchainwallet", "-multibitwallet", "-bip38", "-ethpresale", "-androidwallet",
		"-slip39", "-aezeed", "-eth2validator", "-bisqwallet", "-dogechainwallet",
		"-stellarwallet", "-electrumwallet", "-exodusseco", "-bitcoinjwallet",
		"-multidogewallet", "-walletjs", "-walletscan", "-wallet-load-only", "-crypted"
	};
	for (int i = 1; i < argc; ++i) {
		for (const char* blocked : disallowed) {
			if (std::strcmp(argv[i], blocked) == 0) {
				error = std::string("option ") + blocked + " cannot be combined with -poetry";
				return false;
			}
		}
	}
	return true;
}

void poetry_print_help()
{
	std::fputs(R"HELP([!] MAIN MODE: -poetry  (Poetry brainwallet phrase recovery)
[!] ======================================================================
[!] Purpose:
[!] Restore Poetry brainwallet phrases and check their decoded 32-byte
[!] private keys against selected targets and filters on Metal GPUs.
[!]
[!] Enable / input:
[!] -poetry "TEMPLATE"              Add one final Poetry template.
[!]                                 Repeat -poetry for multiple templates.
[!] -poetry -i FILE                 Read one non-empty template per line.
[!] -poetry                         Read one non-empty template per line from STDIN.
[!]
[!] TEMPLATE:
[!] Exactly 3, 6, 9, 12, 15, 18, 21 or 24 whitespace-separated words.
[!] Use '*' for each unknown word. A phrase may contain only wildcards:
[!] "* * *". Wildcards are never added automatically.
[!] Fixed words are lowercased. Unknown words are replaced by the nearest
[!] entry from the embedded 1626-word Poetry dictionary.
[!]
[!] Finite mode:
[!] Without -random, all wildcard combinations are enumerated on the GPU.
[!] The rightmost '*' changes fastest. A phrase without '*' is checked once.
[!] Multiple templates are processed sequentially by all selected GPUs.
[!] The exact combination count is printed before every finite task.
[!]
[!] Random mode:
[!] -random                         Infinite GPU generation of wildcard words.
[!]                                 Without -n, requires exactly one template with at least one '*'.
[!] -n N                            With -random, generate exactly N random combinations
[!]                                 for each template, then switch to the next template.
[!]                                 After the last template, continue again from the first.
[!]                                 N is the total across all selected GPUs.
[!]
[!] Private-key processing:
[!] -round N                        Plus/minus rounds around every decoded key.
[!] -em                             Enable secp256k1 endomorphism.
[!] -scalar                         Treat the 32-byte key as ed25519 scalar.
[!] -LE                             With -scalar, input scalar is little-endian.
[!] -shash                          Treat the key as ed25519 hash(seed pre-clamp).
[!]
[!] GPU behavior:
[!] Wildcard generation, Poetry decoding and target checks run on GPU.
[!] Each Metal thread processes 32 phrases. Default secp256k1 table: 18 bits.
[!] Finite MultiGPU search uses one global non-overlapping base-1626 space.
[!]
[!] Result format:
[!] phrase:private:currency:payload
[!] payload is the hash by default and the formatted address with -save.
[!]
[!] Examples:
[!] METAL_CRYPTO_TOOLKIT -poetry "just just *" -c cus -bf btc.blf
[!] METAL_CRYPTO_TOOLKIT -poetry "* * *" -random -c e -xc eth.xor
[!] METAL_CRYPTO_TOOLKIT -poetry "just * *" -poetry "love * *" -random -n 1000000000 -c e -xc eth.xor
[!] METAL_CRYPTO_TOOLKIT -poetry -i templates.txt -device 0-3 -c cus -save
[!] METAL_CRYPTO_TOOLKIT -poetry < templates.txt
[!]
)HELP", stdout);
}

bool poetry_prepare_templates(
	bool random_mode,
	bool random_batch_enabled,
	std::vector<PoetryPreparedTemplate>& templates,
	PoetryDictionaryHost& dictionary,
	std::string& error)
{
	if (!g_poetry_mode || g_poetry_inputs.empty()) {
		error = "a -poetry input is required";
		return false;
	}
	if (std::count_if(g_poetry_inputs.begin(), g_poetry_inputs.end(), [](const PoetryInputSpec& input) {
		return input.kind == PoetryInputKind::Stdin;
	}) > 1) {
		error = "stdin may be selected by -poetry only once";
		return false;
	}
	if (!build_dictionary(dictionary, error)) {
		return false;
	}

	std::vector<std::pair<std::string, std::pair<std::string, size_t>>> lines;
	for (const PoetryInputSpec& input : g_poetry_inputs) {
		if (!append_input_lines(input, lines, error)) {
			return false;
		}
	}
	if (lines.empty()) {
		error = "no non-empty Poetry templates were provided";
		return false;
	}

	std::unordered_map<std::string, int> exact;
	exact.reserve(POETRY_WORD_COUNT);
	for (uint32_t i = 0; i < POETRY_WORD_COUNT; ++i) {
		exact.emplace(wordsOLD[i], static_cast<int>(i));
	}

	templates.clear();
	templates.reserve(lines.size());
	for (const auto& line : lines) {
		PoetryPreparedTemplate prepared;
		if (!prepare_one(line.first, line.second.first, line.second.second, exact, prepared, error)) {
			if (line.second.second != 0U) {
				error = line.second.first + ":" + std::to_string(line.second.second) + ": " + error;
			}
			return false;
		}
		templates.emplace_back(std::move(prepared));
	}

	if (random_mode) {
		if (!random_batch_enabled && templates.size() != 1U) {
			error = "-random with multiple Poetry templates requires -n N";
			return false;
		}
		for (PoetryPreparedTemplate& prepared : templates) {
			if (prepared.device.wildcard_count == 0U) {
				error = "-random requires at least one '*' in every Poetry template";
				return false;
			}
			prepared.device.random_mode = 1U;
		}
	}
	return true;
}

void poetry_reset_cli_for_tests()
{
	g_poetry_inputs.clear();
	g_poetry_mode = false;
}
