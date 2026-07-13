#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "lib/hash/sha256.h"

static const char* const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// encodeBase58: encodes Base58.
std::string encodeBase58(const uint8_t* bytes, size_t length) {
	if (!bytes || length == 0) {
		return std::string();
	}

	size_t zeros = 0;
	while (zeros < length && bytes[zeros] == 0) {
		++zeros;
	}

	std::vector<uint8_t> b58;
	b58.reserve((length - zeros) * 138 / 100 + 1);

	for (size_t i = zeros; i < length; ++i) {
		uint32_t carry = bytes[i];
		for (size_t j = 0; j < b58.size(); ++j) {
			uint32_t x = static_cast<uint32_t>(b58[j]) * 256u + carry;
			b58[j] = static_cast<uint8_t>(x % 58u);
			carry = x / 58u;
		}
		while (carry > 0) {
			b58.push_back(static_cast<uint8_t>(carry % 58u));
			carry /= 58u;
		}
	}

	std::string out;
	out.reserve(zeros + b58.size());
	out.append(zeros, '1');
	for (size_t i = 0; i < b58.size(); ++i) {
		out.push_back(ALPHABET[b58[b58.size() - 1 - i]]);
	}
	return out;
}

// hash160ToBase58: computes 160 to Base58.
std::string hash160ToBase58(const uint8_t hash160[20], uint8_t prefix) {
	uint8_t extended[25];
	extended[0] = prefix;
	memcpy(&extended[1], hash160, 20);

	uint8_t hash[32];
	sha256(extended, 21, hash);
	sha256(hash, 32, hash);
	memcpy(&extended[21], hash, 4);

	return encodeBase58(extended, 25);
}
