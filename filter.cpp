#include "filter.h"
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cctype>

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
#error "No filesystem support"
#endif

const std::vector<std::string> exts_xc = { ".xor_c", ".xc" };
const std::vector<std::string> exts_xu = { ".xor_u", ".xu" };
const std::vector<std::string> exts_xb = { ".blf" };
const std::vector<std::string> exts_xuc = { ".xor_uc", ".xuc" };
const std::vector<std::string> exts_xh = { ".xor_hc", ".xhc" };

// iequals: performs iequals.
static bool iequals(const std::string& a, const std::string& b) {
	if (a.size() != b.size()) {
		return false;
	}
	for (size_t i = 0; i < a.size(); ++i) {
		if (std::tolower(static_cast<unsigned char>(a[i])) !=
			std::tolower(static_cast<unsigned char>(b[i]))) {
			return false;
		}
	}
	return true;
}

// Returns true when the file extension matches one of allowed extensions (case-insensitive).
static bool has_allowed_ext_ci(const fs::path& p, const std::vector<std::string>& exts) {
	const std::string eext = p.extension().string();
	for (const auto& ext : exts) {
		if (iequals(eext, ext)) return true;
	}
	return false;
}

// Returns true if the file path is already in the destination list.
static bool already_added(const std::vector<std::string>& files, const std::string& path) {
	return std::find(files.begin(), files.end(), path) != files.end();
}


// Adds a single filter file or all matching files from a directory into outFiles.
void add_filter_path(const char* p,
	std::vector<std::string>& outFiles,
	bool& useFlag,
	const std::vector<std::string>& allowedExts,
	bool recursive)
{
	std::error_code ec;



	const fs::path& pth(p);

	if (!fs::exists(pth, ec)) {
		std::cerr << "[-] path not found: " << pth.string() << "\n";
		return;
	}

	if (fs::is_directory(pth, ec)) {
		auto add_if_match = [&](const fs::directory_entry& e) {
			if (!e.is_regular_file(ec)) return;
			if (!has_allowed_ext_ci(e.path(), allowedExts)) return;

			const std::string s = e.path().string();
			if (!already_added(outFiles, s)) {
				outFiles.push_back(s);
				std::cerr << "[!] " << s << " Added [!]\n";
			}
			};

		if (recursive) {
			for (const auto& e : fs::recursive_directory_iterator(
				p, fs::directory_options::skip_permission_denied, ec))
			{
				if (ec) break;
				add_if_match(e);
			}
		}
		else {
			for (const auto& e : fs::directory_iterator(
				p, fs::directory_options::skip_permission_denied, ec))
			{
				if (ec) break;
				add_if_match(e);
			}
		}

		if (!outFiles.empty()) useFlag = true;
		return;
	}

	const std::string s = pth.string();
	if (!already_added(outFiles, s)) {
		outFiles.push_back(s);
		std::cerr << "[!] " << s << " Added [!]\n";
	}
	useFlag = true;
}

int bloom_count = 0;
int xor_count = 0;

size_t     size[25] = { 0 };
size_t     arrayLength[25] = { 0 };
size_t     segmentCount[25] = { 0 };
size_t     segmentCountLength[25] = { 0 };
size_t     segmentLength[25] = { 0 };
size_t     segmentLengthMask[25] = { 0 };
uint32_t* fingerprints[25];

unsigned char* blooms[100];

uint64_t Seed_cpu = 0;

// Checks whether all 20 derived Bloom bit positions for HASH160 are set.
bool bloom_chk_hash160_cpu(const unsigned char* bloom, const uint32_t* h) {
	unsigned int t;
	t = BH00(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH01(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH02(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH03(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH04(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH05(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH06(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH07(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH08(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH09(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH10(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH11(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH12(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH13(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH14(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH15(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH16(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH17(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH18(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	t = BH19(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
	return 1;
}

// Sets all 20 derived Bloom bit positions for HASH160.
void bloom_set_hash160(unsigned char* bloom, uint32_t* h) {
	unsigned int t;
	t = BH00(h); BLOOM_SET_BIT(t);
	t = BH01(h); BLOOM_SET_BIT(t);
	t = BH02(h); BLOOM_SET_BIT(t);
	t = BH03(h); BLOOM_SET_BIT(t);
	t = BH04(h); BLOOM_SET_BIT(t);
	t = BH05(h); BLOOM_SET_BIT(t);
	t = BH06(h); BLOOM_SET_BIT(t);
	t = BH07(h); BLOOM_SET_BIT(t);
	t = BH08(h); BLOOM_SET_BIT(t);
	t = BH09(h); BLOOM_SET_BIT(t);
	t = BH10(h); BLOOM_SET_BIT(t);
	t = BH11(h); BLOOM_SET_BIT(t);
	t = BH12(h); BLOOM_SET_BIT(t);
	t = BH13(h); BLOOM_SET_BIT(t);
	t = BH14(h); BLOOM_SET_BIT(t);
	t = BH15(h); BLOOM_SET_BIT(t);
	t = BH16(h); BLOOM_SET_BIT(t);
	t = BH17(h); BLOOM_SET_BIT(t);
	t = BH18(h); BLOOM_SET_BIT(t);
	t = BH19(h); BLOOM_SET_BIT(t);
}

// SplitMix64 PRNG step used to initialize a deterministic seed for XOR filter hashing.
uint64_t rng_splitmix64_cpu(uint64_t* seed)
{
	uint64_t z = (*seed += UINT64_C(0x9E3779B97F4A7C15));
	z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
	return z ^ (z >> 31);
}

// Loads XOR filters into shared memory and prepares CPU-side lookup arrays.
bool loadXorFilters(const std::vector<std::string>& xorFiles)
{
	uint64_t rng_counter = 0x726b2b9d438b9d4d;
	Seed_cpu = rng_splitmix64_cpu(&rng_counter);

	if (xorFiles.size() > 25) {
		std::cerr << "[!] Too many xor files, maximum supported is 25." << std::endl;
		return false;
	}

	for (size_t i = 0; i < xorFiles.size(); ++i) {
		const auto& xorFile = xorFiles[i];
		fprintf(stderr, "[!] Initializing CPU XOR Filter [file=%s]\n", xorFile.c_str());
		std::string raw = xorFiles[i];
		size_t pos = raw.find_last_of("/\\");
		if (pos != std::string::npos) {
			raw = raw.substr(pos + 1);
		}
		std::ifstream in(xorFile, std::ios::binary);
		if (!in.is_open()) {
			std::cerr << "[!] Failed to open CPU XOR filter '" << xorFile << "'." << std::endl;
			return false;
		}

		in.read(reinterpret_cast<char*>(&size[i]), sizeof(size_t));
		in.read(reinterpret_cast<char*>(&arrayLength[i]), sizeof(size_t));
		in.read(reinterpret_cast<char*>(&segmentCount[i]), sizeof(size_t));
		in.read(reinterpret_cast<char*>(&segmentCountLength[i]), sizeof(size_t));
		in.read(reinterpret_cast<char*>(&segmentLength[i]), sizeof(size_t));
		in.read(reinterpret_cast<char*>(&segmentLengthMask[i]), sizeof(size_t));
		if (!in.good()) {
			std::cerr << "[!] Failed to read XOR filter header '" << xorFile << "'." << std::endl;
			in.close();
			return false;
		}
		uint64_t XOR_SIZE = sizeof(uint32_t) * arrayLength[i];

		int shm_fd = shm_open(
			raw.c_str(),
			O_CREAT | O_RDWR,
			0666
		);
		if (shm_fd == -1) {
			std::cerr << "[!] Failed to shm_open '" << raw
				<< "'. Error: " << std::endl;
			in.close();
			return false;
		}

		if (ftruncate(shm_fd, XOR_SIZE) == -1) {
			std::cerr << "[!] Failed to ftruncate '" << raw
				<< "'. Error: " << std::endl;
			close(shm_fd);
			in.close();
			return false;
		}

		uint32_t* shm_ptr = static_cast<uint32_t*>(mmap(
			NULL,
			XOR_SIZE,
			PROT_READ | PROT_WRITE,
			MAP_SHARED,
			shm_fd,
			0
		));
		if (shm_ptr == MAP_FAILED) {
			std::cerr << "[!] Failed to mmap '" << raw
				<< "'. Error: " << std::endl;
			close(shm_fd);
			in.close();
			return false;
		}

		in.read(reinterpret_cast<char*>(shm_ptr), XOR_SIZE);

		fingerprints[i] = shm_ptr;
		close(shm_fd);


		in.close();
		xor_count++;
	}
	return true;
}

// loadBloomFiltersIntoSharedMemory: loads bloom filters into shared memory.
bool loadBloomFiltersIntoSharedMemory(const std::vector<std::string>& bloomFiles) {
	if (bloomFiles.size() > 100) {
		std::cerr << "[!] Too many bloom files, maximum supported is 100." << std::endl;
		return false;
	}

	for (size_t i = 0; i < bloomFiles.size(); ++i) {
		const auto& bloomFile = bloomFiles[i];

		int fd = open(bloomFile.c_str(), O_RDONLY);
		if (fd == -1) {
			std::cerr << "[!] Failed to open '" << bloomFile << "'." << std::endl;
			return false;
		}

		struct stat st;
		if (fstat(fd, &st) != 0) {
			std::cerr << "[!] fstat failed for '" << bloomFile << "'." << std::endl;
			close(fd);
			return false;
		}
		if ((size_t)st.st_size < BLOOM_SIZE) {
			std::cerr << "[!] File too small for bloom '" << bloomFile << "'." << std::endl;
			close(fd);
			return false;
		}

		unsigned char* mmap_ptr = static_cast<unsigned char*>(mmap(
			NULL,
			BLOOM_SIZE,
			PROT_READ,
			MAP_SHARED
#ifdef MAP_POPULATE
			| MAP_POPULATE
#endif
			,
			fd,
			0
		));

		if (mmap_ptr == MAP_FAILED) {
			std::cerr << "[!] Failed to mmap '" << bloomFile << "'." << std::endl;
			close(fd);
			return false;
		}

		blooms[i] = mmap_ptr;
		++bloom_count;
		close(fd);
	}

	return true;
}

// fingerprint_cpu: performs fingerprint CPU.
uint32_t fingerprint_cpu(uint64_t hash)
{
	return hash ^ (hash >> 32);
}



// MurmurHash3 finalizer used by CPU XOR filter checks.
uint64_t murmur64_cpu(uint64_t h) {
	h ^= h >> 33;
	h *= UINT64_C(0xff51afd7ed558ccd);
	h ^= h >> 33;
	h *= UINT64_C(0xc4ceb9fe1a85ec53);
	h ^= h >> 33;
	return h;
}


// Computes one XOR-filter segment index from hash and segment index.
uint64_t getHashFromHash_cpu(uint64_t hash, int index, int xors)
//  const binary_fuse_t *filter)
{
	uint128_t x = (uint128_t)hash * (uint128_t)segmentCountLength[xors];
	uint64_t h = (uint64_t)(x >> 64);
	h += index * segmentLength[xors];
	// keep the lower 32 bits (compat with current xor_u/xor_c/xor_uc/xor_hc files)
	uint64_t hh = hash & ((1ULL << 32) - 1);
	// index 0: right shift by 36; index 1: right shift by 18; index 2: no shift
	if (index < 3)
	{
		h ^= (uint64_t)((hh >> (36 - 18 * index)) & segmentLengthMask[xors]);
	}
	return h;

}

// Checks one 64-bit half-hash against a CPU XOR filter.
bool Contain_cpu(const uint64_t& item, int xors){
	if (xors < 0 || xors >= 25 || fingerprints[xors] == nullptr) return false;
	uint64_t hash = murmur64_cpu(item + Seed_cpu);
	uint32_t f = fingerprint_cpu(hash);
	for (int hi = 0; hi < 4; hi++) {
		uint64_t h = getHashFromHash_cpu(hash, hi, xors);
		if (h >= arrayLength[xors]) return false;
		f ^= fingerprints[xors][h];
	}
	return f == 0;
}

// Combined Bloom/XOR CPU check used by host-side validation path.
bool find_in_bloom(const hash160_t hash)
{
	if (useBloomCPU)
	{
		for (int i = 0; i < bloom_count; i++)
		{
			if (blooms[i] == nullptr) continue;
			if (bloom_chk_hash160_cpu(blooms[i], hash.ul))
			{
				return true;
			}
		}
	}
	if (useXorCPU)
	{
		hash160_t hash128 = hash;
		hash128.uc[3] = hash128.uc[3] & hash128.uc[16];
		hash128.uc[7] = hash128.uc[7] & hash128.uc[17];
		hash128.uc[11] = hash128.uc[11] & hash128.uc[18];
		hash128.uc[15] = hash128.uc[15] & hash128.uc[19];
		for (int i = 0; i < xor_count; i++)
		{
			if (fingerprints[i] == nullptr) continue;
			if (!Contain_cpu(hash128.ull[0], i)) continue;
			if (Contain_cpu(hash128.ull[1], i)) return true;
		}
	}
	return false;
}
