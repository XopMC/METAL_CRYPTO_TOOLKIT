
#include "MetalBackend.h"

#include <string>
#include <vector>
#include "host_secp/secp256k1_common.h"
#include "lib/hash/GPUHash.h"
#include "lib/hash/sha3_ver3.h"
#include "Kernels/ProfanityHost.h"
#include "Kernels/WalletModesHost.h"
#include "Kernels/XpReplayHost.h"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>

using namespace std;

#ifdef _DEBUG
#define THREAD_STEPS 3
#define THREAD_STEPS_BRUTE 5
#define THREAD_STEPS_BRAIN 2
#else
#define THREAD_STEPS 32
#define THREAD_STEPS_BRUTE 64
#define THREAD_STEPS_BRAIN 16
#endif
#define PRIV_ROTATE_BATCH 32
#define PRIV_ROTATE_PHASES 8
#define PRIV_ROTATE_VARIANTS (PRIV_ROTATE_BATCH * PRIV_ROTATE_PHASES)
#define PASS_THREAD_STRIDE 128






#define atomicAdd(x, n) ((uint64_t)x + (uint64_t)n)
#define METAL_NOINLINE





#ifndef METAL_CRYPTO_TOOLKIT_KERNEL_RUNTIME_H
#define METAL_CRYPTO_TOOLKIT_KERNEL_RUNTIME_H

#define PREFIX_MAX_LEN 25
#define SUFFIX_MAX_LEN 20

#define ALPHABET_LEN 68

#define KERNEL_LAUNCH_BOUNDS

#define SUBSTRATE_MAX_PATHS 128
#define SUBSTRATE_MAX_JUNCTIONS 16
#define SUBSTRATE_MAX_PASSWORD_LEN 64

struct SubstrateJunctionDevice {
	uint8_t chain_code[32];
	uint8_t is_hard;
	uint8_t reserved[3];
};

struct SubstratePathDevice {
	uint32_t junction_count;
	uint32_t password_len;
	uint32_t save_index;
	uint32_t reserved;
	uint8_t password[SUBSTRATE_MAX_PASSWORD_LEN];
	SubstrateJunctionDevice junctions[SUBSTRATE_MAX_JUNCTIONS];
};

// Endomorphism result-tag encoding for secp256k1 vanity paths.
// type = ENDO_TAG_BASE + ENDO_GROUP_STRIDE * group + variant
// groups:
// 0=COMPRESSED, 1=SEGWIT, 2=UNCOMPRESSED, 3=ETH, 4=TAPROOT, 5=XPOINT, 6=P2WSH
// variants:
// 0=base+, 1=base-, 2=endo1+, 3=endo1-, 4=endo2+, 5=endo2-
static constexpr uint8_t ENDO_TAG_BASE = 0xA0u;
static constexpr uint8_t ENDO_GROUP_STRIDE = 8u;
static constexpr uint8_t ENDO_GROUP_COMPRESSED = 0u;
static constexpr uint8_t ENDO_GROUP_SEGWIT = 1u;
static constexpr uint8_t ENDO_GROUP_UNCOMPRESSED = 2u;
static constexpr uint8_t ENDO_GROUP_ETH = 3u;
static constexpr uint8_t ENDO_GROUP_TAPROOT = 4u;
static constexpr uint8_t ENDO_GROUP_XPOINT = 5u;
static constexpr uint8_t ENDO_GROUP_P2WSH = 6u;
static constexpr uint8_t ENDO_VARIANT_BASE_POS = 0u;
static constexpr uint8_t ENDO_VARIANT_BASE_NEG = 1u;
static constexpr uint8_t ENDO_VARIANT_ENDO1_POS = 2u;
static constexpr uint8_t ENDO_VARIANT_ENDO1_NEG = 3u;
static constexpr uint8_t ENDO_VARIANT_ENDO2_POS = 4u;
static constexpr uint8_t ENDO_VARIANT_ENDO2_NEG = 5u;
static constexpr uint32_t MINIKEY_STAGE_STRIDE = 31u;

extern  METAL_CONSTANT char       PREFIX[PREFIX_MAX_LEN];
extern  METAL_CONSTANT uint32_t   _NUM_TARGET_HASHES[1];
extern  METAL_CONSTANT uint32_t   HASH_TARGET_WORDS[8];
extern  METAL_CONSTANT uint32_t   HASH_TARGET_MASKS[8];
extern  METAL_CONSTANT uint32_t   HASH_TARGET_LEN[1];
extern  METAL_CONSTANT uint32_t   HASH_TARGET_ENABLED[1];

extern METAL_CONSTANT METAL_ALIGN(8) uint8_t* _BLOOM_FILTER[100];

extern METAL_DEVICE METAL_ALIGN(8) uint32_t* fingerprints_d[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     size_d[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     arrayLength_d[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentCount_d[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentCountLength_d[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentLength_d[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentLengthMask_d[25];

extern METAL_CONSTANT METAL_ALIGN(8) uint32_t* fingerprints_d_Un[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     size_d_Un[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     arrayLength_d_Un[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentCount_d_Un[25];
extern METAL_CONSTANT METAL_ALIGN(8) size_t   segmentCountLength_d_Un[25];
extern METAL_CONSTANT METAL_ALIGN(8) size_t   segmentLength_d_Un[25];
extern METAL_CONSTANT METAL_ALIGN(8) size_t   segmentLengthMask_d_Un[25];

extern METAL_DEVICE METAL_ALIGN(8) uint16_t* fingerprints_d_Uc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     size_d_Uc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     arrayLength_d_Uc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentCount_d_Uc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentCountLength_d_Uc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentLength_d_Uc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentLengthMask_d_Uc[25];

extern METAL_DEVICE METAL_ALIGN(8) uint8_t* fingerprints_d_Hc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     size_d_Hc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     arrayLength_d_Hc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentCount_d_Hc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentCountLength_d_Hc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentLength_d_Hc[25];
extern METAL_DEVICE METAL_ALIGN(8) size_t     segmentLengthMask_d_Hc[25];

extern METAL_DEVICE METAL_ALIGN(8) const char (*current_dict)[34];
extern METAL_DEVICE           MetalRandomState  state;

extern  METAL_CONSTANT uint32_t _USE_BLOOM_FILTER[1];
extern METAL_CONSTANT int         _bloom_count[1];
extern METAL_DEVICE int           _xor_count[1];
extern METAL_CONSTANT int         _xor_un_count[1];
extern METAL_DEVICE int           _xor_uc_count[1];
extern METAL_DEVICE int           _xor_hc_count[1];
extern METAL_DEVICE bool          useBloom_d;
extern METAL_DEVICE bool          useXor_d;
extern METAL_DEVICE bool          useXorUn_d;
extern METAL_DEVICE bool          useXorUc_d;
extern METAL_DEVICE bool          useXorHc_d;
extern METAL_DEVICE SubstratePathDevice* SUBSTRATE_PATHS_D;
extern METAL_CONSTANT uint32_t SUBSTRATE_PATH_COUNT_D[1];
extern METAL_CONSTANT uint32_t BIP_DERIVATIONS_ENABLED_D[1];
extern METAL_CONSTANT uint32_t ADA_POINTER_ENABLED_D[1];
extern METAL_CONSTANT uint64_t ADA_POINTER_SLOT_D[1];
extern METAL_CONSTANT uint64_t ADA_POINTER_TX_D[1];
extern METAL_CONSTANT uint64_t ADA_POINTER_CERT_D[1];
extern METAL_CONSTANT uint32_t ADA_TYPE_MASK_D[1];
extern METAL_CONSTANT uint32_t TON_TYPE_MASK_D[1];
extern METAL_CONSTANT uint32_t DOT_TYPE_MASK_D[1];
extern METAL_CONSTANT uint32_t APTOS_TYPE_MASK_D[1];
extern METAL_CONSTANT uint32_t SUI_TYPE_MASK_D[1];
extern METAL_CONSTANT uint32_t XRP_TYPE_MASK_D[1];
extern METAL_CONSTANT uint32_t IOTA_TYPE_MASK_D[1];
extern METAL_CONSTANT uint32_t ICP_TYPE_MASK_D[1];
extern METAL_CONSTANT uint32_t FIL_TYPE_MASK_D[1];
extern METAL_CONSTANT uint32_t XTZ_TYPE_MASK_D[1];

extern  METAL_CONSTANT int        ITERATION[1];
extern  METAL_CONSTANT int        SHA_LEVEL[1];
extern  METAL_CONSTANT uint32_t   SHA_PRE[8];


extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   salt[12];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   salt_swap[16];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   ton_salt1[20];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   ton_seed_swap[24];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   ton_salt[16];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   electrum_salt[12];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   electrum_salt_swap[16];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   key001[16];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   key[12];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   ed_key[12];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   ed_key_swap[16];
extern METAL_CONSTANT METAL_ALIGN(4) uint8_t   key_swap[16];

extern METAL_CONSTANT METAL_ALIGN(64) uint8_t SECP_G65[65];

extern METAL_DEVICE unsigned long long int  d_resultsCount[1];


extern METAL_DEVICE char        (*d_foundStrings)[512];
extern METAL_DEVICE unsigned char (*d_foundPrvKeys)[64];
extern METAL_DEVICE uint32_t(*d_foundHash160)[20];
extern METAL_DEVICE uint32_t(*d_len)[1];
extern METAL_DEVICE uint32_t(*d_iter)[1];
extern METAL_DEVICE uint8_t* d_type;
extern METAL_DEVICE int64_t* d_round;
extern METAL_DEVICE ProfanityVerifiedResult* d_profanityResults;
extern METAL_DEVICE unsigned long long* d_profanityCount;
extern METAL_DEVICE WalletModeResult* d_walletResults;
extern METAL_DEVICE unsigned long long* d_walletCount;
extern METAL_DEVICE XpReplayResult* d_xpResults;
extern METAL_DEVICE unsigned long long* d_xpCount;
extern METAL_DEVICE uint32_t d_xp_randstorm_seed_events;
extern METAL_DEVICE uint32_t d_xp_randstorm_time_mode;
extern METAL_DEVICE uint32_t d_xp_randstorm_mileage_start;
extern METAL_DEVICE uint64_t d_xp_randstorm_mileage_count;
extern METAL_DEVICE uint32_t* d_foundDerivations;
extern METAL_DEVICE uint32_t* d_foundDerivations2;
extern METAL_DEVICE char (*d_pass)[128];
extern METAL_DEVICE uint16_t* d_pass_size;
extern METAL_DEVICE uint64_t* d_seed;

extern METAL_DEVICE bool                    old_electrum;

extern METAL_DEVICE bool                    secp256_d;
extern METAL_DEVICE bool                    ed25519_d;
extern METAL_DEVICE bool                    electrum_dev;
extern METAL_DEVICE bool                    Ton_d_dev;
extern METAL_DEVICE bool                    Ton_only_d_dev;
extern METAL_DEVICE bool                    compressed_dev;
extern METAL_DEVICE bool                    uncompressed_dev;
extern METAL_DEVICE bool                    segwit_dev;
extern METAL_DEVICE bool                    p2wsh_dev;
extern METAL_DEVICE bool                    taproot_dev;
extern METAL_DEVICE bool                    ethereum_dev;
extern METAL_DEVICE bool                    xpoint_dev;
extern METAL_DEVICE bool                    solana_dev;
extern METAL_DEVICE bool                    ton_dev;
extern METAL_DEVICE bool                    ton_all_dev;
extern METAL_DEVICE bool                    dot_dev;
extern METAL_DEVICE bool                    aptos_dev;
extern METAL_DEVICE bool                    sui_dev;
extern METAL_DEVICE bool                    xrp_dev;
extern METAL_DEVICE bool                    exodus_dev;
extern METAL_DEVICE bool                    iota_dev;
extern METAL_DEVICE bool					  ada_dev;
extern METAL_DEVICE bool					  icp_dev;
extern METAL_DEVICE bool					  fil_dev;
extern METAL_DEVICE bool					  xtz_dev;
extern METAL_DEVICE bool                     endomorphism_dev;
extern METAL_DEVICE bool                     secp_targets_any_dev;
extern METAL_DEVICE bool                     ed_targets_any_dev;
extern METAL_DEVICE uint8_t                  derivation_type_mask_dev;

extern METAL_DEVICE uint64_t                Seed;
extern METAL_DEVICE uint32_t				  Deep;
extern METAL_DEVICE uint64_t pbkdf2_iterations;

METAL_DEVICE METAL_FORCEINLINE bool ada_type_enabled(const uint8_t coin_type) {
	if (coin_type < 0x10u || coin_type > 0x19u) {
		return true;
	}
	return (ADA_TYPE_MASK_D[0] & (1u << (coin_type - 0x10u))) != 0u;
}

METAL_DEVICE METAL_FORCEINLINE bool ton_type_enabled(const uint8_t coin_type) {
	if (coin_type < 0x80u || coin_type > 0x8cu) {
		return true;
	}
	return (TON_TYPE_MASK_D[0] & (1u << (coin_type - 0x80u))) != 0u;
}

METAL_DEVICE METAL_FORCEINLINE bool dot_type_enabled(const uint8_t coin_type) {
	if (coin_type < 0x30u || coin_type > 0x31u) {
		return true;
	}
	return (DOT_TYPE_MASK_D[0] & (1u << (coin_type - 0x30u))) != 0u;
}

METAL_DEVICE METAL_FORCEINLINE bool aptos_type_enabled(const uint8_t coin_type) {
	if (coin_type < 0x20u || coin_type > 0x22u) {
		return true;
	}
	return (APTOS_TYPE_MASK_D[0] & (1u << (coin_type - 0x20u))) != 0u;
}

METAL_DEVICE METAL_FORCEINLINE bool sui_type_enabled(const uint8_t coin_type) {
	if (coin_type < 0x70u || coin_type > 0x71u) {
		return true;
	}
	return (SUI_TYPE_MASK_D[0] & (1u << (coin_type - 0x70u))) != 0u;
}

METAL_DEVICE METAL_FORCEINLINE bool xrp_type_enabled(const uint8_t coin_type) {
	if (coin_type < 0x90u || coin_type > 0x91u) {
		return true;
	}
	return (XRP_TYPE_MASK_D[0] & (1u << (coin_type - 0x90u))) != 0u;
}

METAL_DEVICE METAL_FORCEINLINE bool iota_type_enabled(const uint8_t coin_type) {
	if (coin_type < 0x50u || coin_type > 0x51u) {
		return true;
	}
	return (IOTA_TYPE_MASK_D[0] & (1u << (coin_type - 0x50u))) != 0u;
}

METAL_DEVICE METAL_FORCEINLINE bool icp_type_enabled(const uint8_t coin_type) {
	if (coin_type < 0x52u || coin_type > 0x53u) {
		return true;
	}
	return (ICP_TYPE_MASK_D[0] & (1u << (coin_type - 0x52u))) != 0u;
}

METAL_DEVICE METAL_FORCEINLINE bool fil_type_enabled(const uint8_t coin_type) {
	if (coin_type < 0x41u || coin_type > 0x42u) {
		return true;
	}
	return (FIL_TYPE_MASK_D[0] & (1u << (coin_type - 0x41u))) != 0u;
}

METAL_DEVICE METAL_FORCEINLINE bool xtz_type_enabled(const uint8_t coin_type) {
	if (coin_type < 0x92u || coin_type > 0x93u) {
		return true;
	}
	return (XTZ_TYPE_MASK_D[0] & (1u << (coin_type - 0x92u))) != 0u;
}

METAL_DEVICE METAL_FORCEINLINE bool target_subtype_enabled(const uint8_t coin_type) {
	return ada_type_enabled(coin_type) &&
		ton_type_enabled(coin_type) &&
		dot_type_enabled(coin_type) &&
		aptos_type_enabled(coin_type) &&
		sui_type_enabled(coin_type) &&
		xrp_type_enabled(coin_type) &&
		iota_type_enabled(coin_type) &&
		icp_type_enabled(coin_type) &&
		fil_type_enabled(coin_type) &&
		xtz_type_enabled(coin_type);
}
extern METAL_DEVICE uint64_t SeqStep;

extern METAL_DEVICE bool IS_HEX_DEV;
extern METAL_DEVICE bool IS_PASS;


extern std::atomic<uint64_t> false_positive;
extern bool STOP_THREAD;

extern uint64_t pbkdf_iter;
extern uint32_t MAX_FOUNDS;
extern METAL_DEVICE uint32_t MAX_FOUNDS_DEV;

extern METAL_DEVICE bool FULL_d;
extern bool FULL;
extern METAL_DEVICE bool UTF8;

extern std::vector<std::thread> g_save_threads;
extern std::mutex g_save_threads_mutex;

METAL_HOST void wait_for_current_gpu_async_save_queue();
METAL_HOST void flush_all_async_save_queues();
METAL_HOST void shutdown_async_save_queues();
METAL_HOST void push_save_cpu_postcheck_suppression();
METAL_HOST void pop_save_cpu_postcheck_suppression();

extern bool is_ed25519_scalar;
extern bool is_ed25519_hash;

#define DERIVATION_TYPE_MASK_BIP32 0x01u
#define DERIVATION_TYPE_MASK_SLIP0010 0x02u
#define DERIVATION_TYPE_MASK_BIP32_ED25519 0x04u

typedef struct METAL_ALIGN(16) {
	uint8_t key[32];
	uint8_t chain_code[32];
} extended_private_key_t;

typedef struct METAL_ALIGN(16) {
	uint8_t key[64];
	uint8_t chain_code[32];
} extended_public_key_t;

typedef struct METAL_ALIGN(16) {
	uint8_t key[64];
	uint8_t chain_code[32];
} cardano_extended_private_key_t;




metalError_t loadPrefix(const char* _prefix, size_t const prefixLen);
metalError_t loadHashTarget(const uint32_t words[8], const uint32_t masks[8], uint32_t lenBytes, bool enabled);
metalError_t loadLevel(int _level);
metalError_t loadIteration(int _i);
metalError_t loadShaPre(uint32_t* _pre);
metalError_t metalLoadBloomFilter(uint8_t* _bloomFilterPtr, int count);
metalError_t metalLoadCompressedXorFilter(uint32_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h);
metalError_t metalLoadUncompressedXorFilter(uint32_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h);
metalError_t metalLoadUltraXorFilter(uint16_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h);
metalError_t metalLoadHyperXorFilter(uint8_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h);

// Parameter setter kernels.

METAL_KERNEL void setFULL();

METAL_KERNEL void setPASS();

METAL_KERNEL void setLE();

METAL_KERNEL void setUTF8();

METAL_KERNEL void setEd25519_scalar();

METAL_KERNEL void setEd25519_hash();

METAL_KERNEL void setFoundSize(uint32_t max_founds);

METAL_KERNEL void setDict(int lang);
METAL_KERNEL void setDictPointer(const char (*dict)[34]);

METAL_KERNEL void rand_state();

METAL_KERNEL void SetSkipDev(uint64_t skip_host);
METAL_KERNEL void SetSkipDev64(uint64_t skip_host);

METAL_KERNEL void SetSeqStep(uint64_t step_host);

METAL_HOST void setSilentMode();

METAL_HOST void setPassMode();

METAL_KERNEL void SetDeep(uint32_t deep);

METAL_KERNEL void setHEX();

METAL_KERNEL void setFilterType(bool bloomUse, bool xorFilter, bool xorFilterUn, bool xorFilterUc, bool xorFilterHc);

METAL_KERNEL void SetCurve(bool secp256, bool ed25519, bool electrum_host, bool ton_mnem, bool ton_only, bool old_electrum_host, bool compressed, bool uncompressed, bool segwit, bool p2wsh, bool taproot, bool ethereum, bool xpoint, bool solana, bool ton, bool ton_all, bool dot, bool aptos, bool sui, bool xrp, bool exodus, bool iota, bool ada, bool icp, bool fil, bool xtz, bool endomorphism);

METAL_KERNEL void SetDerivationTypeMask(uint8_t mask);

METAL_KERNEL void set_iter(uint64_t pbkdf_iter);

metalError_t loadWindow(unsigned int windowSize, unsigned int windows);

METAL_DEVICE METAL_FORCEINLINE
// reverse32: reverses 32.
uint8_t* reverse32(uint8_t* p) {
#pragma unroll
	for (int i = 0; i < 16; ++i) {
		uint8_t t = p[i];
		p[i] = p[31 - i];
		p[31 - i] = t;
	}
	return p;
}

//Entropy cores

METAL_KERNEL void workerEntropy(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const char* __restrict__ passwd, const uint32_t  pass_size, const uint32_t starter_pass, bool custom_size, const int* __restrict__ sizes, const uint32_t sizez_size, uint8_t entropy_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size, uint64_t round, bool dub_mnem = false);

METAL_KERNEL void workerEntropy_seq(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, int mode, uint8_t* start_point_dev, int min_len, const char* __restrict__ passwd, const uint32_t  pass_size, const uint32_t starter_pass, bool custom_size, int custom_len, uint8_t entropy_mode, const uint32_t iter, uint64_t round, bool dub_mnem = false);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerEntropy_seq_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, const char* __restrict__ passwd, const uint32_t pass_size, const uint32_t starter_pass, bool custom_size, int custom_len, uint8_t entropy_mode, const uint32_t iter, uint64_t round, bool dub_mnem = false);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerEntropy_recovery_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, const char* __restrict__ passwd, const uint32_t pass_size, const uint32_t starter_pass, bool custom_size, int custom_len, uint8_t entropy_mode, const uint32_t iter, uint64_t round, bool dub_mnem);

//Mnemonic cores

METAL_KERNEL void worker(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const char* __restrict__ passwd, const uint32_t pass_size, const uint32_t starter_pass, uint64_t round, uint8_t m_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size, bool is_str, bool dub_mnem = false);

// Pass-thread cores (inverted: one mnemonic, N passwords one per thread)
METAL_KERNEL void workerPassThread(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const char* __restrict__ single_mnem, const uint32_t single_mnem_len, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const char* __restrict__ passwords, const uint8_t* __restrict__ pass_lengths, const uint32_t pass_count, uint64_t round, uint8_t m_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size, bool is_str, bool dub_mnem = false);

METAL_KERNEL void workerPassThreadEntropy(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const char* __restrict__ single_entropy, const uint32_t single_entropy_len, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const char* __restrict__ passwords, const uint8_t* __restrict__ pass_lengths, const uint32_t pass_count, bool custom_size, const int* __restrict__ sizes, const uint32_t sizez_size, uint8_t entropy_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size, uint64_t round, bool dub_mnem = false);

METAL_KERNEL void workerByte(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const char* __restrict__ passwd, const uint32_t* __restrict__ pass_size, const uint32_t pass_count, bool dub_mnem = false);

METAL_KERNEL void worker_seq(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, int mode, uint8_t* start_point_dev, int min_len, const char* __restrict__ passwd, const uint32_t  pass_size, const uint32_t starter_pass, uint64_t round, uint8_t m_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size, bool is_str, bool dub_mnem = false);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void worker_seq_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, const char* __restrict__ passwd, const uint32_t pass_size, const uint32_t starter_pass, uint64_t round, uint8_t m_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size, bool is_str, bool dub_mnem = false);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void worker_recovery_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, const char* __restrict__ passwd, const uint32_t pass_size, const uint32_t starter_pass, uint64_t round, uint8_t m_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size, bool is_str, bool dub_mnem);

METAL_KERNEL void worker_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, const char* __restrict__ passwd, const uint32_t  pass_size, const uint32_t starter_pass, bool custom_size, int custom_len, uint8_t entropy_mode, const uint32_t iter, uint64_t round, bool dub_mnem = false);

//Bip32 Passphrase cores

METAL_KERNEL void workerBip32(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, uint8_t bip_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size, uint64_t round);

METAL_KERNEL void workerBip32_seq(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, int mode, uint8_t* start_point_dev, int min_len, uint8_t bip_mode, const uint32_t iter, uint64_t round);
METAL_KERNEL void workerBip32_seq_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint8_t bip_mode, const uint32_t iter, uint64_t round);
METAL_KERNEL void workerBip32_recovery_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint8_t bip_mode, const uint32_t iter, uint64_t round);

METAL_KERNEL void workerBip32_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, uint8_t bip_mode, const uint32_t ITERATION, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, uint64_t round);

//Seed cores

METAL_KERNEL void workerSeed(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, uint64_t round);


METAL_KERNEL void workerSeed_seq(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, int mode, uint8_t* start_point_dev, int min_len, uint64_t round);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerSeed_seq_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint64_t round);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerSeed_recovery_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint64_t round);

METAL_KERNEL void workerSeed_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, uint64_t round);

//Hmac cores

METAL_KERNEL void workerHmac(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, uint64_t round);

METAL_KERNEL void workerHmac_seq(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, int mode, uint8_t* start_point_dev, uint64_t round);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerHmac_seq_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint64_t round);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerHmac_recovery_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint64_t round);

METAL_KERNEL void workerHmac_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint32_t* __restrict__  d_derivations, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_start_index, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, uint64_t round);

// Der-thread cores (inverted: one input, all derivation paths split across threads)
METAL_KERNEL void workerDerThread_mkd(const char* __restrict__ input_str, const uint32_t input_str_len, const char* __restrict__ passphrase, const uint32_t pass_len, uint8_t* d_master_secp, uint8_t* d_master_ed, uint8_t* d_master_cardano_icarus, uint8_t* d_master_cardano_daedalus, uint8_t* d_master_cardano_ledger, uint8_t* d_master_cardano_byron_legacy, uint8_t* d_entropy, uint32_t* d_entropy_len, uint8_t* d_entropy_valid, char* d_save_str, uint32_t* d_save_len, uint8_t mode, uint8_t m_mode, uint8_t entropy_mode, uint8_t bip_mode, const uint32_t* iterations, uint32_t iterations_size, uint32_t iteration_idx);

METAL_KERNEL void workerDerThread_mkd_gen(uint64_t seed_d, int entropy_bytes, int gen, uint8_t* d_master_secp, uint8_t* d_master_ed, uint8_t* d_master_cardano_icarus, uint8_t* d_master_cardano_daedalus, uint8_t* d_master_cardano_ledger, uint8_t* d_master_cardano_byron_legacy, uint8_t* d_entropy, uint32_t* d_entropy_len, uint8_t* d_entropy_valid, char* d_save_str, uint32_t* d_save_len, uint8_t mode, uint8_t entropy_mode_p, const char* __restrict__ passphrase, uint32_t pass_len, bool is_64);

METAL_KERNEL void workerDerThread(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint8_t* __restrict__ d_master_secp, const uint8_t* __restrict__ d_master_ed, const uint8_t* __restrict__ d_master_cardano_icarus, const uint8_t* __restrict__ d_master_cardano_daedalus, const uint8_t* __restrict__ d_master_cardano_ledger, const uint8_t* __restrict__ d_master_cardano_byron_legacy, const uint8_t* __restrict__ d_entropy, const uint32_t* __restrict__ d_entropy_len, const uint8_t* __restrict__ d_entropy_valid, const char* __restrict__ d_save_str, const uint32_t d_save_len, const char* __restrict__ d_passphrase, uint32_t pass_len, uint64_t seed_value, bool store_seed, const uint32_t* __restrict__ d_derivations, const uint32_t* __restrict__ d_deriv_offsets, const uint32_t* __restrict__ derindex, const uint32_t der_indexes_size, const uint32_t der_offset, uint64_t round);

//Private keys cores

METAL_KERNEL void workerPRIV(bool* isResult, bool* buffResult, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, int true_priv, uint64_t round);
METAL_KERNEL void workerPRIV_pattern(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint8_t* __restrict__ pattern_start_nibbles, uint8_t pattern_len, uint64_t gpu_stride, bool cycle_last_nibble, uint64_t round);
METAL_KERNEL void workerMINIKEYS_collect(const uint8_t* __restrict__ suffix_start_base58, const uint8_t* __restrict__ suffix_end_base58, uint8_t suffix_len, uint64_t gpu_stride, unsigned char* __restrict__ out_valid_minikeys, uint8_t* __restrict__ out_valid_minikey_lens, uint32_t* __restrict__ out_count, uint32_t out_capacity);
METAL_KERNEL void workerMINIKEYS_process(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const unsigned char* __restrict__ valid_minikeys, const uint8_t* __restrict__ valid_minikey_lens, const uint32_t* __restrict__ valid_count_ptr, uint64_t round, uint32_t valid_capacity);
METAL_KERNEL void workerMINIKEYS_seed_collect_file(const char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const uint8_t* __restrict__ sizes, const uint32_t sizes_count, unsigned char* __restrict__ out_valid_minikeys, uint8_t* __restrict__ out_valid_minikey_lens, uint32_t* __restrict__ out_count);
METAL_KERNEL void workerMINIKEYS_seed_collect_seq(const uint8_t* __restrict__ start_point_dev, int mode, int min_len, const uint8_t* __restrict__ sizes, const uint32_t sizes_count, unsigned char* __restrict__ out_valid_minikeys, uint8_t* __restrict__ out_valid_minikey_lens, uint32_t* __restrict__ out_count);
METAL_KERNEL void workerMINIKEYS_seed_collect_gen(uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, const uint8_t* __restrict__ sizes, const uint32_t sizes_count, unsigned char* __restrict__ out_valid_minikeys, uint8_t* __restrict__ out_valid_minikey_lens, uint32_t* __restrict__ out_count);

METAL_KERNEL void workerPRIV_seq(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch,  int mode, uint8_t* start_point);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerPRIV_seq_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, uint16_t hexset_digit_count, const uint8_t* __restrict__ hexset_alphabet, uint8_t hexset_base, uint64_t gpu_stride, uint64_t round);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanity_c(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_s0, uint64_t seed_s1, uint64_t seed_s2, uint64_t seed_s3, uint32_t seed32, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanity_u(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_s0, uint64_t seed_s1, uint64_t seed_s2, uint64_t seed_s3, uint32_t seed32, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanity_s(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_s0, uint64_t seed_s1, uint64_t seed_s2, uint64_t seed_s3, uint32_t seed32, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanity_r(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_s0, uint64_t seed_s1, uint64_t seed_s2, uint64_t seed_s3, uint32_t seed32, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanity_x(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_s0, uint64_t seed_s1, uint64_t seed_s2, uint64_t seed_s3, uint32_t seed32, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanity_e(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_s0, uint64_t seed_s1, uint64_t seed_s2, uint64_t seed_s3, uint32_t seed32, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanity_cu(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_s0, uint64_t seed_s1, uint64_t seed_s2, uint64_t seed_s3, uint32_t seed32, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanity_cusr(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_s0, uint64_t seed_s1, uint64_t seed_s2, uint64_t seed_s3, uint32_t seed32, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanity_cusrxe(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_s0, uint64_t seed_s1, uint64_t seed_s2, uint64_t seed_s3, uint32_t seed32, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanityPrepareTargetGe(const uint8_t* __restrict__ target_pubkey, uint32_t target_len, secp256k1_ge* __restrict__ target_ge, uint32_t* __restrict__ target_ok);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanityRecoveryReverse_ge(const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const secp256k1_ge* __restrict__ target_ge, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityRecoveryHit* __restrict__ hits, uint32_t* __restrict__ hit_count, uint32_t max_hits, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanityRecoveryReverse_xc_ge(const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const secp256k1_ge* __restrict__ target_ge, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityRecoveryHit* __restrict__ hits, uint32_t* __restrict__ hit_count, uint32_t max_hits, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanityRecoveryReverse_xuc_ge(const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const secp256k1_ge* __restrict__ target_ge, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityRecoveryHit* __restrict__ hits, uint32_t* __restrict__ hit_count, uint32_t max_hits, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanityRecoveryReverse_xh_ge(const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const secp256k1_ge* __restrict__ target_ge, uint64_t lane_start, uint64_t lane_count, uint64_t state_index_start, uint64_t round_start, uint64_t round_count, ProfanityRecoveryHit* __restrict__ hits, uint32_t* __restrict__ hit_count, uint32_t max_hits, ProfanityWalkState* __restrict__ walk_state, uint64_t walk_state_capacity, bool use_walk_state, bool store_walk_state);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanitySeedResolve(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint32_t start_seed32, uint32_t seed_count, uint64_t lane_start, uint64_t lane_count, uint64_t pair_start, uint64_t pair_count, const uint8_t* __restrict__ target_pubkey, uint32_t target_len, const ProfanityRecoveryHit* __restrict__ hits, uint32_t hit_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerProfanitySeedResolveBatch(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint32_t start_seed32, uint32_t seed_count, uint64_t lane_start, uint64_t lane_count, uint64_t pair_start, uint64_t pair_count, const uint8_t* __restrict__ target_pubkey, uint32_t target_len, const ProfanityRecoveryHit* __restrict__ hits, uint32_t hit_count);

METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerKeystoreV3(
	bool* isResult,
	bool* buffResult,
	const secp256k1_ge_storage* __restrict__ precPtr,
	const size_t precPitch,
	const WalletKeystoreTarget* __restrict__ targets,
	uint32_t target_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint8_t* __restrict__ scrypt_scratch,
	uint64_t scrypt_scratch_stride,
	uint64_t candidate_start,
	uint64_t candidate_count);

METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletDat(
    bool* isResult,
    bool* buffResult,
    const secp256k1_ge_storage* __restrict__ precPtr,
    const size_t precPitch,
	const WalletDatTarget* __restrict__ targets,
	uint32_t target_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
    const WalletRangeSpec* __restrict__ range_spec,
    uint64_t candidate_start,
    uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletDatMaster(
	const WalletDatTarget* __restrict__ targets,
	uint32_t target_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint64_t candidate_start,
	uint64_t candidate_count,
	WalletDatMasterHit* __restrict__ hits,
	uint32_t* __restrict__ hit_count,
	uint32_t max_hits);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletDatResolveHits(
	bool* isResult,
	bool* buffResult,
	const secp256k1_ge_storage* __restrict__ precPtr,
	const size_t precPitch,
	const WalletDatTarget* __restrict__ targets,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	const WalletDatMasterHit* __restrict__ hits,
	uint32_t hit_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletDatKdfInit(
	const WalletDatTarget* __restrict__ targets,
	uint32_t target_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint64_t candidate_start,
	uint64_t candidate_count,
	WalletDatKdfTmp* __restrict__ tmp,
	uint64_t tmp_capacity);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletDatKdfLoop(
	const WalletDatTarget* __restrict__ targets,
	uint32_t target_count,
	uint64_t candidate_count,
	uint32_t loop_pos,
	uint32_t loop_count,
	WalletDatKdfTmp* __restrict__ tmp,
	uint64_t tmp_capacity);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletDatKdfLoopUniform(
	uint64_t total_jobs,
	uint32_t loop_count,
	WalletDatKdfTmp* __restrict__ tmp,
	uint64_t tmp_capacity);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletDatKdfCheck(
	const WalletDatTarget* __restrict__ targets,
	uint32_t target_count,
	uint64_t candidate_start,
	uint64_t candidate_count,
	const WalletDatKdfTmp* __restrict__ tmp,
	uint64_t tmp_capacity,
	WalletDatMasterHit* __restrict__ hits,
	uint32_t* __restrict__ hit_count,
	uint32_t max_hits);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletDatGroupKdfInit(
	const WalletDatGroup* __restrict__ groups,
	uint32_t group_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint64_t candidate_start,
	uint64_t candidate_count,
	WalletDatKdfTmp* __restrict__ tmp,
	uint64_t tmp_capacity);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletDatGroupKdfLoop(
	const WalletDatGroup* __restrict__ groups,
	uint32_t group_count,
	uint64_t candidate_count,
	uint32_t loop_pos,
	uint32_t loop_count,
	WalletDatKdfTmp* __restrict__ tmp,
	uint64_t tmp_capacity);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletDatGroupKdfCheck(
	const WalletDatTarget* __restrict__ targets,
	const WalletDatGroup* __restrict__ groups,
	uint32_t group_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint64_t candidate_start,
	uint64_t candidate_count,
	const WalletDatKdfTmp* __restrict__ tmp,
	uint64_t tmp_capacity,
	WalletDatMasterHit* __restrict__ hits,
	uint32_t* __restrict__ hit_count,
	uint32_t max_hits);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerBrowserVault(
	bool* isResult,
	bool* buffResult,
	const BrowserVaultDeviceTarget* __restrict__ targets,
	const uint8_t* __restrict__ ciphertext_pool,
	uint32_t target_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint8_t* __restrict__ scrypt_scratch,
	uint64_t scrypt_scratch_stride,
	uint64_t candidate_start,
	uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerBrowserVaultGrouped(
	bool* isResult,
	bool* buffResult,
	const secp256k1_ge_storage* __restrict__ precPtr,
	const size_t precPitch,
	const BrowserVaultDeviceTarget* __restrict__ targets,
	const BrowserVaultGroup* __restrict__ groups,
	const uint8_t* __restrict__ ciphertext_pool,
	uint32_t group_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint8_t* __restrict__ scrypt_scratch,
	uint64_t scrypt_scratch_stride,
	uint64_t candidate_start,
	uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerExodusSeco(
	bool* isResult,
	bool* buffResult,
	const ExodusSecoTarget* __restrict__ targets,
	uint32_t target_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint8_t* __restrict__ scrypt_scratch,
	uint64_t scrypt_scratch_stride,
	uint64_t candidate_start,
	uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerBitcoinJWallet(
	bool* isResult,
	bool* buffResult,
	const secp256k1_ge_storage* __restrict__ precPtr,
	const size_t precPitch,
	const BitcoinJWalletTarget* __restrict__ targets,
	uint32_t target_count,
	uint8_t result_mode,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint8_t* __restrict__ scrypt_scratch,
	uint64_t scrypt_scratch_stride,
	uint64_t candidate_start,
	uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerArmoryWallet(
	bool* isResult,
	bool* buffResult,
	const secp256k1_ge_storage* __restrict__ precPtr,
	const size_t precPitch,
	const ArmoryWalletTarget* __restrict__ targets,
	uint32_t target_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint8_t* __restrict__ romix_scratch,
	uint64_t romix_scratch_stride,
	uint64_t candidate_start,
	uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerElectrumWalletPrepareTargets(
	ElectrumWalletTarget* targets,
	ElectrumWalletEcdhPrecomp* ecdh_precomp,
	uint32_t ecdh_precomp_count,
	uint32_t target_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerElectrumWallet(
	bool* isResult,
	bool* buffResult,
	const ElectrumWalletTarget* __restrict__ targets,
	const ElectrumWalletEcdhPrecomp* __restrict__ ecdh_precomp,
	const uint8_t* __restrict__ ciphertext_pool,
	uint32_t target_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint64_t candidate_start,
	uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerElectrumWalletFieldOnly(
	bool* isResult,
	bool* buffResult,
	const ElectrumWalletTarget* __restrict__ targets,
	const uint8_t* __restrict__ ciphertext_pool,
	uint32_t target_count,
	const uint8_t* __restrict__ solved_flags,
	uint32_t solved_count,
	uint8_t candidate_kind,
	const char* __restrict__ pass_data,
	const uint8_t* __restrict__ pass_lens,
	uint32_t pass_count,
	const WalletMaskSpec* __restrict__ mask_spec,
	const WalletRangeSpec* __restrict__ range_spec,
	uint64_t candidate_start,
	uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS(
    bool* isResult,
    bool* buffResult,
    const secp256k1_ge_storage* __restrict__ precPtr,
    const size_t precPitch,
    WalletJsSpec spec,
    uint8_t candidate_kind,
    const char* __restrict__ pass_data,
    const uint8_t* __restrict__ pass_lens,
    uint32_t pass_count,
    const WalletMaskSpec* __restrict__ mask_spec,
    const WalletRangeSpec* __restrict__ range_spec,
    uint64_t candidate_start,
    uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_c(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint8_t candidate_kind, const char* __restrict__ pass_data, const uint8_t* __restrict__ pass_lens, uint32_t pass_count, const WalletMaskSpec* __restrict__ mask_spec, const WalletRangeSpec* __restrict__ range_spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_u(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint8_t candidate_kind, const char* __restrict__ pass_data, const uint8_t* __restrict__ pass_lens, uint32_t pass_count, const WalletMaskSpec* __restrict__ mask_spec, const WalletRangeSpec* __restrict__ range_spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_s(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint8_t candidate_kind, const char* __restrict__ pass_data, const uint8_t* __restrict__ pass_lens, uint32_t pass_count, const WalletMaskSpec* __restrict__ mask_spec, const WalletRangeSpec* __restrict__ range_spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_r(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint8_t candidate_kind, const char* __restrict__ pass_data, const uint8_t* __restrict__ pass_lens, uint32_t pass_count, const WalletMaskSpec* __restrict__ mask_spec, const WalletRangeSpec* __restrict__ range_spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_x(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint8_t candidate_kind, const char* __restrict__ pass_data, const uint8_t* __restrict__ pass_lens, uint32_t pass_count, const WalletMaskSpec* __restrict__ mask_spec, const WalletRangeSpec* __restrict__ range_spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_e(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint8_t candidate_kind, const char* __restrict__ pass_data, const uint8_t* __restrict__ pass_lens, uint32_t pass_count, const WalletMaskSpec* __restrict__ mask_spec, const WalletRangeSpec* __restrict__ range_spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_cu(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint8_t candidate_kind, const char* __restrict__ pass_data, const uint8_t* __restrict__ pass_lens, uint32_t pass_count, const WalletMaskSpec* __restrict__ mask_spec, const WalletRangeSpec* __restrict__ range_spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_cusr(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint8_t candidate_kind, const char* __restrict__ pass_data, const uint8_t* __restrict__ pass_lens, uint32_t pass_count, const WalletMaskSpec* __restrict__ mask_spec, const WalletRangeSpec* __restrict__ range_spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_cusrxe(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint8_t candidate_kind, const char* __restrict__ pass_data, const uint8_t* __restrict__ pass_lens, uint32_t pass_count, const WalletMaskSpec* __restrict__ mask_spec, const WalletRangeSpec* __restrict__ range_spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_seed(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_seed_c(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_seed_u(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_seed_s(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_seed_r(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_seed_x(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_seed_e(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_seed_cu(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_seed_cusr(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint64_t candidate_start, uint64_t candidate_count);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerWalletJS_seed_cusrxe(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, WalletJsSpec spec, uint64_t candidate_start, uint64_t candidate_count);

METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerXP_c(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t profile_kind, uint64_t path_mask, uint32_t path_count, uint32_t pid_start, uint32_t pid_count, uint32_t keys_per_pid, uint64_t linear_start, uint64_t linear_count, uint64_t randstorm_state_start, uint64_t randstorm_state_count, uint32_t randstorm_time_start, uint32_t randstorm_time_count, uint32_t randstorm_delta_count, const XpCgrStateInput* __restrict__ cgr_inputs, uint32_t cgr_count, const XpSsleayInput* __restrict__ ssleay_inputs, uint32_t ssleay_count, uint32_t input_line_base);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerXP_u(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t profile_kind, uint64_t path_mask, uint32_t path_count, uint32_t pid_start, uint32_t pid_count, uint32_t keys_per_pid, uint64_t linear_start, uint64_t linear_count, uint64_t randstorm_state_start, uint64_t randstorm_state_count, uint32_t randstorm_time_start, uint32_t randstorm_time_count, uint32_t randstorm_delta_count, const XpCgrStateInput* __restrict__ cgr_inputs, uint32_t cgr_count, const XpSsleayInput* __restrict__ ssleay_inputs, uint32_t ssleay_count, uint32_t input_line_base);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerXP_s(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t profile_kind, uint64_t path_mask, uint32_t path_count, uint32_t pid_start, uint32_t pid_count, uint32_t keys_per_pid, uint64_t linear_start, uint64_t linear_count, uint64_t randstorm_state_start, uint64_t randstorm_state_count, uint32_t randstorm_time_start, uint32_t randstorm_time_count, uint32_t randstorm_delta_count, const XpCgrStateInput* __restrict__ cgr_inputs, uint32_t cgr_count, const XpSsleayInput* __restrict__ ssleay_inputs, uint32_t ssleay_count, uint32_t input_line_base);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerXP_r(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t profile_kind, uint64_t path_mask, uint32_t path_count, uint32_t pid_start, uint32_t pid_count, uint32_t keys_per_pid, uint64_t linear_start, uint64_t linear_count, uint64_t randstorm_state_start, uint64_t randstorm_state_count, uint32_t randstorm_time_start, uint32_t randstorm_time_count, uint32_t randstorm_delta_count, const XpCgrStateInput* __restrict__ cgr_inputs, uint32_t cgr_count, const XpSsleayInput* __restrict__ ssleay_inputs, uint32_t ssleay_count, uint32_t input_line_base);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerXP_x(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t profile_kind, uint64_t path_mask, uint32_t path_count, uint32_t pid_start, uint32_t pid_count, uint32_t keys_per_pid, uint64_t linear_start, uint64_t linear_count, uint64_t randstorm_state_start, uint64_t randstorm_state_count, uint32_t randstorm_time_start, uint32_t randstorm_time_count, uint32_t randstorm_delta_count, const XpCgrStateInput* __restrict__ cgr_inputs, uint32_t cgr_count, const XpSsleayInput* __restrict__ ssleay_inputs, uint32_t ssleay_count, uint32_t input_line_base);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerXP_e(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t profile_kind, uint64_t path_mask, uint32_t path_count, uint32_t pid_start, uint32_t pid_count, uint32_t keys_per_pid, uint64_t linear_start, uint64_t linear_count, uint64_t randstorm_state_start, uint64_t randstorm_state_count, uint32_t randstorm_time_start, uint32_t randstorm_time_count, uint32_t randstorm_delta_count, const XpCgrStateInput* __restrict__ cgr_inputs, uint32_t cgr_count, const XpSsleayInput* __restrict__ ssleay_inputs, uint32_t ssleay_count, uint32_t input_line_base);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerXP_cu(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t profile_kind, uint64_t path_mask, uint32_t path_count, uint32_t pid_start, uint32_t pid_count, uint32_t keys_per_pid, uint64_t linear_start, uint64_t linear_count, uint64_t randstorm_state_start, uint64_t randstorm_state_count, uint32_t randstorm_time_start, uint32_t randstorm_time_count, uint32_t randstorm_delta_count, const XpCgrStateInput* __restrict__ cgr_inputs, uint32_t cgr_count, const XpSsleayInput* __restrict__ ssleay_inputs, uint32_t ssleay_count, uint32_t input_line_base);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerXP_cusr(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t profile_kind, uint64_t path_mask, uint32_t path_count, uint32_t pid_start, uint32_t pid_count, uint32_t keys_per_pid, uint64_t linear_start, uint64_t linear_count, uint64_t randstorm_state_start, uint64_t randstorm_state_count, uint32_t randstorm_time_start, uint32_t randstorm_time_count, uint32_t randstorm_delta_count, const XpCgrStateInput* __restrict__ cgr_inputs, uint32_t cgr_count, const XpSsleayInput* __restrict__ ssleay_inputs, uint32_t ssleay_count, uint32_t input_line_base);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerXP_cusrxe(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t profile_kind, uint64_t path_mask, uint32_t path_count, uint32_t pid_start, uint32_t pid_count, uint32_t keys_per_pid, uint64_t linear_start, uint64_t linear_count, uint64_t randstorm_state_start, uint64_t randstorm_state_count, uint32_t randstorm_time_start, uint32_t randstorm_time_count, uint32_t randstorm_delta_count, const XpCgrStateInput* __restrict__ cgr_inputs, uint32_t cgr_count, const XpSsleayInput* __restrict__ ssleay_inputs, uint32_t ssleay_count, uint32_t input_line_base);
METAL_KERNEL KERNEL_LAUNCH_BOUNDS void workerXP_common(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t profile_kind, uint64_t path_mask, uint32_t path_count, uint32_t pid_start, uint32_t pid_count, uint32_t keys_per_pid, uint64_t linear_start, uint64_t linear_count, uint64_t randstorm_state_start, uint64_t randstorm_state_count, uint32_t randstorm_time_start, uint32_t randstorm_time_count, uint32_t randstorm_delta_count, const XpCgrStateInput* __restrict__ cgr_inputs, uint32_t cgr_count, const XpSsleayInput* __restrict__ ssleay_inputs, uint32_t ssleay_count, uint32_t input_line_base);

METAL_KERNEL void advance_P0_kernel(uint64_t advance);

METAL_KERNEL void compute_P0_H_kernel(const uint8_t* __restrict__ start_point, uint64_t step, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, int mode);

metalError_t metal_vanity_set_step_increment(uint64_t step, const void* precPtr, size_t precPitch);
metalError_t metal_vanity_set_persistent_shift(uint64_t advance);
metalError_t metal_vanity_apply_persistent_shift(uint64_t* startx_buf, uint64_t* starty_buf, MetalGridSize grid, MetalGridSize block);

METAL_KERNEL void precompute_vanity_starts_kernel(uint64_t* __restrict__ startx_buf, uint64_t* __restrict__ starty_buf, int thread_steps_pub);

// Specialized vanity kernels (one hash type per kernel for max speed)
METAL_KERNEL void workerPRIV_seq_vanity_x(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, int mode, uint8_t* start_point, uint64_t step, int thread_steps_pub, uint64_t* __restrict__ startx_buf, uint64_t* __restrict__ starty_buf);
METAL_KERNEL void workerPRIV_seq_vanity_u(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, int mode, uint8_t* start_point, uint64_t step, int thread_steps_pub, uint64_t* __restrict__ startx_buf, uint64_t* __restrict__ starty_buf);
METAL_KERNEL void workerPRIV_seq_vanity_s(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, int mode, uint8_t* start_point, uint64_t step, int thread_steps_pub, uint64_t* __restrict__ startx_buf, uint64_t* __restrict__ starty_buf);
METAL_KERNEL void workerPRIV_seq_vanity_r(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, int mode, uint8_t* start_point, uint64_t step, int thread_steps_pub, uint64_t* __restrict__ startx_buf, uint64_t* __restrict__ starty_buf);
METAL_KERNEL void workerPRIV_seq_vanity_e(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, int mode, uint8_t* start_point, uint64_t step, int thread_steps_pub, uint64_t* __restrict__ startx_buf, uint64_t* __restrict__ starty_buf);
METAL_KERNEL void workerPRIV_seq_vanity_c(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, int mode, uint8_t* start_point, uint64_t step, int thread_steps_pub, uint64_t* __restrict__ startx_buf, uint64_t* __restrict__ starty_buf);
METAL_KERNEL void workerPRIV_seq_vanity_cusr(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, int mode, uint8_t* start_point, uint64_t step, int thread_steps_pub, uint64_t* __restrict__ startx_buf, uint64_t* __restrict__ starty_buf);

METAL_KERNEL void workerPRIV_seq_128(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, int mode, uint8_t* start_point, uint64_t step, int thread_steps_pub, uint64_t* __restrict__ startx_buf, uint64_t* __restrict__ starty_buf);

METAL_KERNEL void workerPRIV_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, uint64_t round);

METAL_KERNEL void workerPRIVadd_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, int true_priv, uint64_t round);

METAL_KERNEL void workerPRIVSwap_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, uint64_t round);

METAL_KERNEL void workerPRIVPlus_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, uint64_t round);

METAL_KERNEL void workerPRIVHash_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, uint64_t round);

METAL_KERNEL void workerPRIVByte_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, int iteration, int bytePosition, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, uint64_t round);

METAL_KERNEL void workerPRIV_plus(bool* isResult, bool* buffResult, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t round);

METAL_KERNEL void workerPRIV_byte(bool* isResult, bool* buffResult, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, int iteration, int bytePosition, uint64_t round);

METAL_KERNEL void workerPRIV_hash(bool* isResult, bool* buffResult, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t round);

METAL_KERNEL void workerPRIV_swap(bool* isResult, bool* buffResult, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t round);

//Brain cores

METAL_KERNEL void workerBrain(bool* isResult, bool* buffResult, char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t round, uint8_t brain_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size);

METAL_KERNEL void workerBrain_seq(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t round, uint8_t brain_mode, int mode, uint8_t* start_point_dev, int min_len, uint32_t iter);
METAL_KERNEL void workerBrain_seq_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t round, uint8_t brain_mode, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint32_t iter);
METAL_KERNEL void workerBrain_recovery_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t round, uint8_t brain_mode, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint32_t iter);

METAL_KERNEL void workerBrain_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t round, uint8_t brain_mode, const uint32_t iteration, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen);


//OLD Mnemonic cores

METAL_KERNEL void workerOld(bool* isResult, bool* buffResult, const char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t round);

METAL_KERNEL void workerOldSeed(bool* isResult, bool* buffResult, const char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, bool custom_size, const int* __restrict__ sizes, const uint32_t sizez_size, uint8_t entropy_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size, uint64_t round);

METAL_KERNEL void workerOldSeed_seq(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t* __restrict__ start_point_dev, int min_len, int mode, bool custom_size, int custom_len, uint8_t entropy_mode, const uint32_t iter, uint64_t round);
METAL_KERNEL void workerOldSeed_seq_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, bool custom_size, int custom_len, uint8_t entropy_mode, const uint32_t iter, uint64_t round);
METAL_KERNEL void workerOldSeed_recovery_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, bool custom_size, int custom_len, uint8_t entropy_mode, const uint32_t iter, uint64_t round);

METAL_KERNEL void workerOld_seq(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint8_t* __restrict__ start_point_dev, int min_len, int mode, uint64_t round);
METAL_KERNEL void workerOld_seq_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint64_t round);
METAL_KERNEL void workerOld_recovery_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_lower_exact, const uint8_t* __restrict__ hexset_upper_exact, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint64_t round);

METAL_KERNEL void workerOld_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, uint64_t round);

METAL_KERNEL void workerOldSeed_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, bool custom_size, int custom_len, uint8_t entropy_mode, const uint32_t iter, uint64_t round);

//Armory cores

METAL_KERNEL void workerArmory(bool* isResult, bool* buffResult, const char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint32_t child, uint64_t round);
METAL_KERNEL void workerArmory_recovery_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint32_t child, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride, uint64_t round);

METAL_KERNEL void workerArmoryRoot(bool* isResult, bool* buffResult, const char* __restrict__ lines, const uint32_t* __restrict__ indexes, const uint32_t indexes_size, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint32_t child, uint64_t round, uint8_t m_mode, const uint32_t* __restrict__ iterations, const uint32_t iterations_size, bool is_str);
METAL_KERNEL void workerArmoryRoot_recovery_hexset(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint32_t child, uint64_t round, uint8_t m_mode, const uint32_t iteration, bool is_str, const uint8_t* __restrict__ hexset_start_digits, const uint8_t* __restrict__ hexset_alphabet, uint32_t hexset_base, uint32_t hexset_size, uint64_t gpu_stride);

METAL_KERNEL void workerArmory_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint32_t child, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen, uint64_t round);

METAL_KERNEL void workerArmoryRoot_gen(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, uint32_t child, uint64_t round, uint8_t m_mode, const uint32_t iteration, bool is_str, uint64_t seed_d, uint64_t seed_count, bool is_64, int entropy_len, int mode, int gen);

// Recovery checksum core (BIP39-like checksum validation for wildcard templates).
METAL_KERNEL void workerRecoveryChecksum(
    const uint16_t* base_ids,
    int words_count,
    const int* missing_positions,
    int missing_count,
    uint64_t range_start,
    uint64_t range_count,
    uint16_t* out_ids,
    uint32_t* out_count,
    uint32_t out_capacity);

METAL_KERNEL void workerRecoveryFused(
    bool* isResult,
    bool* buffResult,
    const secp256k1_ge_storage* __restrict__ precPtr,
    size_t precPitch,
    const uint16_t* base_ids,
    int words_count,
    const int* missing_positions,
    int missing_count,
    uint64_t range_start,
    uint64_t range_count,
    const uint32_t* __restrict__ d_derivations,
    const uint32_t* __restrict__ derindex,
    uint32_t der_indexes_size,
    uint32_t der_start_index,
    const char* __restrict__ passwd,
    uint32_t pass_size,
    uint32_t starter_pass,
    uint64_t round,
    uint8_t m_mode,
    const uint32_t* __restrict__ iterations,
    uint32_t iterations_size,
    bool is_str,
    bool dub_mnem,
    uint64_t* valid_count);

METAL_KERNEL void workerRecoveryEvalBatch(
    bool* isResult,
    bool* buffResult,
    const secp256k1_ge_storage* __restrict__ precPtr,
    size_t precPitch,
    const uint16_t* batch_ids,
    int words_count,
    uint32_t batch_count,
    const uint32_t* __restrict__ d_derivations,
    const uint32_t* __restrict__ derindex,
    uint32_t der_indexes_size,
    uint32_t der_start_index,
    const char* __restrict__ passwd,
    uint32_t pass_size,
    uint32_t starter_pass,
    uint64_t round,
    uint8_t m_mode,
    const uint32_t* __restrict__ iterations,
    uint32_t iterations_size,
    bool is_str,
    bool dub_mnem);

METAL_KERNEL void workerRecoverySeedBatch(
    const uint16_t* batch_ids,
    int words_count,
    uint32_t batch_count,
    const char* __restrict__ passwd,
    uint32_t pass_size,
    const uint32_t* __restrict__ iterations,
    uint32_t iterations_size,
    uint32_t* batch_master_words);

METAL_KERNEL void workerRecoveryEvalMasterBatch(
    bool* isResult,
    bool* buffResult,
    const secp256k1_ge_storage* __restrict__ precPtr,
    size_t precPitch,
    const uint16_t* batch_ids,
    const uint32_t* batch_master_words,
    int words_count,
    uint32_t batch_count,
    const uint32_t* __restrict__ d_derivations,
    const uint32_t* __restrict__ derindex,
    uint32_t der_indexes_size,
    uint32_t der_start_index,
    const char* __restrict__ passwd,
    uint32_t pass_size,
    uint32_t starter_pass,
    uint64_t round,
    uint8_t m_mode,
    bool is_str,
    bool dub_mnem);


METAL_KERNEL void workerPvkRecoveryBatch(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ base_private_key, const int* __restrict__ missing_positions, int missing_count, uint64_t range_start, uint64_t range_count, uint64_t round);
METAL_KERNEL void workerPvkRecoveryBatchEdOnly(bool* isResult, bool* buffResult, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ base_private_key, const int* __restrict__ missing_positions, int missing_count, uint64_t range_start, uint64_t range_count, uint64_t round);
METAL_KERNEL void compute_P0_H_kernel(const uint8_t* __restrict__ start_point, uint64_t step, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, int mode);
METAL_KERNEL void workerPvkRecoverySeqCompressed(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityX(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityU(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityS(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityR(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityE(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityCu(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityCus(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityCusr(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityCuse(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityCusex(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityCusrx(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqVanityCusrxe(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqSecp(bool* isResult, bool* buffResult, const secp256k1_ge_storage* __restrict__ precPtr, size_t precPitch, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count);
METAL_KERNEL void workerPvkRecoverySeqEdOnly(bool* isResult, bool* buffResult, const char* __restrict__ template_text, uint32_t template_len, const uint8_t* __restrict__ start_private_key, uint64_t step, uint64_t range_start, uint64_t range_count, uint32_t keys_per_thread, uint8_t launch_kind_raw);


metalError_t launchWorkerRecoveryChecksum(
    const uint16_t* d_base_ids,
    int words_count,
    const int* d_missing_positions,
    int missing_count,
    uint64_t range_start,
    uint64_t range_count,
    uint16_t* d_out_ids,
    uint32_t* d_out_count,
    uint32_t out_capacity,
    unsigned int block_count,
    unsigned int block_threads);

metalError_t launchWorkerRecoveryChecksumLastWordFast(
    const uint16_t* d_base_ids,
    int words_count,
    const int* d_missing_positions_without_last,
    int missing_without_last_count,
    uint64_t range_start,
    uint64_t range_count,
    uint16_t* d_out_ids,
    uint32_t* d_out_count,
    uint32_t out_capacity,
    unsigned int block_count,
    unsigned int block_threads);

metalError_t launchWorkerRecoveryFused(
    bool* d_is_result,
    bool* d_buff_result,
    const secp256k1_ge_storage* d_prec_ptr,
    size_t d_prec_pitch,
    const uint16_t* d_base_ids,
    int words_count,
    const int* d_missing_positions,
    int missing_count,
    uint64_t range_start,
    uint64_t range_count,
    const uint32_t* d_derivations,
    const uint32_t* d_derindex,
    uint32_t der_indexes_size,
    uint32_t der_start_index,
    const char* d_passwd,
    uint32_t pass_size,
    uint32_t starter_pass,
    uint64_t round,
    uint8_t m_mode,
    const uint32_t* d_iterations,
    uint32_t iterations_size,
    bool is_str,
    bool dub_mnem,
    uint64_t* d_valid_count,
    unsigned int block_count,
    unsigned int block_threads);

metalError_t launchWorkerRecoveryEvalBatch(
    bool* d_is_result,
    bool* d_buff_result,
    const secp256k1_ge_storage* d_prec_ptr,
    size_t d_prec_pitch,
    const uint16_t* d_batch_ids,
    int words_count,
    uint32_t batch_count,
    const uint32_t* d_derivations,
    const uint32_t* d_derindex,
    uint32_t der_indexes_size,
    uint32_t der_start_index,
    const char* d_passwd,
    uint32_t pass_size,
    uint32_t starter_pass,
    uint64_t round,
    uint8_t m_mode,
    const uint32_t* d_iterations,
    uint32_t iterations_size,
    bool is_str,
    bool dub_mnem,
    unsigned int block_count,
    unsigned int block_threads);

metalError_t launchWorkerRecoverySeedBatch(
    const uint16_t* d_batch_ids,
    int words_count,
    uint32_t batch_count,
    const char* d_passwd,
    uint32_t pass_size,
    const uint32_t* d_iterations,
    uint32_t iterations_size,
    uint32_t* d_batch_master_words,
    unsigned int block_count,
    unsigned int block_threads);

metalError_t launchWorkerRecoveryEvalMasterBatch(
    bool* d_is_result,
    bool* d_buff_result,
    const secp256k1_ge_storage* d_prec_ptr,
    size_t d_prec_pitch,
    const uint16_t* d_batch_ids,
    const uint32_t* d_batch_master_words,
    int words_count,
    uint32_t batch_count,
    const uint32_t* d_derivations,
    const uint32_t* d_derindex,
    uint32_t der_indexes_size,
    uint32_t der_start_index,
    const char* d_passwd,
    uint32_t pass_size,
    uint32_t starter_pass,
    uint64_t round,
    uint8_t m_mode,
    bool is_str,
    bool dub_mnem,
    unsigned int block_count,
    unsigned int block_threads);



METAL_DEVICE METAL_HOST unsigned char* hexing(unsigned char* buf, size_t buf_sz, unsigned char* hexed, size_t hexed_sz);

METAL_DEVICE unsigned char* unhex(unsigned char* str, size_t str_sz, unsigned char* unhexed, size_t unhexed_sz);

METAL_KERNEL void shaPre(size_t const prefixLen, uint32_t* hashPre);


METAL_KERNEL void ecmult_big_create(secp256k1_gej* gej_temp, secp256k1_fe* z_ratio, secp256k1_ge_storage* precPtr, size_t precPitch, unsigned int bits);

METAL_HOST void SaveResult(FILE* file, uint32_t &Founds, bool save, vector<string> Der_list);
METAL_HOST void SaveResultSeed(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list);
METAL_HOST void SaveResultBip32(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list);
METAL_HOST void SaveResultBip32Gen(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list, int bytes, int mode, int gen, int skipBytes);
METAL_HOST void SaveResultByte(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list);
METAL_HOST void SaveResultHmac(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list);
METAL_HOST void SaveResultHmacGen(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list, int bytes, int mode, int gen, int skipBytes);
METAL_HOST void SaveResultSeedGen(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list, int bytes, int mode, int gen, int skipBytes);
METAL_HOST void SaveResultGen(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list, int bytes, int mode, int gen, int skipBytes);
METAL_HOST void SaveResultPRIVGen(FILE* file, uint32_t& Founds, bool save, const vector<string>& Der_list, int bytes, int mode, int gen, int skipBytes);
METAL_HOST void SaveResultPRIV(FILE* file, uint32_t &Founds, bool save, const vector<string>& Der_list);
METAL_HOST void SaveResultPoetry(FILE* file, uint32_t& Founds, bool save, const vector<string>& Der_list);
METAL_HOST void SaveResultProfanity(FILE* file, uint32_t& Founds, bool save, const ProfanityVerifiedResult* results, unsigned long long count);
METAL_HOST void SaveResultProfanityRecovery(FILE* file, uint32_t& Founds, bool save, const ProfanityRecoveryVerifiedResult* results, unsigned long long count);
METAL_HOST void SaveResultKeystore(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files);
METAL_HOST void SaveResultWalletDat(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files);
METAL_HOST void SaveResultWalletJS(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& profiles);
METAL_HOST void SaveResultBrowserVault(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files);
METAL_HOST void SaveResultExodusSeco(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files);
METAL_HOST void SaveResultElectrumWallet(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files);
METAL_HOST void SaveResultBitcoinJWallet(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files);
METAL_HOST void SaveResultArmoryWallet(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files);
METAL_HOST void SaveResultXP(FILE* file, uint32_t& Founds, bool save, const XpReplayResult* results, unsigned long long count);
METAL_HOST void SaveResultBrain(FILE* file, uint32_t& Founds, bool save, const vector<string>& Der_list);
METAL_HOST void SaveResultBrainGen(FILE* file, uint32_t& Founds, bool save, const vector<string>& Der_list, int bytes, int mode, int gen, int skipBytes);


METAL_HOST void SaveResultOld(FILE* file, uint32_t& Founds, bool save);
METAL_HOST void SaveResultOldSeed(FILE* file, uint32_t& Founds, bool save);

METAL_HOST void SaveResultOldGen(FILE* file, uint32_t& Founds, bool save, int bytes, int mode, int gen, int skipBytes);
METAL_HOST void SaveResultOldSeedGen(FILE* file, uint32_t& Founds, bool save, int bytes, int mode, int gen, int skipBytes);

METAL_HOST void SaveResultArmory(FILE* file, uint32_t& Founds, bool save);
METAL_HOST void SaveResultArmoryGen(FILE* file, uint32_t& Founds, bool save, int bytes, int mode, int gen, int skipBytes);


METAL_HOST void SaveResultArmoryRoot(FILE* file, uint32_t& Founds, bool save);
METAL_HOST void SaveResultArmoryRootGen(FILE* file, uint32_t& Founds, bool save, int bytes, int mode, int gen, int skipBytes);

METAL_DEVICE int lltoa(uint64_t* __restrict__ val, char* __restrict__ buf, const char* __restrict__ dict);


//SHA Func and other hashing.

METAL_DEVICE  uint32_t SWAP256(uint32_t val);



METAL_DEVICE  uint64_t SWAP512(uint64_t val);

METAL_DEVICE  void md_pad_128(uint64_t* msg, const long msgLen_bytes);

METAL_DEVICE  void sha256_process2(const uint32_t* W, uint32_t* digest);

METAL_DEVICE  void sha512_d(uint64_t* input, const uint32_t length, uint64_t* hash);

METAL_DEVICE  void md_pad_128_swap(uint64_t* msg, const long msgLen_bytes);

METAL_DEVICE  void sha512_swap(uint64_t* input, const uint32_t length, uint64_t* hash);


typedef struct METAL_ALIGN(16) {
	uint64_t inner_H[8];
	uint64_t outer_H[8];
} hmac_sha512_precomp_t;

METAL_DEVICE  void hmac_sha512_const(const uint32_t* key, const uint32_t* message, uint32_t* output);
METAL_DEVICE  void hmac_sha512_const_precompute(const uint32_t* key, hmac_sha512_precomp_t* ctx);
METAL_DEVICE  void hmac_sha512_const_precomp(const hmac_sha512_precomp_t* ctx, const uint32_t* message, uint32_t* output);

METAL_DEVICE  void sha256_d(const uint32_t* pass, int pass_len, uint32_t* hash);


METAL_DEVICE  void sha256_swap_64(const uint32_t* pass, uint32_t* hash);




//TON Func.

enum class TonWalletVariant : uint8_t {
    V1R1 = 0,
    V1R2,
    V1R3,
    V2R1,
    V2R2,
    V3R1,
    V3R2,
    V4R1,
    V4R2,
    V5R1,
    HV1,
    HV2,
    HV3
};

enum class PvkEdLaunchKind : uint8_t {
    Generic = 0,
    Solana,
    Ton,
    TonAll,
    SolanaTon,
    SolanaTonAll
};

METAL_DEVICE  bool pubkey_to_hash_ton(const uint8_t* public_key, const
	char* type,
	uint8_t* out,
	size_t out_len = 32);


METAL_DEVICE  void ton_to_masterkey(char* __restrict__  mnem, uint64_t len, const char* passwd, uint32_t pass_size, extended_private_key_t* out_master);

METAL_DEVICE  void ton_seed_to_masterkey(const uint8_t* mnemom, char* passwd, extended_private_key_t* out_master);


//XOR Filter and BLOOM filter func.
METAL_DEVICE  uint64_t rng_splitmix64(uint64_t* seed);

METAL_DEVICE bool checkHashEth(const unsigned char d_hash[32]);
METAL_DEVICE bool checkHashPayload(const uint32_t* hash, uint32_t payload_len);

METAL_DEVICE bool bloom_chk_hash160(const unsigned char* bloom, const uint32_t* h);

METAL_DEVICE  uint64_t fnv1a_64(const uint8_t* buffer, size_t length);

METAL_DEVICE bool checkHash(const uint32_t hash[5]);

//Derivation func.

METAL_DEVICE
void hardened_private_child_from_private(const extended_private_key_t* parent, extended_private_key_t* child, uint32_t hardened_child_number);

METAL_DEVICE
void normal_private_child_from_private(const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const extended_private_key_t* parent, extended_private_key_t* child, uint32_t normal_child_number);

METAL_DEVICE
void normal_private_child_from_private_cached_pub(const extended_private_key_t* parent, extended_private_key_t* child, uint32_t normal_child_number, const uint8_t* cached_serialized_pub);

METAL_DEVICE
void normal_private_child_from_private_save_pub(const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const extended_private_key_t* parent, extended_private_key_t* child, uint32_t normal_child_number, uint8_t* out_serialized_pub);

METAL_DEVICE
void normal_private_child_from_private_cached_pub_precomp(const extended_private_key_t* parent, extended_private_key_t* child, uint32_t normal_child_number, const uint8_t* cached_serialized_pub, const hmac_sha512_precomp_t* hctx);

METAL_DEVICE
void hardened_private_child_from_private_precomp(const extended_private_key_t* parent, extended_private_key_t* child, uint32_t hardened_child_number, const hmac_sha512_precomp_t* hctx);

METAL_DEVICE void hardened_private_child_from_private_ed25519(const extended_private_key_t* parent, extended_private_key_t* child, uint32_t hardened_child_number);
METAL_DEVICE void hardened_private_child_from_private_ed25519_precomp(const extended_private_key_t* parent, extended_private_key_t* child, uint32_t hardened_child_number, const hmac_sha512_precomp_t* hctx);

METAL_DEVICE void ed25519_bip32_ckd_priv_hardened(const extended_private_key_t* parent, extended_private_key_t* child, uint32_t i_hardened);

METAL_DEVICE void ed25519_bip32_ckd_priv_normal(const extended_private_key_t* parent, extended_private_key_t* child, uint32_t i_normal);

METAL_DEVICE void ed25519_bip32_ckd_priv_hardened(const cardano_extended_private_key_t* parent, cardano_extended_private_key_t* child, uint32_t i_hardened);

METAL_DEVICE void ed25519_bip32_ckd_priv_normal(const cardano_extended_private_key_t* parent, cardano_extended_private_key_t* child, uint32_t i_normal);

METAL_DEVICE void cardano_byron_legacy_ckd_priv_hardened(const cardano_extended_private_key_t* parent, cardano_extended_private_key_t* child, uint32_t i_hardened);

METAL_DEVICE void cardano_ed25519_publickey_from_scalar(const uint8_t scalar[32], uint8_t pk[32]);

//Mnemonic func.

METAL_DEVICE void GenerateMnemonic(const char* __restrict__  entropy, size_t entropy_size, char* __restrict__  mnemonic_phrase, const char(*words)[34], size_t& mnemo_len);

METAL_DEVICE bool mnemonic_to_entropy(const char* phrase, int slen, uint8_t* out_entropy, uint32_t* out_len);

METAL_KERNEL void set_electrum(bool segwit_host, bool is_electrum_128, bool is_cake_wallet);

METAL_DEVICE METAL_NOINLINE
void GenerateMnemonicElectrumV2(const char* __restrict__ entropy, size_t entropy_size, char* __restrict__ mnemonic_phrase, const char (*words)[34], size_t& mnemo_len);

METAL_DEVICE void random32(uint32_t* output, int size);



METAL_DEVICE size_t random_mnemoic(char* __restrict__  mnemonic, int entropy_len_dev, bool electrum);


METAL_DEVICE size_t TweakTaproot_batch(uint8_t* __restrict__ out, const uint8_t* __restrict__ pub_uncomp, const int count, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch);

METAL_DEVICE void TweakTaproot(uint8_t* __restrict__ out, const uint8_t* __restrict__ pub_uncomp, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch);

//ICP func.

METAL_DEVICE int icp_principal_from_ed25519(const uint8_t pub_ed25519[32], uint8_t out_principal[29]);

METAL_DEVICE int icp_principal_from_secp256k1(const uint8_t pub_secp256k1[65], uint8_t out_principal[29]);

METAL_DEVICE int icp_account_identifier(const uint8_t principal29[29],
	const uint8_t* subaccount32, //NULL
	uint8_t out_ai32[32]);

//Cardano

METAL_DEVICE void byron_from_pubkey(const uint8_t* publ, uint8_t* out);

METAL_DEVICE size_t byron_daedalus_from_root_xpub(
	const uint8_t root_xpub_pub[32],
	const uint8_t root_xpub_cc[32],
	const uint8_t child_pub[32],
	const uint8_t child_cc[32],
	uint32_t accIx,
	uint32_t addrIx,
	uint8_t* out_outer);

METAL_DEVICE void cip3_icarus_master_xprv_from_entropy(
	const uint8_t* entropy, size_t entlen,
	const uint8_t* pass, size_t passlen, extended_private_key_t* master_private);

METAL_DEVICE void cip3_byron_master_xprv_from_entropy(
	const uint8_t* entropy, size_t entlen,
	extended_private_key_t* master_private);

METAL_DEVICE void cip3_icarus_master_xprv_from_entropy(
	const uint8_t* entropy, size_t entlen,
	const uint8_t* pass, size_t passlen, cardano_extended_private_key_t* master_private);

METAL_DEVICE void cip3_byron_master_xprv_from_entropy(
	const uint8_t* entropy, size_t entlen,
	cardano_extended_private_key_t* master_private);

METAL_DEVICE void cardano_byron_legacy_master_xprv_from_entropy(
	const uint8_t* entropy, size_t entlen,
	cardano_extended_private_key_t* master_private);

METAL_DEVICE void cardano_kholaw_master_xprv_from_seed(
	const uint8_t* seed, size_t seed_len,
	cardano_extended_private_key_t* master_private);


//Old Mnemonic func

#define BASE 1626
#define MAX_MNEMONIC_LENGTH 512
#define MAX_WORDS 128

extern std::unordered_map<std::string, uint16_t> globalDictMap;
extern const char* wordsOLD[1626];
extern uint8_t word_lengths[1626];


void initGlobalDictionary(const char* dictionary[], size_t dictionary_size);
void mnemonic_to_seed(const uint16_t* words_index, uint16_t word_count, uint32_t* seed_out, uint16_t* seed_count);

void seed_to_mnemonic(const uint32_t* seed, uint16_t word_count, uint16_t* words_index_out);
void words_index_to_mnemonic_text(const uint16_t* words_index, size_t word_count,
	const char* dictionary[], const uint8_t word_lengths[],
	char* mnemonic_out);
bool mnemonic_phrase_to_seed(const char* mnemonic,
	uint32_t* seed_out, uint16_t* seed_count, uint16_t* word_count_out);
void seed_to_mnemonic_phrase(const uint32_t* seed, size_t word_count,
	const char* dictionary[], const uint8_t word_lengths[],
	char* mnemonic_out);

#endif
