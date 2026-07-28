#pragma once

#include <stdint.h>

static constexpr uint32_t WALLET_MAX_PASSWORD_LEN = 127u;
static constexpr uint32_t WALLET_PASS_STRIDE = 128u;
static constexpr uint32_t WALLET_MAX_SALT_LEN = 64u;
static constexpr uint32_t WALLET_MAX_CIPHERTEXT_LEN = 128u;
static constexpr uint32_t WALLETDAT_MAX_CRYPTED_KEY_LEN = 128u;
static constexpr uint32_t WALLETDAT_MAX_PUBKEY_LEN = 65u;
static constexpr uint32_t WALLETDAT_MAX_CKEY_SLOTS = 8u;
static constexpr uint32_t BROWSERVAULT_MAX_BLOB_LEN = 65536u;
static constexpr uint32_t ETHPRESALE_MAX_ENCSEED_LEN = 608u;
static constexpr uint32_t ELECTRUMWALLET_MAX_BLOB_LEN = 64u * 1024u * 1024u;
static constexpr uint32_t ELECTRUMWALLET_ECDH_WINDOW_BITS = 8u;
static constexpr uint32_t ELECTRUMWALLET_ECDH_WINDOWS = (256u + ELECTRUMWALLET_ECDH_WINDOW_BITS - 1u) / ELECTRUMWALLET_ECDH_WINDOW_BITS;
static constexpr uint32_t ELECTRUMWALLET_ECDH_WINDOW_VALUES = 1u << ELECTRUMWALLET_ECDH_WINDOW_BITS;
static constexpr uint32_t ELECTRUMWALLET_ECDH_PRECOMP_ENTRIES =
	ELECTRUMWALLET_ECDH_WINDOWS * ELECTRUMWALLET_ECDH_WINDOW_VALUES;
static constexpr uint32_t WALLET_MAX_MASK_LEN = 64u;
static constexpr uint32_t WALLET_MAX_MASK_CHARS = 4096u;

enum WalletModeKind : uint8_t {
	WALLET_MODE_KEYSTORE = 1,
	WALLET_MODE_WALLETDAT = 2,
	WALLET_MODE_WALLETJS = 3,
	WALLET_MODE_BROWSERVAULT = 4,
	WALLET_MODE_ELECTRUMWALLET = 5,
	WALLET_MODE_EXODUSSECO = 6,
	WALLET_MODE_BITCOINJ = 7,
	WALLET_MODE_ARMORYWALLET = 8,
	WALLET_MODE_BLOCKCHAINWALLET = 9,
	WALLET_MODE_MULTIBITWALLET = 10,
	WALLET_MODE_ETHPRESALE = 11,
	WALLET_MODE_BISQWALLET = 12,
	WALLET_MODE_DOGECHAINWALLET = 13,
	WALLET_MODE_STELLARWALLET = 14,
	WALLET_MODE_BIP38 = 15,
	WALLET_MODE_ANDROIDWALLET = 16
};

enum WalletCandidateKind : uint8_t {
	WALLET_CANDIDATE_DICTIONARY = 1,
	WALLET_CANDIDATE_MASK = 2,
	WALLET_CANDIDATE_RANGE = 3
};

enum WalletKdfType : uint8_t {
	WALLET_KDF_PBKDF2_SHA256 = 1,
	WALLET_KDF_SCRYPT = 2
};

enum WalletJsProfileKind : uint8_t {
	WALLETJS_PROFILE_SHA256_BRAIN = 1,
	WALLETJS_PROFILE_PRNG64_SEED = 2,
	WALLETJS_PROFILE_RANDSTORM_JSBN_EXACT = 3
};

enum WalletJsSourceKind : uint8_t {
	WALLETJS_SOURCE_PASSWORD = 1,
	WALLETJS_SOURCE_SEED64 = 2
};

enum WalletKeystoreResultKind : uint8_t {
	WALLET_KEYSTORE_RESULT_ETH_PRIV = 0x06,
	WALLET_KEYSTORE_RESULT_MAC_ONLY = 0x80
};

enum WalletDatResultKind : uint8_t {
	WALLET_DAT_RESULT_PRIV = 0x01,
	WALLET_DAT_RESULT_MKEY_ONLY = 0x80
};

enum BrowserVaultProfileKind : uint8_t {
	BROWSERVAULT_PROFILE_METAMASK_AES_GCM = 1,
	BROWSERVAULT_PROFILE_PHANTOM_SECRETBOX_PBKDF2 = 2,
	BROWSERVAULT_PROFILE_PHANTOM_SECRETBOX_SCRYPT = 3,
	BROWSERVAULT_PROFILE_ATOMIC_CRYPTOJS_AES = 4,
	BROWSERVAULT_PROFILE_STELLAR_AES_GCM = 20,
	BROWSERVAULT_PROFILE_BISQ_SCRYPT_AES = 21,
	BROWSERVAULT_PROFILE_MULTIBIT_HD_SCRYPT_AES = 22,
	BROWSERVAULT_PROFILE_DOGECHAIN_PBKDF2_AES_CBC = 23,
	BROWSERVAULT_PROFILE_BLOCKCHAIN_V2_PBKDF2_AES_CBC = 24,
	BROWSERVAULT_PROFILE_ETHPRESALE_PBKDF2_AES_CBC = 25,
	BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_MD5_AES = 26,
	BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_SCRYPT_AES = 27,
	BROWSERVAULT_PROFILE_BIP38_NON_EC = 28,
	BROWSERVAULT_PROFILE_ANDROID_BACKUP_PBKDF2_SHA1_AES_CBC = 29,
	BROWSERVAULT_PROFILE_BIP38_EC = 30,
	BROWSERVAULT_PROFILE_SUBSTRATE_SCRYPT_PKCS8 = 31,
	BROWSERVAULT_PROFILE_SUBSTRATE_LEGACY_PKCS8 = 32
};

enum SubstrateWalletKeyKind : uint32_t {
	SUBSTRATEWALLET_KEY_SR25519 = 1,
	SUBSTRATEWALLET_KEY_ED25519 = 2,
	SUBSTRATEWALLET_KEY_ECDSA = 3
};

struct WalletJsSpec {
	uint32_t profile_kind;
	uint32_t prng_gen;
	uint32_t prng_mode;
	uint64_t randstorm_state_start;
	uint32_t randstorm_time_start;
	uint32_t reserved0;
	uint64_t randstorm_time_count;
	uint32_t randstorm_time_delta_count;
	uint32_t reserved1;
};

struct WalletKeystoreTarget {
	uint8_t kdf_type;
	uint8_t has_address;
	uint8_t reserved0[2];
	uint32_t iterations;
	uint32_t dklen;
	uint32_t scrypt_n;
	uint32_t scrypt_r;
	uint32_t scrypt_p;
	uint32_t salt_len;
	uint32_t ciphertext_len;
	uint32_t target_index;
	uint8_t salt[WALLET_MAX_SALT_LEN];
	uint8_t iv[16];
	uint8_t ciphertext[WALLET_MAX_CIPHERTEXT_LEN];
	uint8_t mac[32];
	uint8_t address[20];
	uint8_t vault_hash[32];
};

struct WalletDatTarget {
	uint32_t iterations;
	uint32_t salt_len;
	uint32_t crypted_master_len;
	uint32_t target_index;
	uint32_t ckey_count;
	uint32_t crypted_key_len[WALLETDAT_MAX_CKEY_SLOTS];
	uint32_t pubkey_len[WALLETDAT_MAX_CKEY_SLOTS];
	uint8_t salt[WALLET_MAX_SALT_LEN];
	uint8_t crypted_master[WALLETDAT_MAX_CRYPTED_KEY_LEN];
	uint8_t crypted_key[WALLETDAT_MAX_CKEY_SLOTS][WALLETDAT_MAX_CRYPTED_KEY_LEN];
	uint8_t pubkey[WALLETDAT_MAX_CKEY_SLOTS][WALLETDAT_MAX_PUBKEY_LEN];
	uint8_t ckey_iv[WALLETDAT_MAX_CKEY_SLOTS][16];
};

struct WalletDatGroup {
	uint32_t iterations;
	uint32_t salt_len;
	uint32_t target_offset;
	uint32_t target_count;
	uint8_t salt[WALLET_MAX_SALT_LEN];
};

struct WalletDatMasterHit {
	uint64_t candidate_index;
	uint32_t target_index;
	uint32_t master_len;
	uint8_t key32[32];
	uint8_t iv16[16];
};

struct WalletDatKdfTmp {
	uint64_t digest[8];
	uint32_t active;
	uint32_t reserved0;
};

struct BrowserVaultTarget {
	uint32_t iterations;
	uint32_t salt_len;
	uint32_t iv_len;
	uint32_t ciphertext_len;
	uint32_t target_index;
	uint8_t salt[WALLET_MAX_SALT_LEN];
	uint8_t iv[32];
	uint8_t ciphertext[BROWSERVAULT_MAX_BLOB_LEN];
	uint8_t tag[16];
	uint8_t vault_hash[32];
};

struct BrowserVaultDeviceTarget {
	uint32_t iterations;
	uint32_t salt_len;
	uint32_t iv_len;
	uint32_t ciphertext_len;
	uint32_t target_index;
	uint32_t profile;
	uint32_t scrypt_n;
	uint32_t scrypt_r;
	uint32_t scrypt_p;
	uint64_t ciphertext_offset;
	uint8_t salt[WALLET_MAX_SALT_LEN];
	uint8_t iv[32];
	uint8_t tag[16];
	uint8_t vault_hash[32];
	uint32_t key_kind;
	uint32_t expected_public_len;
	uint8_t expected_public[33];
	uint8_t reserved_substrate[7];
};

struct BrowserVaultGroup {
	uint32_t iterations;
	uint32_t salt_len;
	uint32_t target_offset;
	uint32_t target_count;
	uint32_t profile;
	uint32_t scrypt_n;
	uint32_t scrypt_r;
	uint32_t scrypt_p;
	uint8_t salt[WALLET_MAX_SALT_LEN];
};

struct ExodusSecoTarget {
	uint32_t scrypt_n;
	uint32_t scrypt_r;
	uint32_t scrypt_p;
	uint32_t salt_len;
	uint32_t target_index;
	uint8_t salt[WALLET_MAX_SALT_LEN];
	uint8_t key_iv[12];
	uint8_t key_tag[16];
	uint8_t encrypted_key[32];
	uint8_t vault_hash[32];
};

struct BitcoinJWalletTarget {
	uint32_t scrypt_n;
	uint32_t scrypt_r;
	uint32_t scrypt_p;
	uint32_t salt_len;
	uint32_t encrypted_key_len;
	uint32_t pubkey_len;
	uint32_t target_index;
	uint8_t salt[WALLET_MAX_SALT_LEN];
	uint8_t iv[16];
	uint8_t encrypted_key[WALLETDAT_MAX_CRYPTED_KEY_LEN];
	uint8_t pubkey[WALLETDAT_MAX_PUBKEY_LEN];
	uint8_t wallet_hash[32];
};

struct ArmoryWalletTarget {
	uint32_t kdf_mem;
	uint32_t kdf_iterations;
	uint32_t target_index;
	uint32_t reserved0;
	uint8_t salt[32];
	uint8_t iv[16];
	uint8_t encrypted_priv[32];
	uint8_t pubkey[65];
	uint8_t addr160[20];
	uint8_t wallet_hash[32];
};

enum ElectrumWalletTargetKind : uint8_t {
	ELECTRUMWALLET_TARGET_BIE1 = 1,
	ELECTRUMWALLET_TARGET_FIELD_V1 = 2,
	ELECTRUMWALLET_TARGET_PLAINTEXT = 0x80
};

struct ElectrumWalletTarget {
	uint8_t kind;
	uint8_t ge_ready;
	uint16_t reserved0;
	uint32_t ciphertext_len;
	uint32_t target_index;
	uint32_t precomp_index;
	uint64_t ciphertext_offset;
	uint8_t ephemeral_pubkey[33];
	uint8_t reserved1[11];
	secp256k1_ge_storage ephemeral_ge;
	uint8_t mac[32];
	uint8_t detail_hash[32];
};

struct ElectrumWalletEcdhPrecomp {
	secp256k1_ge_storage table[ELECTRUMWALLET_ECDH_PRECOMP_ENTRIES];
};

struct WalletMaskSpec {
	uint32_t len;
	uint32_t total_charsets;
	uint64_t total_candidates;
	uint16_t charset_offset[WALLET_MAX_MASK_LEN];
	uint16_t charset_len[WALLET_MAX_MASK_LEN];
	uint8_t chars[WALLET_MAX_MASK_CHARS];
};

struct WalletRangeSpec {
	uint32_t len;
	uint8_t start[WALLET_MAX_PASSWORD_LEN];
};

struct WalletModeResult {
	uint8_t mode;
	uint8_t type;
	uint16_t password_len;
	uint32_t target_index;
	uint8_t password[WALLET_PASS_STRIDE];
	uint8_t priv[32];
	uint8_t payload[WALLETDAT_MAX_PUBKEY_LEN];
	uint8_t payload_len;
	uint8_t reserved[6];
};
