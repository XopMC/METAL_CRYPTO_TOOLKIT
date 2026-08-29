##############################################################################
# METAL_CRYPTO_TOOLKIT - macOS Metal CLI build
#
# Standalone production build for macOS and Apple Silicon.
##############################################################################

MACOSX_DEPLOYMENT_TARGET ?= 15.0
export MACOSX_DEPLOYMENT_TARGET

# Keep the host executable on macOS 15 while emitting Metal IR that the
# Apple7/M1 runtime compiler can consume reliably.
METAL_DEPLOYMENT_TARGET ?= 14.0

BUILD_DIR := build
BIN_DIR   := bin
TARGET    := $(BIN_DIR)/METAL_CRYPTO_TOOLKIT
ROOT_TARGET := METAL_CRYPTO_TOOLKIT
METAL_AIR := $(BUILD_DIR)/default.air
METALLIB  := $(BUILD_DIR)/default.metallib
METAL_BINARY_ARCHIVE_15 := $(BUILD_DIR)/default.binary.macos15.metallib
METAL_BINARY_ARCHIVE_26 := $(BUILD_DIR)/default.binary.macos26.metallib
METAL_BINARY_ARCHIVES := $(METAL_BINARY_ARCHIVE_15) $(METAL_BINARY_ARCHIVE_26)
METAL_BINARY_ARCHIVE_CONFIG := $(BUILD_DIR)/metal_binary_archive.mtlp-json
METAL_BINARY_ARCHIVE_PROFILE_HEADER := $(BUILD_DIR)/MetalBinaryArchiveProfiles.generated.h
METAL_BINARY_ARCHIVE_BUILDER := scripts/build_metal_binary_archive.py

CXX      := xcrun clang++
CC       := xcrun clang
METAL    := xcrun metal
METALLIB_TOOL ?= xcrun metallib
PYTHON3 ?= python3
VANITY_GROUP_SIZE ?= 1024

CXXFLAGS := -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wno-unused-parameter \
            -DMETAL_VANITY_GROUP_SIZE=$(VANITY_GROUP_SIZE) \
            -I. -Isr25519-donna-32bit -Ilib -Ilib/hash -Ilib/V
OBJCXXFLAGS := $(CXXFLAGS) -fobjc-arc
CFLAGS   := -std=c17 -O3 -DNDEBUG -Wall -Wextra -Wno-unused-parameter \
            -I. -Isr25519-donna-32bit -Ilib -Ilib/hash -Ilib/V \
            -IMoneroWallet/third_party \
            -Ithird_party/blst/bindings -Ithird_party/blst/src
DEPFLAGS := -MMD -MP
LDFLAGS  := -framework Foundation -framework CoreFoundation -framework Metal -framework IOKit
EMBED_METAL_LDFLAGS := \
	-Wl,-sectcreate,__DATA,__metallib,$(METALLIB) \
	-Wl,-sectcreate,__DATA,__metarc15,$(METAL_BINARY_ARCHIVE_15) \
	-Wl,-sectcreate,__DATA,__metarc26,$(METAL_BINARY_ARCHIVE_26)

HOST_SRCS := main.mm MetalRuntime.mm SaveFunc.mm MetalBackend.mm
HOST_OBJS := $(HOST_SRCS:%.mm=$(BUILD_DIR)/%.o)
CPP_SRCS := \
	base58.cpp filter.cpp \
	MacFileSystem.cpp \
	PoetryHost.cpp \
	SecpPrecompute.cpp \
	Kangaroo/KangarooMode.cpp \
	Bsgs/BsgsMode.cpp \
	KeyRepair/KeyRepairMode.cpp \
	Nonce/NonceMode.cpp \
	Vanity/VanityMode.cpp \
	Create2/Create2Mode.cpp \
	HdPath/HdPathMode.cpp \
	Hamming/HammingMode.cpp \
	WarpWallet/WarpWalletMode.cpp \
	Slip39/Slip39Mode.cpp \
	Aezeed/AezeedMode.cpp \
	Stronghold/StrongholdMode.cpp \
	Eth2Validator/Eth2ValidatorMode.cpp \
	Chia/ChiaMode.cpp \
	bls12_381/Bls12381.cpp \
	Algorand/AlgorandMode.cpp \
	Monero/MoneroMode.cpp \
	MoneroWallet/MoneroWalletMode.cpp \
	Brain/BrainInput.cpp \
	host_secp/HostSecp256k1.cpp \
	old_electrum_host.cpp \
	lib/util.cpp lib/Bech32.cpp lib/V/VBase58.cpp \
	lib/hash/sha256.cpp lib/hash/ripemd160.cpp \
	tools/common/Hashes.cpp \
	sr25519-donna-32bit/dot.cpp
C_SRCS := lib/base58.c \
	Monero/third_party/crypto-ops.c \
	Monero/third_party/crypto-ops-data.c \
	MoneroWallet/third_party/blake256.c \
	MoneroWallet/third_party/chacha.c \
	MoneroWallet/third_party/groestl.c \
	MoneroWallet/third_party/hash-extra-blake.c \
	MoneroWallet/third_party/hash-extra-groestl.c \
	MoneroWallet/third_party/hash-extra-jh.c \
	MoneroWallet/third_party/hash-extra-skein.c \
	MoneroWallet/third_party/jh.c \
	MoneroWallet/third_party/memwipe.c \
	MoneroWallet/third_party/skein.c \
	third_party/blst/src/client_min_pk.c
BLS_ASM_SRC := third_party/blst/build/assembly.S
BLS_ASM_OBJ := $(BUILD_DIR)/third_party/blst/build/assembly.o
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
CPP_SRCS += lib/hash/ripemd160_sse.cpp
endif

CPP_OBJS := $(CPP_SRCS:%.cpp=$(BUILD_DIR)/%.o)
C_OBJS := $(C_SRCS:%.c=$(BUILD_DIR)/%.o)
DEPS := $(HOST_OBJS:.o=.d) $(CPP_OBJS:.o=.d) $(C_OBJS:.o=.d)

LOCALIZED_HOST_HEADERS := Makefile KernelRuntime.h MacFileSystem.h Poetry.h PoetryHost.h SecpPrecompute.h \
	main_priv_recovery_runtime.h xor_filter_core.h \
	Kangaroo/KangarooMode.h \
	Bsgs/BsgsMode.h \
	KeyRepair/KeyRepairMode.h \
	Nonce/NonceMode.h \
	Vanity/VanityMode.h \
	Create2/Create2Mode.h \
	HdPath/HdPathMode.h \
	Hamming/HammingMode.h \
	WarpWallet/WarpWalletMode.h \
	Slip39/Slip39Mode.h Slip39/Slip39Wordlist.generated.h \
	Aezeed/AezeedMode.h \
	Stronghold/StrongholdMode.h \
	Eth2Validator/Eth2ValidatorMode.h \
	Chia/ChiaMode.h \
	bls12_381/Bls12381.h \
	Algorand/AlgorandMode.h \
	Monero/MoneroMode.h Monero/MoneroWordlists.generated.h \
	MoneroWallet/MoneroWalletMode.h \
	Brain/BrainInput.h \
	Prng32ComboAllowlist.generated.h Prng64ComboAllowlist.generated.h \
	Kernels/ProfanityHost.h Kernels/WalletModesHost.h Kernels/XpReplayHost.h \
	lib/hash/GPUHash.h lib/hash/sha3_ver3.h
LOCALIZED_SECP_HEADERS := Makefile SecpPrecompute.h MetalBackend.h \
	$(sort $(wildcard host_secp/*.h))
LOCALIZED_HOST_OBJS := $(BUILD_DIR)/main.o $(BUILD_DIR)/SaveFunc.o \
	$(BUILD_DIR)/SecpPrecompute.o $(BUILD_DIR)/host_secp/HostSecp256k1.o

METAL_SRCS := $(sort $(wildcard Kernels/*.metal))
METAL_HELPER_HEADERS := $(shell find lib sr25519-donna-32bit big_int fastpbkdf2 -type f \( -name '*.metalh' -o -name '*.h' \) 2>/dev/null)
METAL_HEADERS := KernelState.metalh $(sort $(wildcard Kernels/*.metalh) $(METAL_HELPER_HEADERS))
METAL_AIRS := $(METAL_SRCS:%.metal=$(BUILD_DIR)/%.air)
METAL_DEPS := $(METAL_AIRS:.air=.d)
ILLBLOOM_TEST_AIR := $(BUILD_DIR)/tests/illbloom_prng_vectors.air
ILLBLOOM_TEST_METALLIB := $(BUILD_DIR)/tests/illbloom_prng_vectors.metallib
ILLBLOOM_TEST_BIN := $(BUILD_DIR)/tests/illbloom_prng_metal_test
BLS_TEST_ASM_BIN := $(BUILD_DIR)/tests/bls12_381_vectors_asm
BLS_TEST_PORTABLE_BIN := $(BUILD_DIR)/tests/bls12_381_vectors_portable
BLS_TEST_PORTABLE_C := $(BUILD_DIR)/tests/blst_client_portable.o

.PHONY: all host clean metal-toolchain-check tools tools-clean \
	illbloom-prng-test bls12-381-test bls12-381-bench

all: $(TARGET) $(ROOT_TARGET) $(BLS_TEST_ASM_BIN) $(BLS_TEST_PORTABLE_BIN)

host: $(TARGET)

tools:
	$(MAKE) -C tools all

tools-clean:
	$(MAKE) -C tools clean

illbloom-prng-test: $(ILLBLOOM_TEST_BIN) $(ILLBLOOM_TEST_METALLIB)
	$(ILLBLOOM_TEST_BIN) $(ILLBLOOM_TEST_METALLIB)

bls12-381-test: $(BLS_TEST_ASM_BIN) $(BLS_TEST_PORTABLE_BIN)
	$(BLS_TEST_ASM_BIN)
	$(BLS_TEST_PORTABLE_BIN)

bls12-381-bench: $(BLS_TEST_ASM_BIN) $(BLS_TEST_PORTABLE_BIN)
	$(BLS_TEST_ASM_BIN) --bench 10000
	$(BLS_TEST_PORTABLE_BIN) --bench 10000

$(TARGET): $(HOST_OBJS) $(CPP_OBJS) $(C_OBJS) $(BLS_ASM_OBJ) $(METALLIB) $(METAL_BINARY_ARCHIVES) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(HOST_OBJS) $(CPP_OBJS) $(C_OBJS) $(BLS_ASM_OBJ) -o $@ $(LDFLAGS) $(EMBED_METAL_LDFLAGS)

$(ROOT_TARGET): $(TARGET)
	cp $(TARGET) $@

$(BUILD_DIR)/%.o: %.mm | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CXX) $(OBJCXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BLS_ASM_OBJ): $(BLS_ASM_SRC) $(wildcard third_party/blst/build/mach-o/*armv8.S) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) -O3 -c $< -o $@

$(BLS_TEST_PORTABLE_C): third_party/blst/src/client_min_pk.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -D__BLST_NO_ASM__ -U__aarch64__ \
		-fno-builtin -c $< -o $@

$(BLS_TEST_ASM_BIN): tests/bls12_381_vectors.cpp bls12_381/Bls12381.cpp \
		bls12_381/Bls12381.h $(BUILD_DIR)/third_party/blst/src/client_min_pk.o \
		$(BLS_ASM_OBJ) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -DBLS_TEST_BACKEND=\"arm64-asm\" \
		tests/bls12_381_vectors.cpp bls12_381/Bls12381.cpp \
		$(BUILD_DIR)/third_party/blst/src/client_min_pk.o $(BLS_ASM_OBJ) -o $@

$(BLS_TEST_PORTABLE_BIN): tests/bls12_381_vectors.cpp bls12_381/Bls12381.cpp \
		bls12_381/Bls12381.h $(BLS_TEST_PORTABLE_C) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -DBLS_TEST_BACKEND=\"portable-c\" \
		tests/bls12_381_vectors.cpp bls12_381/Bls12381.cpp \
		$(BLS_TEST_PORTABLE_C) -o $@

$(BUILD_DIR)/main.o $(BUILD_DIR)/SaveFunc.o: $(LOCALIZED_HOST_HEADERS) $(LOCALIZED_SECP_HEADERS)
$(BUILD_DIR)/SecpPrecompute.o $(BUILD_DIR)/host_secp/HostSecp256k1.o: $(LOCALIZED_SECP_HEADERS)
$(BUILD_DIR)/MetalRuntime.o: $(METAL_BINARY_ARCHIVE_PROFILE_HEADER)

$(BUILD_DIR)/%.air: %.metal | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(METAL) -std=metal3.1 -mmacosx-version-min=$(METAL_DEPLOYMENT_TARGET) \
		-DMETAL_VANITY_GROUP_SIZE=$(VANITY_GROUP_SIZE) \
		-I. -MMD -MP -MF $(@:.air=.d) -MT $@ -c $< -o $@

$(ILLBLOOM_TEST_AIR): tests/illbloom_prng_vectors.metal $(METAL_HEADERS) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(METAL) -std=metal3.1 -mmacosx-version-min=$(METAL_DEPLOYMENT_TARGET) \
		-DMETAL_VANITY_GROUP_SIZE=$(VANITY_GROUP_SIZE) \
		-I. -MMD -MP -MF $(@:.air=.d) -MT $@ -c $< -o $@

$(ILLBLOOM_TEST_METALLIB): $(ILLBLOOM_TEST_AIR)
	@$(MAKE) --no-print-directory metal-toolchain-check
	$(METALLIB_TOOL) $< -o $@

$(ILLBLOOM_TEST_BIN): tests/illbloom_prng_metal_test.mm | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CXX) $(OBJCXXFLAGS) $< -o $@ $(LDFLAGS)

$(METALLIB): $(METAL_AIRS)
	@$(MAKE) --no-print-directory metal-toolchain-check
	$(METALLIB_TOOL) $(METAL_AIRS) -o $@

$(METAL_BINARY_ARCHIVE_PROFILE_HEADER): $(METAL_BINARY_ARCHIVE_BUILDER) | $(BUILD_DIR)
	$(PYTHON3) $(METAL_BINARY_ARCHIVE_BUILDER) header --output $@

$(METAL_BINARY_ARCHIVE_15): $(METALLIB) $(METAL_BINARY_ARCHIVE_BUILDER) | $(BUILD_DIR)
	@$(MAKE) --no-print-directory metal-toolchain-check
	$(PYTHON3) $(METAL_BINARY_ARCHIVE_BUILDER) build \
		--metallib $(METALLIB) \
		--config-output $(METAL_BINARY_ARCHIVE_CONFIG) \
		--target air64-apple-macos15.0 \
		--output $@

# Serialize the two metal-tt passes: they share the system Metal compiler
# service, and concurrent archive translation is both slower and less reliable.
$(METAL_BINARY_ARCHIVE_26): $(METAL_BINARY_ARCHIVE_15) $(METALLIB) $(METAL_BINARY_ARCHIVE_BUILDER) | $(BUILD_DIR)
	@$(MAKE) --no-print-directory metal-toolchain-check
	$(PYTHON3) $(METAL_BINARY_ARCHIVE_BUILDER) build \
		--metallib $(METALLIB) \
		--config-output $(METAL_BINARY_ARCHIVE_CONFIG) \
		--target air64-apple-macos26.0 \
		--output $@

metal-toolchain-check:
	@$(METAL) -v >/dev/null 2>&1 || \
		(printf "%s\n" "[!] Metal compiler is installed but the Metal Toolchain component is missing." >&2; \
		 printf "%s\n" "[!] Install it with: xcodebuild -downloadComponent MetalToolchain" >&2; \
		 exit 1)
	@xcrun --find metallib >/dev/null 2>&1 || \
		(printf "%s\n" "[!] metallib tool is missing from the active Xcode toolchain." >&2; \
		 printf "%s\n" "[!] Install the Metal Toolchain component with: xcodebuild -downloadComponent MetalToolchain" >&2; \
		 exit 1)
	@xcrun --find metal-tt >/dev/null 2>&1 || \
		(printf "%s\n" "[!] metal-tt is missing from the active Metal toolchain." >&2; \
		 printf "%s\n" "[!] Install the Metal Toolchain component with: xcodebuild -downloadComponent MetalToolchain" >&2; \
		 exit 1)
	@xcrun --find metal-lipo >/dev/null 2>&1 || \
		(printf "%s\n" "[!] metal-lipo is missing from the active Metal toolchain." >&2; \
		 printf "%s\n" "[!] Install the Metal Toolchain component with: xcodebuild -downloadComponent MetalToolchain" >&2; \
		 exit 1)

$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) $(ROOT_TARGET)

-include $(DEPS) $(METAL_DEPS) $(ILLBLOOM_TEST_AIR:.air=.d)
