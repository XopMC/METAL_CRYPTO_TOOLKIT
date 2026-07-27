##############################################################################
# METAL_CRYPTO_TOOLKIT - macOS Metal CLI build
#
# Standalone production build for macOS and Apple Silicon.
##############################################################################

MACOSX_DEPLOYMENT_TARGET ?= 15.0
export MACOSX_DEPLOYMENT_TARGET

BUILD_DIR := build
BIN_DIR   := bin
TARGET    := $(BIN_DIR)/METAL_CRYPTO_TOOLKIT
ROOT_TARGET := METAL_CRYPTO_TOOLKIT
METAL_AIR := $(BUILD_DIR)/default.air
METALLIB  := $(BUILD_DIR)/default.metallib

CXX      := xcrun clang++
METAL    := xcrun metal
METALLIB_TOOL ?= xcrun metallib
VANITY_GROUP_SIZE ?= 1024

CXXFLAGS := -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wno-unused-parameter \
            -DMETAL_VANITY_GROUP_SIZE=$(VANITY_GROUP_SIZE) \
            -I. -Isr25519-donna-32bit -Ilib -Ilib/hash -Ilib/V
OBJCXXFLAGS := $(CXXFLAGS) -fobjc-arc
CFLAGS   := -std=c17 -O3 -DNDEBUG -Wall -Wextra -Wno-unused-parameter \
            -I. -Isr25519-donna-32bit -Ilib -Ilib/hash -Ilib/V
DEPFLAGS := -MMD -MP
LDFLAGS  := -framework Foundation -framework Metal -framework IOKit
EMBED_METALLIB_LDFLAGS := -Wl,-sectcreate,__DATA,__metallib,$(METALLIB)

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
	host_secp/HostSecp256k1.cpp \
	old_electrum_host.cpp \
	lib/util.cpp lib/Bech32.cpp lib/V/VBase58.cpp \
	lib/hash/sha256.cpp lib/hash/ripemd160.cpp \
	sr25519-donna-32bit/dot.cpp
C_SRCS := lib/base58.c
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

.PHONY: all host clean metal-toolchain-check tools tools-clean

all: $(TARGET) $(ROOT_TARGET)

host: $(TARGET)

tools:
	$(MAKE) -C tools all

tools-clean:
	$(MAKE) -C tools clean

$(TARGET): $(HOST_OBJS) $(CPP_OBJS) $(C_OBJS) $(METALLIB) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(HOST_OBJS) $(CPP_OBJS) $(C_OBJS) -o $@ $(LDFLAGS) $(EMBED_METALLIB_LDFLAGS)

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
	xcrun clang $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/main.o $(BUILD_DIR)/SaveFunc.o: $(LOCALIZED_HOST_HEADERS) $(LOCALIZED_SECP_HEADERS)
$(BUILD_DIR)/SecpPrecompute.o $(BUILD_DIR)/host_secp/HostSecp256k1.o: $(LOCALIZED_SECP_HEADERS)

$(BUILD_DIR)/%.air: %.metal | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(METAL) -std=metal3.1 -DMETAL_VANITY_GROUP_SIZE=$(VANITY_GROUP_SIZE) \
		-I. -MMD -MP -MF $(@:.air=.d) -MT $@ -c $< -o $@

$(METALLIB): $(METAL_AIRS)
	@$(MAKE) --no-print-directory metal-toolchain-check
	$(METALLIB_TOOL) $(METAL_AIRS) -o $@

metal-toolchain-check:
	@$(METAL) -v >/dev/null 2>&1 || \
		(printf "%s\n" "[!] Metal compiler is installed but the Metal Toolchain component is missing." >&2; \
		 printf "%s\n" "[!] Install it with: xcodebuild -downloadComponent MetalToolchain" >&2; \
		 exit 1)
	@xcrun --find metallib >/dev/null 2>&1 || \
		(printf "%s\n" "[!] metallib tool is missing from the active Xcode toolchain." >&2; \
		 printf "%s\n" "[!] Install the Metal Toolchain component with: xcodebuild -downloadComponent MetalToolchain" >&2; \
		 exit 1)

$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) $(ROOT_TARGET)

-include $(DEPS) $(METAL_DEPS)
