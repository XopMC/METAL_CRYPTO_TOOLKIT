MACOSX_DEPLOYMENT_TARGET ?= 15.0
export MACOSX_DEPLOYMENT_TARGET

CXX := xcrun clang++
CPPFLAGS := -I../.. -I../../host_secp
CXXFLAGS := -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wpedantic \
	-Wno-deprecated-declarations -Wno-sign-compare -Wno-unused-variable \
	-pthread -arch arm64
LDFLAGS := -pthread -arch arm64

TARGET := bin/profanity_basepoint_generator
SOURCES := Source.cpp \
	../../SecpPrecompute.cpp \
	../../host_secp/HostSecp256k1.cpp
HEADERS := ../../MetalBackend.h ../../SecpPrecompute.h \
	../../Kernels/ProfanityHost.h ../../uint128_t.h ../../intrin_local.h \
	$(wildcard ../../host_secp/*.h)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS) | bin
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SOURCES) $(LDFLAGS) -o $@

bin:
	mkdir -p $@

clean:
	rm -rf bin build
