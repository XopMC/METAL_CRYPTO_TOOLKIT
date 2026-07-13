MACOSX_DEPLOYMENT_TARGET ?= 15.0
export MACOSX_DEPLOYMENT_TARGET

CXX := xcrun clang++
CPPFLAGS := -I../common
CXXFLAGS := -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wpedantic \
	-Wno-deprecated-declarations -pthread -arch arm64
LDFLAGS := -pthread -arch arm64

TARGET := bin/$(TOOL_NAME)
SOURCES := Source.cpp \
	../common/ToolRunner.cpp \
	../common/AddressCodecs.cpp \
	../common/Hashes.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES) ../common/ToolRunner.h ../common/AddressCodecs.h ../common/Hashes.h | bin
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SOURCES) $(LDFLAGS) -o $@

bin:
	mkdir -p $@

clean:
	rm -rf bin build
