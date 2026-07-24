#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <array>
#include <type_traits>
#include <utility>

#ifndef METAL_HOST
#define METAL_HOST
#endif
#ifndef METAL_DEVICE
#define METAL_DEVICE
#endif
#ifndef METAL_KERNEL
#define METAL_KERNEL
#endif
#ifndef METAL_CONSTANT
#define METAL_CONSTANT
#endif
#ifndef METAL_SHARED
#define METAL_SHARED
#endif
#ifndef METAL_FORCEINLINE
#define METAL_FORCEINLINE inline
#endif
#ifndef METAL_NOINLINE
#define METAL_NOINLINE
#endif
#ifndef METAL_ALIGN
#define METAL_ALIGN(N) __attribute__((aligned(N)))
#endif

inline uint32_t metalBitReverse32(uint32_t value) {
#if defined(__has_builtin)
#if __has_builtin(__builtin_bitreverse32)
    return __builtin_bitreverse32(value);
#endif
#endif
    value = ((value & 0x55555555u) << 1) | ((value >> 1) & 0x55555555u);
    value = ((value & 0x33333333u) << 2) | ((value >> 2) & 0x33333333u);
    value = ((value & 0x0f0f0f0fu) << 4) | ((value >> 4) & 0x0f0f0f0fu);
    value = ((value & 0x00ff00ffu) << 8) | ((value >> 8) & 0x00ff00ffu);
    return (value << 16) | (value >> 16);
}

inline int metalCountLeadingZeros32(uint32_t value) {
    return value == 0u ? 32 : __builtin_clz(value);
}

template <typename T>
inline T metalLoadReadonly(const T* ptr) {
    return *ptr;
}

struct MetalGridSize {
    unsigned int x;
    unsigned int y;
    unsigned int z;

    constexpr MetalGridSize(unsigned int vx = 1u, unsigned int vy = 1u, unsigned int vz = 1u)
        : x(vx), y(vy), z(vz) {}

    constexpr operator unsigned int() const { return x; }
};

using metalError_t = int;
using metalStream_t = void*;

static constexpr metalError_t metalSuccess = 0;
static constexpr metalError_t metalErrorInvalidValue = 1;
static constexpr metalError_t metalErrorMemoryAllocation = 2;
static constexpr metalError_t metalErrorInvalidDevicePointer = 3;
static constexpr metalError_t metalErrorInvalidDevice = 4;
static constexpr metalError_t metalErrorInvalidConfiguration = 5;
static constexpr metalError_t metalErrorNotSupported = 6;
static constexpr metalError_t metalErrorUnknown = 999;

enum metalMemcpyKind {
    metalMemcpyHostToHost = 0,
    metalMemcpyHostToDevice = 1,
    metalMemcpyDeviceToHost = 2,
    metalMemcpyDeviceToDevice = 3,
    metalMemcpyDefault = 4,
};

struct metalDeviceProp {
    char name[256] = {};
    int multiProcessorCount = 1;
    int maxThreadsPerBlock = 1024;
    uint64_t recommendedMaxWorkingSetSize = 0;
    uint64_t currentAllocatedSize = 0;
    uint64_t maxBufferLength = 0;
    int hasUnifiedMemory = 0;
};

struct MetalRandomState {
    uint64_t seed = 0;
    uint64_t counter = 0;
};

const char* metalGetErrorString(metalError_t error);
const char* metalGetErrorName(metalError_t error);
metalError_t metalMalloc(void** ptr, size_t bytes);
metalError_t metalMallocManaged(void** ptr, size_t bytes);
metalError_t metalMallocHost(void** ptr, size_t bytes);
metalError_t metalMallocPitch(void** ptr, size_t* pitch, size_t width, size_t height);
metalError_t metalFree(void* ptr);
metalError_t metalFreeHost(void* ptr);
metalError_t metalMemcpy(void* dst, const void* src, size_t bytes, metalMemcpyKind kind);
metalError_t metalMemcpyAsync(void* dst, const void* src, size_t bytes, metalMemcpyKind kind, metalStream_t stream = nullptr);
metalError_t metalMemset(void* ptr, int value, size_t bytes);
metalError_t metalMemsetAsync(void* ptr, int value, size_t bytes, metalStream_t stream = nullptr);
metalError_t metalDeviceSynchronize();
metalError_t metalStreamCreate(metalStream_t* stream);
metalError_t metalStreamSynchronize(metalStream_t stream);
metalError_t metalStreamDestroy(metalStream_t stream);
metalError_t metalSetDevice(int device);
metalError_t metalGetDevice(int* device);
metalError_t metalGetDeviceCount(int* count);
metalError_t metalGetDeviceProperties(metalDeviceProp* prop, int device);
metalError_t metalMemGetInfo(size_t* free_bytes, size_t* total_bytes);
metalError_t metalGetLastError();

metalError_t metalWriteState(const char* symbol, const void* src, size_t bytes);
metalError_t metalReadState(void* dst, const char* symbol, size_t bytes);

#define metalWriteStateValue(symbol, src, bytes, ...) metalWriteState(#symbol, (src), (bytes))
#define metalReadStateValue(dst, symbol, bytes, ...) metalReadState((dst), #symbol, (bytes))

struct MetalLaunchArg {
    static constexpr size_t kInlineStorageBytes = 256;

    enum class Kind : uint8_t {
        Pointer,
        Value,
    };

    Kind kind = Kind::Value;
    const void* data = nullptr;
    size_t size = 0;
    alignas(16) std::array<unsigned char, kInlineStorageBytes> storage{};

    MetalLaunchArg() = default;

    MetalLaunchArg(const MetalLaunchArg& other) noexcept {
        assign_from(other);
    }

    MetalLaunchArg(MetalLaunchArg&& other) noexcept {
        assign_from(other);
    }

    MetalLaunchArg& operator=(const MetalLaunchArg& other) noexcept {
        if (this != &other) {
            assign_from(other);
        }
        return *this;
    }

    MetalLaunchArg& operator=(MetalLaunchArg&& other) noexcept {
        if (this != &other) {
            assign_from(other);
        }
        return *this;
    }

private:
    void assign_from(const MetalLaunchArg& other) noexcept {
        kind = other.kind;
        size = other.size;
        storage = other.storage;
        data = (other.data == other.storage.data()) ? storage.data() : other.data;
    }
};

metalError_t metal_launch_impl(const char* function_name,
                              MetalGridSize grid,
                              MetalGridSize block,
                              const MetalLaunchArg* args,
                              size_t count);

inline MetalLaunchArg metal_make_launch_arg(std::nullptr_t) {
    MetalLaunchArg out;
    out.kind = MetalLaunchArg::Kind::Pointer;
    out.data = nullptr;
    out.size = 0;
    return out;
}

template <typename T>
inline MetalLaunchArg metal_make_launch_arg(T* value) {
    MetalLaunchArg out;
    out.kind = MetalLaunchArg::Kind::Pointer;
    out.data = reinterpret_cast<const void*>(value);
    out.size = 0;
    return out;
}

template <typename T>
inline MetalLaunchArg metal_make_launch_arg(const T* value) {
    MetalLaunchArg out;
    out.kind = MetalLaunchArg::Kind::Pointer;
    out.data = reinterpret_cast<const void*>(value);
    out.size = 0;
    return out;
}

template <typename T>
inline MetalLaunchArg metal_make_launch_arg(T& value) {
    using D = std::remove_cv_t<std::remove_reference_t<T>>;
    MetalLaunchArg out;
    out.kind = MetalLaunchArg::Kind::Value;
    out.size = sizeof(D);
    if constexpr (sizeof(D) <= MetalLaunchArg::kInlineStorageBytes) {
        std::memcpy(out.storage.data(), &value, sizeof(D));
        out.data = out.storage.data();
    } else {
        out.data = static_cast<const void*>(&value);
    }
    return out;
}

template <typename T>
inline MetalLaunchArg metal_make_launch_arg(T&& value) {
    using D = std::remove_cv_t<std::remove_reference_t<T>>;
    static_assert(sizeof(D) <= MetalLaunchArg::kInlineStorageBytes,
                  "large temporary Metal launch value must be stored before launch");
    MetalLaunchArg out;
    out.kind = MetalLaunchArg::Kind::Value;
    out.size = sizeof(D);
    std::memcpy(out.storage.data(), &value, sizeof(D));
    out.data = out.storage.data();
    return out;
}

template <typename... Args>
inline metalError_t metal_launch(const char* function_name, MetalGridSize grid, MetalGridSize block, Args&&... args) {
    std::array<MetalLaunchArg, sizeof...(Args)> packed = {
        metal_make_launch_arg(std::forward<Args>(args))...
    };
    return metal_launch_impl(function_name, grid, block, packed.data(), packed.size());
}

template <typename... Args>
inline metalError_t metal_launch(const char* function_name, unsigned int grid, unsigned int block, Args&&... args) {
    return metal_launch(function_name, MetalGridSize(grid), MetalGridSize(block), static_cast<Args&&>(args)...);
}

metalError_t loadPrefix(const char* prefix, size_t prefixLen);
metalError_t loadHashTarget(const uint32_t words[8], const uint32_t masks[8], uint32_t lenBytes, bool enabled);
metalError_t loadLevel(int level);
metalError_t loadIteration(int iteration);
metalError_t loadShaPre(uint32_t* pre);
metalError_t metalLoadBloomFilter(uint8_t* bloomFilterPtr, int count);
metalError_t metalLoadCompressedXorFilter(uint32_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h);
metalError_t metalLoadUncompressedXorFilter(uint32_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h);
metalError_t metalLoadUltraXorFilter(uint16_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h);
metalError_t metalLoadHyperXorFilter(uint8_t* deviceFilter, int count, size_t size_h, size_t arrayLength_h, size_t segmentCount_h, size_t segmentCountLength_h, size_t segmentLength_h, size_t segmentLengthMask_h);
void setSilentMode();
void setPassMode();

template <typename T>
inline metalError_t metalMalloc(T** ptr, size_t bytes) {
    return metalMalloc(reinterpret_cast<void**>(ptr), bytes);
}

template <typename T>
inline metalError_t metalMallocManaged(T** ptr, size_t bytes) {
    return metalMallocManaged(reinterpret_cast<void**>(ptr), bytes);
}

template <typename T>
inline metalError_t metalMallocHost(T** ptr, size_t bytes) {
    return metalMallocHost(reinterpret_cast<void**>(ptr), bytes);
}

template <typename T>
inline metalError_t metalMallocPitch(T** ptr, size_t* pitch, size_t width, size_t height) {
    return metalMallocPitch(reinterpret_cast<void**>(ptr), pitch, width, height);
}
