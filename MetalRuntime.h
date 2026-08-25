#pragma once

#import <Metal/Metal.h>

#include "Kernel.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace metal_crypto {

struct Status {
    bool ok = true;
    std::string message;

    static Status success();
    static Status failure(std::string msg);
};

struct DeviceInfo {
    int index = 0;
    std::string name;
    uint32_t gpuCoreCount = 0;
    uint64_t recommendedMaxWorkingSetSize = 0;
    uint64_t currentAllocatedSize = 0;
    uint64_t maxBufferLength = 0;
    bool hasUnifiedMemory = false;
    NSUInteger maxThreadsPerThreadgroup = 1;
};

enum class XorFilterKind : uint8_t {
    Compressed,
    Uncompressed,
    UltraCompressed,
    HyperCompressed,
};

class Buffer {
public:
    Buffer() = default;
    explicit Buffer(id<MTLBuffer> buffer);

    id<MTLBuffer> native() const;
    void* contents() const;
    std::size_t size() const;
    bool valid() const;

private:
    id<MTLBuffer> buffer_ = nil;
};

class Stream {
public:
    Stream() = default;

private:
    friend class Runtime;

    struct PendingHostCopy {
        void* destination = nullptr;
        Buffer staging;
        std::size_t bytes = 0;
    };

    id<MTLCommandQueue> queue_ = nil;
    mutable std::mutex mutex_;
    mutable std::vector<id<MTLCommandBuffer>> commandBuffers_;
    mutable std::vector<PendingHostCopy> pendingHostCopies_;
};

class Runtime {
public:
    ~Runtime();

    static int availableDeviceCount();

    Status initialize(int deviceIndex, const std::string& metallibPath);
    Status makeBuffer(std::size_t bytes, Buffer& out) const;
    Status copyToBuffer(const Buffer& buffer, const void* src, std::size_t bytes, std::size_t offset = 0) const;
    Status copyFromBuffer(void* dst, const Buffer& buffer, std::size_t bytes, std::size_t offset = 0) const;
    Status memsetBuffer(const Buffer& buffer, uint8_t value, std::size_t bytes, std::size_t offset = 0) const;
    Status createStream(std::shared_ptr<Stream>& out) const;
    Status synchronize(Stream* stream = nullptr) const;
    Status copyToBufferAsync(const Buffer& buffer,
                             std::size_t offset,
                             const void* src,
                             std::size_t bytes,
                             Stream* stream = nullptr) const;
    Status copyFromBufferAsync(void* dst,
                               const Buffer& buffer,
                               std::size_t offset,
                               std::size_t bytes,
                               Stream* stream = nullptr) const;
    Status copyBufferAsync(const Buffer& dst,
                           std::size_t dstOffset,
                           const Buffer& src,
                           std::size_t srcOffset,
                           std::size_t bytes,
                           Stream* stream = nullptr) const;
    Status copyHostAsync(void* dst, const void* src, std::size_t bytes, Stream* stream = nullptr) const;
    Status memsetBufferAsync(const Buffer& buffer,
                             std::size_t offset,
                             uint8_t value,
                             std::size_t bytes,
                             Stream* stream = nullptr) const;
    Status launch1D(const std::string& functionName,
                    NSUInteger totalThreads,
                    NSUInteger threadsPerThreadgroup,
                    const std::function<void(id<MTLComputeCommandEncoder>)>& bind,
                    const std::string& pipelineKey = std::string(),
                    const std::function<void(MTLFunctionConstantValues*)>& constants = {},
                    Stream* stream = nullptr) const;
    Status makeArgumentBuffer(const std::string& functionName,
                              NSUInteger bufferIndex,
                              const std::string& pipelineKey,
                              const std::function<void(MTLFunctionConstantValues*)>& constants,
                              const std::function<void(id<MTLArgumentEncoder>)>& encode,
                              Buffer& out) const;

    const DeviceInfo& deviceInfo() const;
    bool ready() const;

    struct FilterDeviceBuffers {
        XorFilterState filters;
        FilterStorageState storage;
        Buffer filtersBuffer;
        Buffer storageBuffer;
        Buffer bloomBuffer;
        Buffer xorBuffer;
        Buffer xorUnBuffer;
        Buffer xorUcBuffer;
        Buffer xorHcBuffer;
    };

    Status initializeFilterBuffers(FilterDeviceBuffers& buffers) const;
    Status syncFilterState(FilterDeviceBuffers& buffers) const;
    Status uploadBloomFilters(const std::vector<std::string>& targets,
                              FilterDeviceBuffers& buffers,
                              RuntimeConfig* config) const;
    Status uploadXorFilters(const std::vector<std::string>& targets,
                            XorFilterKind kind,
                            FilterDeviceBuffers& buffers) const;

private:
    Status pipelineForFunction(const std::string& functionName,
                               const std::string& pipelineKey,
                               const std::function<void(MTLFunctionConstantValues*)>& constants,
                               id<MTLComputePipelineState>* out) const;
    Status functionForName(const std::string& functionName,
                           const std::string& pipelineKey,
                           const std::function<void(MTLFunctionConstantValues*)>& constants,
                           id<MTLFunction>* out) const;
    Status argumentEncoderForFunction(const std::string& functionName,
                                      NSUInteger bufferIndex,
                                      const std::string& pipelineKey,
                                      const std::function<void(MTLFunctionConstantValues*)>& constants,
                                      id<MTLArgumentEncoder>* out) const;
    Stream* resolveStream(Stream* stream) const;
    Status submit(Stream& stream,
                  id<MTLCommandBuffer> commandBuffer,
                  Stream::PendingHostCopy pending = {}) const;

    id<MTLDevice> device_ = nil;
    id<MTLCommandQueue> queue_ = nil;
    std::shared_ptr<Stream> defaultStream_;
    id<MTLLibrary> library_ = nil;
    id<MTLBinaryArchive> binaryArchive_ = nil;
    std::string binaryArchiveTemporaryPath_;
    DeviceInfo info_;
    mutable std::mutex functionCacheMutex_;
    mutable std::mutex pipelineCacheMutex_;
    mutable std::unordered_map<std::string, id<MTLFunction>> functions_;
    mutable std::unordered_map<std::string, id<MTLComputePipelineState>> pipelines_;
};

std::string defaultMetallibPath();

} // namespace metal_crypto
