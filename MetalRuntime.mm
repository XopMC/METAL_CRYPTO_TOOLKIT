#include "MetalRuntime.h"
#include "build/MetalBinaryArchiveProfiles.generated.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <sstream>
#include <vector>

#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#include <IOKit/IOKitLib.h>
#include <unistd.h>

namespace metal_crypto {

Status Status::success() {
    return {};
}

Status Status::failure(std::string msg) {
    Status status;
    status.ok = false;
    status.message = std::move(msg);
    return status;
}

Buffer::Buffer(id<MTLBuffer> buffer) : buffer_(buffer) {}

id<MTLBuffer> Buffer::native() const {
    return buffer_;
}

void* Buffer::contents() const {
    return buffer_ ? [buffer_ contents] : nullptr;
}

std::size_t Buffer::size() const {
    return buffer_ ? static_cast<std::size_t>([buffer_ length]) : 0u;
}

bool Buffer::valid() const {
    return buffer_ != nil;
}

int Runtime::availableDeviceCount() {
    NSArray<id<MTLDevice>>* devices = MTLCopyAllDevices();
    NSUInteger count = [devices count];
    if (count == 0 && MTLCreateSystemDefaultDevice() != nil) {
        count = 1;
    }
    return count > static_cast<NSUInteger>(std::numeric_limits<int>::max())
        ? std::numeric_limits<int>::max()
        : static_cast<int>(count);
}

static std::string nsErrorMessage(NSError* error) {
    if (error == nil) {
        return {};
    }
    NSString* description = [error localizedDescription];
    return description ? std::string([description UTF8String]) : std::string("unknown Metal error");
}

static bool environmentFlagEnabled(const char* name) {
    const char* value = std::getenv(name);
    return value != nullptr && std::strcmp(value, "1") == 0;
}

static const MetalBinaryArchiveProfile* binaryArchiveProfileFor(
    const std::string& functionName,
    const std::string& pipelineKey) {
    for (const MetalBinaryArchiveProfile& profile : kMetalBinaryArchiveProfiles) {
        if (functionName == profile.functionName && pipelineKey == profile.pipelineKey) {
            return &profile;
        }
    }
    return nullptr;
}

static const uint8_t* embeddedSection(const char* sectionName, unsigned long* size) {
    return getsectiondata(&_mh_execute_header, "__DATA", sectionName, size);
}

static id<MTLLibrary> newLibraryFromEmbeddedMetallib(id<MTLDevice> device, NSError** error) {
    unsigned long size = 0;
    const uint8_t* bytes = embeddedSection("__metallib", &size);
    if (bytes == nullptr || size == 0) {
        return nil;
    }
    dispatch_data_t data = dispatch_data_create(
        bytes, size, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{});
    if (data == nil) {
        return nil;
    }
    return [device newLibraryWithData:data error:error];
}

static Status materializeEmbeddedBinaryArchive(std::string& outputPath) {
    unsigned long size = 0;
    const uint8_t* bytes = embeddedSection("__metalarc", &size);
    if (bytes == nullptr || size == 0) {
        return Status::failure("embedded __DATA,__metalarc section is missing");
    }

    NSString* temporaryDirectory = NSTemporaryDirectory();
    if (temporaryDirectory == nil) {
        return Status::failure("temporary directory is unavailable");
    }
    std::string pathTemplate([temporaryDirectory fileSystemRepresentation]);
    if (pathTemplate.empty()) {
        return Status::failure("temporary directory path is empty");
    }
    if (pathTemplate.back() != '/') {
        pathTemplate.push_back('/');
    }
    pathTemplate += "metal-crypto-archive.XXXXXX.metallib";
    std::vector<char> mutablePath(pathTemplate.begin(), pathTemplate.end());
    mutablePath.push_back('\0');

    constexpr int kSuffixLength = 9;
    const int descriptor = mkstemps(mutablePath.data(), kSuffixLength);
    if (descriptor < 0) {
        return Status::failure("temporary Metal archive creation failed: " +
                               std::string(std::strerror(errno)));
    }

    const std::string candidatePath(mutablePath.data());
    std::size_t offset = 0;
    while (offset < static_cast<std::size_t>(size)) {
        const std::size_t remaining = static_cast<std::size_t>(size) - offset;
        const std::size_t chunk = std::min<std::size_t>(
            remaining, static_cast<std::size_t>(SSIZE_MAX));
        const ssize_t written = ::write(descriptor, bytes + offset, chunk);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            const std::string message = written < 0
                ? std::string(std::strerror(errno))
                : std::string("zero-byte write");
            ::close(descriptor);
            ::unlink(candidatePath.c_str());
            return Status::failure("embedded Metal archive write failed: " + message);
        }
        offset += static_cast<std::size_t>(written);
    }
    if (::close(descriptor) != 0) {
        const std::string message(std::strerror(errno));
        ::unlink(candidatePath.c_str());
        return Status::failure("embedded Metal archive close failed: " + message);
    }
    outputPath = candidatePath;
    return Status::success();
}

Runtime::~Runtime() {
    binaryArchive_ = nil;
    if (!binaryArchiveTemporaryPath_.empty()) {
        ::unlink(binaryArchiveTemporaryPath_.c_str());
    }
}

static uint32_t gpuCoreCountFromRegistry(id<MTLDevice> device) {
    if (device == nil || ![device respondsToSelector:@selector(registryID)]) {
        return 0u;
    }
    const uint64_t selectedRegistryId = [device registryID];
    if (selectedRegistryId == 0u) {
        return 0u;
    }
    io_iterator_t iterator = IO_OBJECT_NULL;
    CFMutableDictionaryRef matching = IOServiceMatching("AGXAccelerator");
    if (matching == nullptr ||
        IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) != KERN_SUCCESS) {
        return 0u;
    }

    uint32_t coreCount = 0u;
    uint32_t soleAcceleratorCoreCount = 0u;
    uint32_t acceleratorsWithCoreCount = 0u;
    io_service_t service = IO_OBJECT_NULL;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        uint64_t serviceRegistryId = 0u;
        const bool registryIdMatches =
            IORegistryEntryGetRegistryEntryID(service, &serviceRegistryId) == KERN_SUCCESS &&
            serviceRegistryId == selectedRegistryId;
        CFTypeRef value = IORegistryEntryCreateCFProperty(
            service, CFSTR("gpu-core-count"), kCFAllocatorDefault, 0);
        if (value != nullptr && CFGetTypeID(value) == CFNumberGetTypeID()) {
            int64_t count = 0;
            if (CFNumberGetValue(static_cast<CFNumberRef>(value), kCFNumberSInt64Type, &count) &&
                count > 0 && count <= static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
                const uint32_t valueCoreCount = static_cast<uint32_t>(count);
                ++acceleratorsWithCoreCount;
                soleAcceleratorCoreCount = valueCoreCount;
                if (registryIdMatches) {
                    coreCount = valueCoreCount;
                }
            }
        }
        if (value != nullptr) {
            CFRelease(value);
        }
        IOObjectRelease(service);
        if (coreCount != 0u) break;
    }
    IOObjectRelease(iterator);
    if (coreCount != 0u) return coreCount;
    return acceleratorsWithCoreCount == 1u ? soleAcceleratorCoreCount : 0u;
}

constexpr std::size_t kBloomSizeBytes = 512ull * 1024ull * 1024ull;

template <typename FingerprintType>
struct XorFilterCacheEntry {
    std::string path;
    std::vector<FingerprintType> fp;
    std::size_t size = 0;
    std::size_t arrayLength = 0;
    std::size_t segmentCount = 0;
    std::size_t segmentCountLength = 0;
    std::size_t segmentLength = 0;
    std::size_t segmentLengthMask = 0;
};

struct BloomFilterCache {
    std::vector<std::vector<uint8_t>> data;
    std::vector<std::size_t> size;
    std::vector<bool> full;
    int count = 0;
    bool loaded = false;
    std::mutex mutex;
};

template <typename FingerprintType>
struct XorFilterCache {
    std::vector<XorFilterCacheEntry<FingerprintType>> entries;
    bool loaded = false;
    std::mutex mutex;
};

static const char* xorFilterKindName(const XorFilterKind kind) {
    switch (kind) {
    case XorFilterKind::Compressed: return "Compressed";
    case XorFilterKind::Uncompressed: return "Uncompressed";
    case XorFilterKind::UltraCompressed: return "Ultra compressed";
    case XorFilterKind::HyperCompressed: return "Hyper compressed";
    }
    return "Unknown";
}

static Status checkedAddBytes(std::size_t& total, const std::size_t add, const char* label) {
    if (add > std::numeric_limits<std::size_t>::max() - total) {
        return Status::failure(std::string(label) + " byte count overflows size_t");
    }
    total += add;
    return Status::success();
}

static Status checkMetalBufferLimit(const Runtime& runtime, const std::size_t bytes, const char* label) {
    const uint64_t maxBufferLength = runtime.deviceInfo().maxBufferLength;
    if (maxBufferLength != 0 && bytes > maxBufferLength) {
        std::ostringstream out;
        out << label << " storage " << bytes
            << " bytes exceeds Metal maxBufferLength " << maxBufferLength;
        return Status::failure(out.str());
    }
    return Status::success();
}

template <typename FingerprintType>
static Status loadXorFilterCacheEntry(const std::string& path,
                                      const char* filterKind,
                                      XorFilterCacheEntry<FingerprintType>& entry) {
    FILE* file = std::fopen(path.c_str(), "rb");
    if (file == nullptr) {
        std::ostringstream out;
        out << "[!] " << filterKind << " XOR filter load failed"
            << " [file=" << path << "]"
            << " [failure=open_failed]"
            << " [fingerprint=" << sizeof(FingerprintType) << "B]";
        if (errno != 0) {
            out << " [errno=" << errno << "] [" << std::strerror(errno) << "]";
        }
        return Status::failure(out.str());
    }

    std::size_t size = 0;
    std::size_t arrayLength = 0;
    std::size_t segmentCount = 0;
    std::size_t segmentCountLength = 0;
    std::size_t segmentLength = 0;
    std::size_t segmentLengthMask = 0;
    const bool headerOk =
        std::fread(&size, sizeof(size), 1, file) == 1 &&
        std::fread(&arrayLength, sizeof(arrayLength), 1, file) == 1 &&
        std::fread(&segmentCount, sizeof(segmentCount), 1, file) == 1 &&
        std::fread(&segmentCountLength, sizeof(segmentCountLength), 1, file) == 1 &&
        std::fread(&segmentLength, sizeof(segmentLength), 1, file) == 1 &&
        std::fread(&segmentLengthMask, sizeof(segmentLengthMask), 1, file) == 1;

    if (!headerOk) {
        std::fclose(file);
        std::ostringstream out;
        out << "[!] " << filterKind << " XOR filter load failed"
            << " [file=" << path << "]"
            << " [failure=header_read_failed]"
            << " [fingerprint=" << sizeof(FingerprintType) << "B]";
        return Status::failure(out.str());
    }

    if (arrayLength == 0 ||
        arrayLength > (std::numeric_limits<std::size_t>::max() / sizeof(FingerprintType))) {
        std::fclose(file);
        std::ostringstream out;
        out << "[!] " << filterKind << " XOR filter load failed"
            << " [file=" << path << "]"
            << " [failure=invalid_header]"
            << " [fingerprint=" << sizeof(FingerprintType) << "B]"
            << " [arrayLength=" << arrayLength << "]";
        return Status::failure(out.str());
    }

    try {
        entry.fp.assign(arrayLength, FingerprintType{});
    } catch (const std::bad_alloc&) {
        std::fclose(file);
        std::ostringstream out;
        out << "[!] " << filterKind << " XOR filter load failed"
            << " [file=" << path << "]"
            << " [failure=alloc_failed]"
            << " [fingerprint=" << sizeof(FingerprintType) << "B]"
            << " [arrayLength=" << arrayLength << "]"
            << " [body_bytes=" << (arrayLength * sizeof(FingerprintType)) << "]";
        return Status::failure(out.str());
    }

    if (std::fread(entry.fp.data(), sizeof(FingerprintType), arrayLength, file) != arrayLength) {
        entry.fp.clear();
        std::fclose(file);
        std::ostringstream out;
        out << "[!] " << filterKind << " XOR filter load failed"
            << " [file=" << path << "]"
            << " [failure=body_read_failed]"
            << " [fingerprint=" << sizeof(FingerprintType) << "B]"
            << " [arrayLength=" << arrayLength << "]"
            << " [body_bytes=" << (arrayLength * sizeof(FingerprintType)) << "]";
        return Status::failure(out.str());
    }
    std::fclose(file);

    entry.path = path;
    entry.size = size;
    entry.arrayLength = arrayLength;
    entry.segmentCount = segmentCount;
    entry.segmentCountLength = segmentCountLength;
    entry.segmentLength = segmentLength;
    entry.segmentLengthMask = segmentLengthMask;

    std::fprintf(stderr,
                 "[!] Initializing %s XOR Filter [size=%zu] [host=%zu] [device=%zu] [fp=%zuB] [file=%s]\n",
                 filterKind,
                 arrayLength * sizeof(FingerprintType),
                 arrayLength * sizeof(FingerprintType),
                 arrayLength * sizeof(FingerprintType),
                 sizeof(FingerprintType),
                 path.c_str());
    return Status::success();
}

template <typename FingerprintType>
static Status ensureXorCacheLoaded(const std::vector<std::string>& targets,
                                   const char* filterKind,
                                   XorFilterCache<FingerprintType>& cache) {
    std::lock_guard<std::mutex> lock(cache.mutex);
    if (cache.loaded) {
        return Status::success();
    }
    if (targets.size() > kXorFilterSlots) {
        std::ostringstream out;
        out << "[!] Too many " << filterKind << " XOR filters: "
            << targets.size() << " (max " << kXorFilterSlots << ")";
        return Status::failure(out.str());
    }
    cache.entries.clear();
    for (const std::string& target : targets) {
        XorFilterCacheEntry<FingerprintType> entry;
        Status status = loadXorFilterCacheEntry(target, filterKind, entry);
        if (!status.ok) {
            cache.entries.clear();
            return status;
        }
        cache.entries.push_back(std::move(entry));
    }
    cache.loaded = true;
    return Status::success();
}

static void clearXorMetadata(XorFilterMetadata& metadata) {
    std::fill(std::begin(metadata.size), std::end(metadata.size), 0ull);
    std::fill(std::begin(metadata.arrayLength), std::end(metadata.arrayLength), 0ull);
    std::fill(std::begin(metadata.segmentCount), std::end(metadata.segmentCount), 0ull);
    std::fill(std::begin(metadata.segmentCountLength), std::end(metadata.segmentCountLength), 0ull);
    std::fill(std::begin(metadata.segmentLength), std::end(metadata.segmentLength), 0ull);
    std::fill(std::begin(metadata.segmentLengthMask), std::end(metadata.segmentLengthMask), 0ull);
}

template <typename FingerprintType>
static Status uploadXorCacheToRuntime(const Runtime& runtime,
                                      Runtime::FilterDeviceBuffers& buffers,
                                      XorFilterKind kind,
                                      const std::vector<XorFilterCacheEntry<FingerprintType>>& cache) {
    std::size_t totalBytes = 0;
    for (const auto& entry : cache) {
        Status status = checkedAddBytes(totalBytes, entry.fp.size() * sizeof(FingerprintType), "XOR filter");
        if (!status.ok) {
            return status;
        }
    }
    Status status = checkMetalBufferLimit(runtime, totalBytes, "XOR filter");
    if (!status.ok) {
        return status;
    }

    Buffer packed;
    status = runtime.makeBuffer(std::max<std::size_t>(totalBytes, 1u), packed);
    if (!status.ok) {
        return Status::failure(std::string(xorFilterKindName(kind)) + " XOR filter GPU upload failed [stage=MetalBuffer] [" + status.message + "]");
    }

    XorFilterMetadata* metadata = nullptr;
    uint64_t* offsets = nullptr;
    uint32_t* count = nullptr;
    Buffer* targetBuffer = nullptr;
    switch (kind) {
    case XorFilterKind::Compressed:
        metadata = &buffers.filters.x;
        offsets = buffers.storage.xorOffsets;
        count = &buffers.storage.xorCount;
        targetBuffer = &buffers.xorBuffer;
        break;
    case XorFilterKind::Uncompressed:
        metadata = &buffers.filters.uncompressed;
        offsets = buffers.storage.xorUnOffsets;
        count = &buffers.storage.xorUnCount;
        targetBuffer = &buffers.xorUnBuffer;
        break;
    case XorFilterKind::UltraCompressed:
        metadata = &buffers.filters.uc;
        offsets = buffers.storage.xorUcOffsets;
        count = &buffers.storage.xorUcCount;
        targetBuffer = &buffers.xorUcBuffer;
        break;
    case XorFilterKind::HyperCompressed:
        metadata = &buffers.filters.hc;
        offsets = buffers.storage.xorHcOffsets;
        count = &buffers.storage.xorHcCount;
        targetBuffer = &buffers.xorHcBuffer;
        break;
    }

    clearXorMetadata(*metadata);
    std::fill(offsets, offsets + kXorFilterSlots, 0ull);
    *count = static_cast<uint32_t>(cache.size());

    std::size_t offset = 0;
    for (std::size_t i = 0; i < cache.size(); ++i) {
        const auto& entry = cache[i];
        const std::size_t bytes = entry.fp.size() * sizeof(FingerprintType);
        offsets[i] = static_cast<uint64_t>(offset);
        metadata->size[i] = static_cast<uint64_t>(entry.size);
        metadata->arrayLength[i] = static_cast<uint64_t>(entry.arrayLength);
        metadata->segmentCount[i] = static_cast<uint64_t>(entry.segmentCount);
        metadata->segmentCountLength[i] = static_cast<uint64_t>(entry.segmentCountLength);
        metadata->segmentLength[i] = static_cast<uint64_t>(entry.segmentLength);
        metadata->segmentLengthMask[i] = static_cast<uint64_t>(entry.segmentLengthMask);
        if (bytes != 0) {
            status = runtime.copyToBuffer(packed, entry.fp.data(), bytes, offset);
            if (!status.ok) {
                return Status::failure(std::string(xorFilterKindName(kind)) + " XOR filter GPU upload failed [stage=MetalCopy] [" + status.message + "]");
            }
        }
        offset += bytes;
    }

    *targetBuffer = packed;
    return runtime.syncFilterState(buffers);
}

Status Runtime::initialize(int deviceIndex, const std::string& metallibPath) {
    {
        std::scoped_lock lock(functionCacheMutex_, pipelineCacheMutex_);
        functions_.clear();
        pipelines_.clear();
    }
    binaryArchive_ = nil;
    if (!binaryArchiveTemporaryPath_.empty()) {
        ::unlink(binaryArchiveTemporaryPath_.c_str());
        binaryArchiveTemporaryPath_.clear();
    }

    NSArray<id<MTLDevice>>* devices = MTLCopyAllDevices();
    if ([devices count] == 0) {
        id<MTLDevice> defaultDevice = MTLCreateSystemDefaultDevice();
        if (defaultDevice != nil) {
            devices = @[ defaultDevice ];
        }
    }
    if ([devices count] == 0) {
        return Status::failure("Metal device enumeration failed");
    }
    if (deviceIndex < 0 || static_cast<NSUInteger>(deviceIndex) >= [devices count]) {
        std::ostringstream out;
        out << "Metal device " << deviceIndex << " is out of range [0.." << ([devices count] - 1) << "]";
        return Status::failure(out.str());
    }

    device_ = [devices objectAtIndex:static_cast<NSUInteger>(deviceIndex)];
    queue_ = [device_ newCommandQueue];
    if (queue_ == nil) {
        return Status::failure("Metal command queue creation failed");
    }
    defaultStream_ = std::make_shared<Stream>();
    defaultStream_->queue_ = queue_;

    info_.index = deviceIndex;
    info_.name = std::string([[device_ name] UTF8String]);
    info_.gpuCoreCount = gpuCoreCountFromRegistry(device_);
    if ([device_ respondsToSelector:@selector(recommendedMaxWorkingSetSize)]) {
        info_.recommendedMaxWorkingSetSize = [device_ recommendedMaxWorkingSetSize];
    }
    if ([device_ respondsToSelector:@selector(currentAllocatedSize)]) {
        info_.currentAllocatedSize = [device_ currentAllocatedSize];
    }
    if ([device_ respondsToSelector:@selector(maxBufferLength)]) {
        info_.maxBufferLength = [device_ maxBufferLength];
    }
    if ([device_ respondsToSelector:@selector(hasUnifiedMemory)]) {
        info_.hasUnifiedMemory = [device_ hasUnifiedMemory];
    }
    info_.maxThreadsPerThreadgroup = 1024;

    NSError* externalError = nil;
    if (!metallibPath.empty()) {
        NSString* path = [NSString stringWithUTF8String:metallibPath.c_str()];
        NSURL* url = [NSURL fileURLWithPath:path];
        library_ = [device_ newLibraryWithURL:url error:&externalError];
    }
    if (library_ == nil) {
        NSError* embeddedError = nil;
        library_ = newLibraryFromEmbeddedMetallib(device_, &embeddedError);
        if (library_ == nil) {
            std::string errorMessage = nsErrorMessage(externalError);
            const std::string embeddedMessage = nsErrorMessage(embeddedError);
            if (errorMessage.empty()) {
                errorMessage = "library not found";
            }
            if (!embeddedMessage.empty()) {
                errorMessage += "; embedded metallib load failed: " + embeddedMessage;
            }
            return Status::failure("Metal library load failed: " + errorMessage);
        }
    }

    const bool requireBinaryArchive = environmentFlagEnabled("METAL_REQUIRE_BINARY_ARCHIVE");
    if (environmentFlagEnabled("METAL_DISABLE_BINARY_ARCHIVE")) {
        if (requireBinaryArchive) {
            return Status::failure(
                "Metal binary archive is required but disabled by METAL_DISABLE_BINARY_ARCHIVE=1");
        }
        return Status::success();
    }

    Status archiveFileStatus = materializeEmbeddedBinaryArchive(binaryArchiveTemporaryPath_);
    std::string archiveError;
    if (archiveFileStatus.ok) {
        MTLBinaryArchiveDescriptor* descriptor = [MTLBinaryArchiveDescriptor new];
        NSString* path = [NSString stringWithUTF8String:binaryArchiveTemporaryPath_.c_str()];
        descriptor.url = [NSURL fileURLWithPath:path];
        NSError* error = nil;
        binaryArchive_ = [device_ newBinaryArchiveWithDescriptor:descriptor error:&error];
        if (binaryArchive_ == nil) {
            archiveError = nsErrorMessage(error);
            ::unlink(binaryArchiveTemporaryPath_.c_str());
            binaryArchiveTemporaryPath_.clear();
        }
    } else {
        archiveError = archiveFileStatus.message;
    }
    if (binaryArchive_ == nil) {
        if (archiveError.empty()) {
            archiveError = "unknown Metal binary archive load error";
        }
        if (requireBinaryArchive) {
            return Status::failure("Metal binary archive load failed: " + archiveError);
        }
        std::fprintf(stderr,
                     "[!] Metal binary archive unavailable; using AIR fallback: %s [!]\n",
                     archiveError.c_str());
    }
    return Status::success();
}

Status Runtime::makeBuffer(std::size_t bytes, Buffer& out) const {
    if (device_ == nil) {
        return Status::failure("Metal runtime is not initialized");
    }
    const std::size_t safeBytes = std::max<std::size_t>(bytes, 1u);
    if (safeBytes > std::numeric_limits<NSUInteger>::max()) {
        return Status::failure("Metal buffer size overflows NSUInteger");
    }
    id<MTLBuffer> buffer = [device_ newBufferWithLength:static_cast<NSUInteger>(safeBytes)
                                                options:MTLResourceStorageModeShared];
    if (buffer == nil) {
        return Status::failure("Metal buffer allocation failed");
    }
    out = Buffer(buffer);
    return Status::success();
}

Status Runtime::copyToBuffer(const Buffer& buffer, const void* src, std::size_t bytes, std::size_t offset) const {
    if (!buffer.valid() || src == nullptr) {
        return Status::failure("copyToBuffer received invalid pointer");
    }
    if (offset > buffer.size() || bytes > buffer.size() - offset) {
        return Status::failure("copyToBuffer exceeds destination buffer");
    }
    std::memcpy(static_cast<uint8_t*>(buffer.contents()) + offset, src, bytes);
    [buffer.native() didModifyRange:NSMakeRange(offset, bytes)];
    return Status::success();
}

Status Runtime::copyFromBuffer(void* dst, const Buffer& buffer, std::size_t bytes, std::size_t offset) const {
    if (!buffer.valid() || dst == nullptr) {
        return Status::failure("copyFromBuffer received invalid pointer");
    }
    if (offset > buffer.size() || bytes > buffer.size() - offset) {
        return Status::failure("copyFromBuffer exceeds source buffer");
    }
    std::memcpy(dst, static_cast<const uint8_t*>(buffer.contents()) + offset, bytes);
    return Status::success();
}

Status Runtime::memsetBuffer(const Buffer& buffer, uint8_t value, std::size_t bytes, std::size_t offset) const {
    if (!buffer.valid()) {
        return Status::failure("memsetBuffer received invalid buffer");
    }
    if (offset > buffer.size() || bytes > buffer.size() - offset) {
        return Status::failure("memsetBuffer exceeds destination buffer");
    }
    std::memset(static_cast<uint8_t*>(buffer.contents()) + offset, value, bytes);
    [buffer.native() didModifyRange:NSMakeRange(offset, bytes)];
    return Status::success();
}

Stream* Runtime::resolveStream(Stream* stream) const {
    return stream != nullptr ? stream : defaultStream_.get();
}

Status Runtime::createStream(std::shared_ptr<Stream>& out) const {
    if (device_ == nil) {
        return Status::failure("Metal runtime is not initialized");
    }
    std::shared_ptr<Stream> created = std::make_shared<Stream>();
    created->queue_ = [device_ newCommandQueue];
    if (created->queue_ == nil) {
        return Status::failure("Metal command queue creation failed");
    }
    out = std::move(created);
    return Status::success();
}

Status Runtime::submit(Stream& stream,
                       id<MTLCommandBuffer> commandBuffer,
                       Stream::PendingHostCopy pending) const {
    if (commandBuffer == nil) {
        return Status::failure("Metal command buffer creation failed");
    }
    std::lock_guard<std::mutex> lock(stream.mutex_);
    stream.commandBuffers_.push_back(commandBuffer);
    if (pending.destination != nullptr && pending.bytes != 0) {
        stream.pendingHostCopies_.push_back(std::move(pending));
    }
    [commandBuffer commit];
    return Status::success();
}

Status Runtime::synchronize(Stream* requestedStream) const {
    Stream* stream = resolveStream(requestedStream);
    if (stream == nullptr || stream->queue_ == nil) {
        return Status::failure("Metal stream is not initialized");
    }

    std::lock_guard<std::mutex> lock(stream->mutex_);
    if (!stream->commandBuffers_.empty()) {
        [stream->commandBuffers_.back() waitUntilCompleted];
    }
    for (id<MTLCommandBuffer> commandBuffer : stream->commandBuffers_) {
        if ([commandBuffer error] != nil) {
            const std::string message = nsErrorMessage([commandBuffer error]);
            stream->commandBuffers_.clear();
            stream->pendingHostCopies_.clear();
            return Status::failure("Metal command buffer failed: " + message);
        }
    }
    for (const Stream::PendingHostCopy& pending : stream->pendingHostCopies_) {
        std::memcpy(pending.destination, pending.staging.contents(), pending.bytes);
    }
    stream->commandBuffers_.clear();
    stream->pendingHostCopies_.clear();
    return Status::success();
}

Status Runtime::copyToBufferAsync(const Buffer& buffer,
                                  std::size_t offset,
                                  const void* src,
                                  std::size_t bytes,
                                  Stream* requestedStream) const {
    if (!buffer.valid() || src == nullptr) {
        return Status::failure("copyToBufferAsync received invalid pointer");
    }
    if (offset > buffer.size() || bytes > buffer.size() - offset) {
        return Status::failure("copyToBufferAsync exceeds destination buffer");
    }
    if (bytes == 0) {
        return Status::success();
    }
    Stream* stream = resolveStream(requestedStream);
    Buffer staging;
    Status status = makeBuffer(bytes, staging);
    if (!status.ok) {
        return status;
    }
    std::memcpy(staging.contents(), src, bytes);
    [staging.native() didModifyRange:NSMakeRange(0, bytes)];
    id<MTLCommandBuffer> commandBuffer = [stream->queue_ commandBuffer];
    id<MTLBlitCommandEncoder> encoder = [commandBuffer blitCommandEncoder];
    [encoder copyFromBuffer:staging.native()
               sourceOffset:0
                   toBuffer:buffer.native()
          destinationOffset:offset
                       size:bytes];
    [encoder endEncoding];
    return submit(*stream, commandBuffer);
}

Status Runtime::copyFromBufferAsync(void* dst,
                                    const Buffer& buffer,
                                    std::size_t offset,
                                    std::size_t bytes,
                                    Stream* requestedStream) const {
    if (dst == nullptr || !buffer.valid()) {
        return Status::failure("copyFromBufferAsync received invalid pointer");
    }
    if (offset > buffer.size() || bytes > buffer.size() - offset) {
        return Status::failure("copyFromBufferAsync exceeds source buffer");
    }
    if (bytes == 0) {
        return Status::success();
    }
    Stream* stream = resolveStream(requestedStream);
    Buffer staging;
    Status status = makeBuffer(bytes, staging);
    if (!status.ok) {
        return status;
    }
    id<MTLCommandBuffer> commandBuffer = [stream->queue_ commandBuffer];
    id<MTLBlitCommandEncoder> encoder = [commandBuffer blitCommandEncoder];
    [encoder copyFromBuffer:buffer.native()
               sourceOffset:offset
                   toBuffer:staging.native()
          destinationOffset:0
                       size:bytes];
    [encoder endEncoding];
    return submit(*stream, commandBuffer, Stream::PendingHostCopy{dst, staging, bytes});
}

Status Runtime::copyBufferAsync(const Buffer& dst,
                                std::size_t dstOffset,
                                const Buffer& src,
                                std::size_t srcOffset,
                                std::size_t bytes,
                                Stream* requestedStream) const {
    if (!dst.valid() || !src.valid()) {
        return Status::failure("copyBufferAsync received invalid buffer");
    }
    if (dstOffset > dst.size() || bytes > dst.size() - dstOffset ||
        srcOffset > src.size() || bytes > src.size() - srcOffset) {
        return Status::failure("copyBufferAsync exceeds buffer bounds");
    }
    if (bytes == 0) {
        return Status::success();
    }
    Stream* stream = resolveStream(requestedStream);
    id<MTLCommandBuffer> commandBuffer = [stream->queue_ commandBuffer];
    id<MTLBlitCommandEncoder> encoder = [commandBuffer blitCommandEncoder];
    [encoder copyFromBuffer:src.native()
               sourceOffset:srcOffset
                   toBuffer:dst.native()
          destinationOffset:dstOffset
                       size:bytes];
    [encoder endEncoding];
    return submit(*stream, commandBuffer);
}

Status Runtime::copyHostAsync(void* dst, const void* src, std::size_t bytes, Stream* requestedStream) const {
    if (dst == nullptr || src == nullptr) {
        return Status::failure("copyHostAsync received invalid pointer");
    }
    if (bytes == 0) {
        return Status::success();
    }
    Stream* stream = resolveStream(requestedStream);
    Buffer staging;
    Status status = makeBuffer(bytes, staging);
    if (!status.ok) {
        return status;
    }
    std::memcpy(staging.contents(), src, bytes);
    id<MTLCommandBuffer> commandBuffer = [stream->queue_ commandBuffer];
    return submit(*stream, commandBuffer, Stream::PendingHostCopy{dst, staging, bytes});
}

Status Runtime::memsetBufferAsync(const Buffer& buffer,
                                  std::size_t offset,
                                  uint8_t value,
                                  std::size_t bytes,
                                  Stream* requestedStream) const {
    if (!buffer.valid()) {
        return Status::failure("memsetBufferAsync received invalid buffer");
    }
    if (offset > buffer.size() || bytes > buffer.size() - offset) {
        return Status::failure("memsetBufferAsync exceeds destination buffer");
    }
    if (bytes == 0) {
        return Status::success();
    }
    Stream* stream = resolveStream(requestedStream);
    id<MTLCommandBuffer> commandBuffer = [stream->queue_ commandBuffer];
    id<MTLBlitCommandEncoder> encoder = [commandBuffer blitCommandEncoder];
    [encoder fillBuffer:buffer.native() range:NSMakeRange(offset, bytes) value:value];
    [encoder endEncoding];
    return submit(*stream, commandBuffer);
}

Status Runtime::functionForName(const std::string& functionName,
                                const std::string& pipelineKey,
                                const std::function<void(MTLFunctionConstantValues*)>& constants,
                                id<MTLFunction>* out) const {
    if (out == nullptr) {
        return Status::failure("functionForName received null output");
    }
    std::lock_guard<std::mutex> lock(functionCacheMutex_);
    const std::string cacheKey = pipelineKey.empty() ? functionName : (functionName + "#" + pipelineKey);
    auto cached = functions_.find(cacheKey);
    if (cached != functions_.end()) {
        *out = cached->second;
        return Status::success();
    }
    if (library_ == nil) {
        return Status::failure("Metal library is not loaded");
    }
    NSString* name = [NSString stringWithUTF8String:functionName.c_str()];
    id<MTLFunction> function = nil;
    MTLFunctionConstantValues* values = nil;
    if (constants) {
        values = [MTLFunctionConstantValues new];
        constants(values);
    }

    const MetalBinaryArchiveProfile* archiveProfile =
        binaryArchiveProfileFor(functionName, pipelineKey);
    std::string archiveError;
    if (archiveProfile != nullptr && binaryArchive_ != nil) {
        MTLFunctionDescriptor* descriptor = [MTLFunctionDescriptor functionDescriptor];
        descriptor.name = name;
        descriptor.specializedName =
            [NSString stringWithUTF8String:archiveProfile->specializedName];
        descriptor.constantValues = values;
        descriptor.binaryArchives = @[ binaryArchive_ ];
        NSError* functionError = nil;
        function = [library_ newFunctionWithDescriptor:descriptor error:&functionError];
        archiveError = nsErrorMessage(functionError);
    } else if (archiveProfile != nullptr) {
        archiveError = "embedded Metal binary archive is not loaded";
    }

    if (function == nil && archiveProfile != nullptr &&
        environmentFlagEnabled("METAL_REQUIRE_BINARY_ARCHIVE")) {
        if (archiveError.empty()) {
            archiveError = "specialized function creation failed";
        }
        return Status::failure("Metal archive-backed function creation failed for " +
                               functionName + ": " + archiveError);
    }

    if (function == nil && constants) {
        NSError* functionError = nil;
        function = [library_ newFunctionWithName:name constantValues:values error:&functionError];
        if (function == nil) {
            std::string message = nsErrorMessage(functionError);
            if (!archiveError.empty()) {
                message += "; binary archive lookup failed: " + archiveError;
            }
            return Status::failure("Metal function specialization failed for " + functionName + ": " + message);
        }
    } else if (function == nil) {
        function = [library_ newFunctionWithName:name];
    }
    if (function == nil) {
        return Status::failure("Metal function not found: " + functionName);
    }
    functions_.emplace(cacheKey, function);
    *out = function;
    return Status::success();
}

Status Runtime::pipelineForFunction(const std::string& functionName,
                                    const std::string& pipelineKey,
                                    const std::function<void(MTLFunctionConstantValues*)>& constants,
                                    id<MTLComputePipelineState>* out) const {
    if (out == nullptr) {
        return Status::failure("pipelineForFunction received null output");
    }
    std::lock_guard<std::mutex> lock(pipelineCacheMutex_);
    const std::string cacheKey = pipelineKey.empty() ? functionName : (functionName + "#" + pipelineKey);
    auto cached = pipelines_.find(cacheKey);
    if (cached != pipelines_.end()) {
        *out = cached->second;
        return Status::success();
    }
    id<MTLFunction> function = nil;
    Status functionStatus = functionForName(functionName, pipelineKey, constants, &function);
    if (!functionStatus.ok) {
        return functionStatus;
    }
    const MetalBinaryArchiveProfile* archiveProfile =
        binaryArchiveProfileFor(functionName, pipelineKey);
    id<MTLComputePipelineState> pipeline = nil;
    std::string archiveError;
    if (archiveProfile != nullptr && binaryArchive_ != nil) {
        MTLComputePipelineDescriptor* descriptor = [MTLComputePipelineDescriptor new];
        descriptor.computeFunction = function;
        descriptor.binaryArchives = @[ binaryArchive_ ];
        NSError* error = nil;
        pipeline = [device_ newComputePipelineStateWithDescriptor:descriptor
                                                          options:MTLPipelineOptionFailOnBinaryArchiveMiss
                                                       reflection:nil
                                                            error:&error];
        archiveError = nsErrorMessage(error);
        if (pipeline != nil) {
            std::fprintf(stderr,
                         "[!] Metal binary archive hit: %s (%s) [!]\n",
                         functionName.c_str(), archiveProfile->specializedName);
        }
    } else if (archiveProfile != nullptr) {
        archiveError = "embedded Metal binary archive is not loaded";
    }

    if (pipeline == nil && archiveProfile != nullptr &&
        environmentFlagEnabled("METAL_REQUIRE_BINARY_ARCHIVE")) {
        if (archiveError.empty()) {
            archiveError = "profile was not found in the binary archive";
        }
        return Status::failure("Metal binary archive pipeline miss for " + functionName +
                               ": " + archiveError);
    }

    NSError* error = nil;
    if (pipeline == nil) {
        pipeline = [device_ newComputePipelineStateWithFunction:function error:&error];
    }
    if (pipeline == nil) {
        std::string message = nsErrorMessage(error);
        if (!archiveError.empty()) {
            message += "; binary archive lookup failed: " + archiveError;
        }
        return Status::failure("Metal pipeline creation failed for " + functionName + ": " + message);
    }
    pipelines_.emplace(cacheKey, pipeline);
    *out = pipeline;
    return Status::success();
}

Status Runtime::argumentEncoderForFunction(const std::string& functionName,
                                           NSUInteger bufferIndex,
                                           const std::string& pipelineKey,
                                           const std::function<void(MTLFunctionConstantValues*)>& constants,
                                           id<MTLArgumentEncoder>* out) const {
    if (out == nullptr) {
        return Status::failure("argumentEncoderForFunction received null output");
    }
    id<MTLFunction> function = nil;
    Status status = functionForName(functionName, pipelineKey, constants, &function);
    if (!status.ok) {
        if (status.message.rfind("Metal function specialization failed for ", 0) == 0) {
            return Status::failure("Metal function specialization failed for argument buffer " + functionName + ": " +
                                   status.message.substr(std::string("Metal function specialization failed for ").size() + functionName.size() + 2));
        }
        if (status.message.rfind("Metal function not found: ", 0) == 0) {
            return Status::failure("Metal function not found for argument buffer: " + functionName);
        }
        return status;
    }
    id<MTLArgumentEncoder> argumentEncoder = [function newArgumentEncoderWithBufferIndex:bufferIndex];
    if (argumentEncoder == nil) {
        return Status::failure("Metal argument encoder creation failed for " + functionName);
    }
    *out = argumentEncoder;
    return Status::success();
}

Status Runtime::makeArgumentBuffer(const std::string& functionName,
                                   NSUInteger bufferIndex,
                                   const std::string& pipelineKey,
                                   const std::function<void(MTLFunctionConstantValues*)>& constants,
                                   const std::function<void(id<MTLArgumentEncoder>)>& encode,
                                   Buffer& out) const {
    if (device_ == nil || library_ == nil) {
        return Status::failure("Metal runtime is not initialized");
    }
    id<MTLArgumentEncoder> argumentEncoder = nil;
    Status encoderStatus = argumentEncoderForFunction(functionName, bufferIndex, pipelineKey, constants, &argumentEncoder);
    if (!encoderStatus.ok) {
        return encoderStatus;
    }
    Status status = makeBuffer(static_cast<std::size_t>([argumentEncoder encodedLength]), out);
    if (!status.ok) {
        return status;
    }
    [argumentEncoder setArgumentBuffer:out.native() offset:0];
    if (encode) {
        encode(argumentEncoder);
    }
    return Status::success();
}

Status Runtime::launch1D(const std::string& functionName,
                         NSUInteger totalThreads,
                         NSUInteger threadsPerThreadgroup,
                         const std::function<void(id<MTLComputeCommandEncoder>)>& bind,
                         const std::string& pipelineKey,
                         const std::function<void(MTLFunctionConstantValues*)>& constants,
                         Stream* requestedStream) const {
    Stream* stream = resolveStream(requestedStream);
    if (stream == nullptr || stream->queue_ == nil) {
        return Status::failure("Metal runtime is not initialized");
    }
    if (totalThreads == 0) {
        return Status::success();
    }
    if (threadsPerThreadgroup == 0) {
        return Status::failure("Metal launch requested zero threads per threadgroup");
    }
    id<MTLComputePipelineState> pipeline = nil;
    Status status = pipelineForFunction(functionName, pipelineKey, constants, &pipeline);
    if (!status.ok) {
        return status;
    }

    const NSUInteger maxThreads = std::max<NSUInteger>(1, [pipeline maxTotalThreadsPerThreadgroup]);
    if (threadsPerThreadgroup > maxThreads) {
        std::ostringstream out;
        out << "Metal launch requested " << static_cast<unsigned long long>(threadsPerThreadgroup)
            << " threads per threadgroup for " << functionName
            << ", but pipeline limit is " << static_cast<unsigned long long>(maxThreads);
        return Status::failure(out.str());
    }

    id<MTLCommandBuffer> commandBuffer = [stream->queue_ commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
    [encoder setComputePipelineState:pipeline];
    if (bind) {
        bind(encoder);
    }
    const NSUInteger tg = threadsPerThreadgroup;
    [encoder dispatchThreads:MTLSizeMake(totalThreads, 1, 1)
        threadsPerThreadgroup:MTLSizeMake(tg, 1, 1)];
    [encoder endEncoding];
    return submit(*stream, commandBuffer);
}

const DeviceInfo& Runtime::deviceInfo() const {
    return info_;
}

bool Runtime::ready() const {
    return device_ != nil && queue_ != nil;
}

Status Runtime::initializeFilterBuffers(FilterDeviceBuffers& buffers) const {
    if (buffers.filtersBuffer.valid() && buffers.storageBuffer.valid()) {
        return Status::success();
    }
    buffers.filters = {};
    buffers.storage = {};

    Status status = makeBuffer(sizeof(XorFilterState), buffers.filtersBuffer);
    if (!status.ok) {
        return Status::failure("Metal XorFilterState buffer allocation failed: " + status.message);
    }
    status = makeBuffer(sizeof(FilterStorageState), buffers.storageBuffer);
    if (!status.ok) {
        return Status::failure("Metal FilterStorageState buffer allocation failed: " + status.message);
    }
    return syncFilterState(buffers);
}

Status Runtime::syncFilterState(FilterDeviceBuffers& buffers) const {
    if (!buffers.filtersBuffer.valid()) {
        Status status = makeBuffer(sizeof(XorFilterState), buffers.filtersBuffer);
        if (!status.ok) {
            return Status::failure("Metal XorFilterState buffer allocation failed: " + status.message);
        }
    }
    if (!buffers.storageBuffer.valid()) {
        Status status = makeBuffer(sizeof(FilterStorageState), buffers.storageBuffer);
        if (!status.ok) {
            return Status::failure("Metal FilterStorageState buffer allocation failed: " + status.message);
        }
    }

    Status status = copyToBuffer(buffers.filtersBuffer, &buffers.filters, sizeof(buffers.filters));
    if (!status.ok) {
        return Status::failure("Metal XorFilterState upload failed: " + status.message);
    }
    status = copyToBuffer(buffers.storageBuffer, &buffers.storage, sizeof(buffers.storage));
    if (!status.ok) {
        return Status::failure("Metal FilterStorageState upload failed: " + status.message);
    }
    return Status::success();
}

Status Runtime::uploadBloomFilters(const std::vector<std::string>& targets,
                                   FilterDeviceBuffers& buffers,
                                   RuntimeConfig* config) const {
    Status status = initializeFilterBuffers(buffers);
    if (!status.ok) {
        return status;
    }

    static BloomFilterCache cache;
    {
        std::lock_guard<std::mutex> lock(cache.mutex);
        if (!cache.loaded) {
            if (targets.size() > kBloomFilterSlots) {
                std::ostringstream out;
                out << "Too many bloom filters: " << targets.size()
                    << " (max " << kBloomFilterSlots << ")";
                return Status::failure(out.str());
            }
            cache.data.clear();
            cache.size.clear();
            cache.full.clear();
            cache.data.resize(targets.size());
            cache.size.resize(targets.size(), 0u);
            cache.full.resize(targets.size(), false);
            cache.count = 0;

            for (std::size_t i = 0; i < targets.size(); ++i) {
                std::fprintf(stderr,
                             "[!] Initializing BF [size=%lu] [file=%s]\n",
                             static_cast<unsigned long>(kBloomSizeBytes),
                             targets[i].c_str());

                if (targets[i] == "full.blf") {
                    cache.full[i] = true;
                    ++cache.count;
                    continue;
                }

                try {
                    cache.data[i].assign(kBloomSizeBytes, 0u);
                } catch (const std::bad_alloc&) {
                    return Status::failure("Metal bloom host cache allocation failed");
                }

                FILE* file = std::fopen(targets[i].c_str(), "rb");
                if (file == nullptr) {
                    cache.data[i].clear();
                    std::ostringstream out;
                    out << "Failed to open bloom file: " << targets[i];
                    return Status::failure(out.str());
                }
                const std::size_t bytesRead = std::fread(cache.data[i].data(), 1, kBloomSizeBytes, file);
                std::fclose(file);
                if (bytesRead != kBloomSizeBytes) {
                    std::fprintf(stderr,
                                 "Warning: bloom file '%s' read %zu of %zu bytes\n",
                                 targets[i].c_str(),
                                 bytesRead,
                                 kBloomSizeBytes);
                }
                cache.size[i] = kBloomSizeBytes;
                ++cache.count;
            }
            cache.loaded = true;
        }
    }

    std::fill(std::begin(buffers.storage.bloomOffsets), std::end(buffers.storage.bloomOffsets), 0ull);
    std::fill(std::begin(buffers.storage.bloomSizes), std::end(buffers.storage.bloomSizes), 0ull);
    buffers.storage.bloomCount = 0;

    std::size_t totalBytes = 0;
    int highestNonFullSlot = -1;
    for (int i = 0; i < cache.count; ++i) {
        if (i >= static_cast<int>(cache.full.size())) {
            break;
        }
        if (cache.full[static_cast<std::size_t>(i)]) {
            if (config != nullptr) {
                config->full = 1u;
            }
            continue;
        }
        highestNonFullSlot = i;
        status = checkedAddBytes(totalBytes, cache.size[static_cast<std::size_t>(i)], "Bloom filter");
        if (!status.ok) {
            return status;
        }
    }

    status = checkMetalBufferLimit(*this, totalBytes, "Bloom filter");
    if (!status.ok) {
        return status;
    }

    Buffer packed;
    status = makeBuffer(std::max<std::size_t>(totalBytes, 1u), packed);
    if (!status.ok) {
        return Status::failure("Bloom filter GPU upload failed [stage=MetalBuffer] [" + status.message + "]");
    }

    std::size_t offset = 0;
    for (int i = 0; i < cache.count; ++i) {
        if (i >= static_cast<int>(cache.full.size())) {
            break;
        }
        const std::size_t slot = static_cast<std::size_t>(i);
        if (cache.full[slot]) {
            continue;
        }
        buffers.storage.bloomOffsets[slot] = static_cast<uint64_t>(offset);
        buffers.storage.bloomSizes[slot] = static_cast<uint64_t>(cache.size[slot]);
        if (cache.size[slot] != 0) {
            status = copyToBuffer(packed, cache.data[slot].data(), cache.size[slot], offset);
            if (!status.ok) {
                return Status::failure("Bloom filter GPU upload failed [stage=MetalCopy] [" + status.message + "]");
            }
        }
        offset += cache.size[slot];
    }

    buffers.storage.bloomCount = highestNonFullSlot >= 0
        ? static_cast<uint32_t>(highestNonFullSlot + 1)
        : 0u;
    buffers.bloomBuffer = packed;
    return syncFilterState(buffers);
}

Status Runtime::uploadXorFilters(const std::vector<std::string>& targets,
                                 XorFilterKind kind,
                                 FilterDeviceBuffers& buffers) const {
    Status status = initializeFilterBuffers(buffers);
    if (!status.ok) {
        return status;
    }

    static XorFilterCache<uint32_t> compressedCache;
    static XorFilterCache<uint32_t> uncompressedCache;
    static XorFilterCache<uint16_t> ultraCompressedCache;
    static XorFilterCache<uint8_t> hyperCompressedCache;

    switch (kind) {
    case XorFilterKind::Compressed:
        status = ensureXorCacheLoaded(targets, xorFilterKindName(kind), compressedCache);
        if (!status.ok) return status;
        return uploadXorCacheToRuntime(*this, buffers, kind, compressedCache.entries);
    case XorFilterKind::Uncompressed:
        status = ensureXorCacheLoaded(targets, xorFilterKindName(kind), uncompressedCache);
        if (!status.ok) return status;
        return uploadXorCacheToRuntime(*this, buffers, kind, uncompressedCache.entries);
    case XorFilterKind::UltraCompressed:
        status = ensureXorCacheLoaded(targets, xorFilterKindName(kind), ultraCompressedCache);
        if (!status.ok) return status;
        return uploadXorCacheToRuntime(*this, buffers, kind, ultraCompressedCache.entries);
    case XorFilterKind::HyperCompressed:
        status = ensureXorCacheLoaded(targets, xorFilterKindName(kind), hyperCompressedCache);
        if (!status.ok) return status;
        return uploadXorCacheToRuntime(*this, buffers, kind, hyperCompressedCache.entries);
    }
    return Status::failure("Unknown XOR filter kind");
}

std::string defaultMetallibPath() {
    return "build/default.metallib";
}

} // namespace metal_crypto
