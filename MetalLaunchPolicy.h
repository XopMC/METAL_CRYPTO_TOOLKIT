#pragma once

#include <algorithm>
#include <cstring>

namespace metal_crypto {

struct LaunchGeometry {
    unsigned int blocks;
    unsigned int threads;
};

inline bool isM1Device(const char* name) {
    return name != nullptr &&
        (std::strcmp(name, "Apple M1") == 0 ||
         std::strcmp(name, "Apple M1 Pro") == 0 ||
         std::strcmp(name, "Apple M1 Max") == 0 ||
         std::strcmp(name, "Apple M1 Ultra") == 0);
}

// Limit the batch before input buffers and generator ranges are calculated.
// Explicit CLI dimensions remain authoritative; never replay a failed batch.
inline LaunchGeometry smallBatchGeometry(LaunchGeometry geometry,
                                         unsigned int gpuCores,
                                         bool explicitBlocks,
                                         bool explicitThreads) {
    if (!explicitThreads) geometry.threads = std::min(geometry.threads, 32u);
    if (!explicitBlocks) {
        const unsigned int coreBudget = std::min(std::max(gpuCores, 1u), 8u) * 4u;
        geometry.blocks = std::min(geometry.blocks, coreBudget);
    }
    return geometry;
}

} // namespace metal_crypto
