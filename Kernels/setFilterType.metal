#include "PrngCommon.metalh"

kernel void setFilterType(device RuntimeConfig& config [[buffer(0)]],
                          constant uint& bloomUse [[buffer(1)]],
                          constant uint& xorFilter [[buffer(2)]],
                          constant uint& xorFilterUn [[buffer(3)]],
                          constant uint& xorFilterUc [[buffer(4)]],
                          constant uint& xorFilterHc [[buffer(5)]]) {
    config.useBloom = bloomUse;
    config.useXor = xorFilter;
    config.useXorUn = xorFilterUn;
    config.useXorUc = xorFilterUc;
    config.useXorHc = xorFilterHc;
    ulong rng_counter = 0x726b2b9d438b9d4dul;
    config.seed = rng_splitmix64(rng_counter);
}
