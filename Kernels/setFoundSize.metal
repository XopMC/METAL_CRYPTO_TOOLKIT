#include "../KernelState.metalh"

kernel void setFoundSize(device RuntimeConfig& config [[buffer(0)]],
                         constant uint& max_founds [[buffer(1)]]) {
    config.maxFounds = max_founds;
}
