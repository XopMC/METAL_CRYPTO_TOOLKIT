#include "../KernelState.metalh"

kernel void SetDeep(device RuntimeConfig& config [[buffer(0)]],
                    constant uint& deep [[buffer(1)]]) {
    config.deep = deep;
}
