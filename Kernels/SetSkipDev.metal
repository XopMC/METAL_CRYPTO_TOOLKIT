#include "../KernelState.metalh"

kernel void SetSkipDev(device RuntimeConfig& config [[buffer(0)]],
                       constant ulong& skip_host [[buffer(1)]]) {
    config.skip = skip_host;
}
