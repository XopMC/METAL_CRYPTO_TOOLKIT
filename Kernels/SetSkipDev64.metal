#include "../KernelState.metalh"

kernel void SetSkipDev64(device RuntimeConfig& config [[buffer(0)]],
                         constant ulong& skip_host [[buffer(1)]]) {
    config.skip64 = skip_host;
}
