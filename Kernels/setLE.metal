#include "../KernelState.metalh"

kernel void setLE(device RuntimeConfig& config [[buffer(0)]]) {
    config.isLittleEndian = 1u;
}
