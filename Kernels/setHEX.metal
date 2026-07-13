#include "../KernelState.metalh"

kernel void setHEX(device RuntimeConfig& config [[buffer(0)]]) {
    config.isHex = 1u;
}
