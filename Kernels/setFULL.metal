#include "../KernelState.metalh"

kernel void setFULL(device RuntimeConfig& config [[buffer(0)]]) {
    config.full = 1u;
}
