#include "../KernelState.metalh"

kernel void setPASS(device RuntimeConfig& config [[buffer(0)]]) {
    config.isPass = 1u;
}
