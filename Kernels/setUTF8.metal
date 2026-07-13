#include "../KernelState.metalh"

kernel void setUTF8(device RuntimeConfig& config [[buffer(0)]]) {
    config.utf8 = 1u;
}
