#include "../KernelState.metalh"

kernel void setEd25519_scalar(device RuntimeConfig& config [[buffer(0)]]) {
    config.isEd25519Scalar = 1u;
    config.isEd25519Hash = 0u;
}
