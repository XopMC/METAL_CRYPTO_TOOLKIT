#include "../KernelState.metalh"

kernel void setEd25519_hash(device RuntimeConfig& config [[buffer(0)]]) {
    config.isEd25519Scalar = 0u;
    config.isEd25519Hash = 1u;
}
