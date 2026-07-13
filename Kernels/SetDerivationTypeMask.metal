#include "../KernelState.metalh"

kernel void SetDerivationTypeMask(device RuntimeConfig& config [[buffer(0)]],
                                  constant uchar& mask [[buffer(1)]]) {
    config.derivationTypeMask = mask;
}
