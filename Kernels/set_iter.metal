#include "../KernelState.metalh"

kernel void set_iter(device RuntimeConfig& config [[buffer(0)]],
                     constant ulong& pbkdf_iter [[buffer(1)]]) {
    config.pbkdf2Iterations = pbkdf_iter;
}
