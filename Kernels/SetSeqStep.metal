#include "../KernelState.metalh"

kernel void SetSeqStep(device RuntimeConfig& config [[buffer(0)]],
                       constant ulong& step_host [[buffer(1)]]) {
    config.seqStep = step_host;
}
