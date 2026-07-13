#include <metal_stdlib>
#include "../KernelState.metalh"

using namespace metal;

kernel void setDictPointer(device RuntimeConfig& config [[buffer(0)]],
                           const device char* dict [[buffer(1)]],
                           device char* customDict [[buffer(2)]],
                           uint tid [[thread_position_in_grid]]) {
    if (config.oldElectrum != 0u) {
        return;
    }

    if (dict != nullptr && customDict != nullptr) {
        if (tid < kMnemonicDictBytes) {
            customDict[tid] = dict[tid];
        }
        if (tid == 0) {
            config.useCustomDict = 1u;
        }
    } else if (tid == 0) {
        config.dictLang = 0u;
        config.useCustomDict = 0u;
    }
}
