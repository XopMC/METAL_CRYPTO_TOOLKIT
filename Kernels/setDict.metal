#include <metal_stdlib>
#include "../KernelState.metalh"
#include "Words.metalh"

using namespace metal;

kernel void setDict(device RuntimeConfig& config [[buffer(0)]],
                    constant int& lang [[buffer(1)]],
                    uint tid [[thread_position_in_grid]]) {
    if (tid != 0 || config.oldElectrum != 0u) {
        return;
    }
    if (lang >= 0 && lang <= 9) {
        config.dictLang = uint(lang);
    } else {
        config.dictLang = 0u;
    }
    config.useCustomDict = 0u;
}
