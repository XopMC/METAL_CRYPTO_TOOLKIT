#include <metal_stdlib>
#include "../KernelState.metalh"

using namespace metal;

kernel void set_electrum(device RuntimeConfig& config [[buffer(0)]],
                         constant bool& segwit_host [[buffer(1)]],
                         constant bool& is_electrum_128 [[buffer(2)]],
                         constant bool& is_cake_wallet [[buffer(3)]],
                         uint tid [[thread_position_in_grid]]) {
    if (tid != 0) {
        return;
    }
    config.electrumSegwit = segwit_host ? 1u : 0u;
    config.electrum128 = is_electrum_128 ? 1u : 0u;
    config.electrumCakeWallet = is_cake_wallet ? 1u : 0u;
}
