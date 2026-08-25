#include "../Kernels/WalletDatResolveCommon.metalh"

kernel void metal_archive_wallet_counter(
    device atomic_uint* counter [[buffer(0)]],
    device ulong* result [[buffer(1)]],
    uint tid [[thread_position_in_grid]]) {
    if (tid == 0u) {
        result[0] = wallet_atomic_add_count(counter, 1u);
    }
}
