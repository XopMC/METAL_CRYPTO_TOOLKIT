#include "../Kernels/FoundCommon.metalh"

kernel void metal_archive_atomic_counter(
    device atomic_uint* counter [[buffer(0)]],
    device ulong* result [[buffer(1)]],
    uint tid [[thread_position_in_grid]]) {
    if (tid == 0u) {
        result[0] = found_atomic_add_count(counter, 1u);
    }
}
