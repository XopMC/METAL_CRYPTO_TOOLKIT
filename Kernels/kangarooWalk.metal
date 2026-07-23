#include "KangarooCore.metalh"

static_assert(KANGAROO_GROUP_SIZE == 16u,
              "legacy kangaroo walk requires the accepted group size");

kernel void kangarooWalk(device KangarooState* states [[buffer(0)]],
                         const device ulong* jumps1 [[buffer(1)]],
                         const device ulong* jumps2 [[buffer(2)]],
                         const device ulong* jumps3 [[buffer(3)]],
                         device KangarooDP* output [[buffer(4)]],
                         device atomic_uint* output_count [[buffer(5)]],
                         constant KangarooWalkParams& params [[buffer(6)]],
                         uint tid [[thread_position_in_grid]]) {
    kangaroo_walk_impl<KANGAROO_GROUP_SIZE>(
        states, jumps1, jumps2, jumps3, output, output_count, params, tid);
}
