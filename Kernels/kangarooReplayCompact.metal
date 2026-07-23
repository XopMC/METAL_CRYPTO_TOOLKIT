#include "KangarooCore.metalh"

kernel void kangarooWalkCompact(
    device KangarooState* states [[buffer(0)]],
    const device ulong* jumps1 [[buffer(1)]],
    const device ulong* jumps2 [[buffer(2)]],
    const device ulong* jumps3 [[buffer(3)]],
    device ushort* hop_metadata [[buffer(4)]],
    device KangarooCompactDpX* dp_x [[buffer(5)]],
    device uint* dp_counts [[buffer(6)]],
    device atomic_uint* replay_error [[buffer(7)]],
    constant KangarooWalkParams& params [[buffer(8)]],
    uint tid [[thread_position_in_grid]])
{
    kangaroo_walk_compact_impl<KANGAROO_GROUP_SIZE>(
        states,
        jumps1,
        jumps2,
        jumps3,
        hop_metadata,
        dp_x,
        dp_counts,
        replay_error,
        params,
        tid);
}

kernel void kangarooReplayCompact(
    device KangarooState* states [[buffer(0)]],
    const device ulong* jumps1 [[buffer(1)]],
    const device ulong* jumps2 [[buffer(2)]],
    const device ulong* jumps3 [[buffer(3)]],
    const device ushort* hop_metadata [[buffer(4)]],
    const device KangarooCompactDpX* dp_x [[buffer(5)]],
    const device uint* dp_counts [[buffer(6)]],
    device KangarooDP* output [[buffer(7)]],
    device atomic_uint* output_count [[buffer(8)]],
    device atomic_uint* replay_error [[buffer(9)]],
    constant KangarooWalkParams& params [[buffer(10)]],
    uint state_index [[thread_position_in_grid]])
{
    kangaroo_replay_compact_impl(
        states,
        jumps1,
        jumps2,
        jumps3,
        hop_metadata,
        dp_x,
        dp_counts,
        output,
        output_count,
        replay_error,
        params,
        state_index);
}

kernel void kangarooReplayWide(
    device KangarooState* states [[buffer(0)]],
    const device ulong* jumps1 [[buffer(1)]],
    const device ulong* jumps2 [[buffer(2)]],
    const device ulong* jumps3 [[buffer(3)]],
    const device ushort* hop_metadata [[buffer(4)]],
    const device KangarooCompactDpX* dp_x [[buffer(5)]],
    const device uint* dp_counts [[buffer(6)]],
    device KangarooDP* output [[buffer(7)]],
    device atomic_uint* output_count [[buffer(8)]],
    device atomic_uint* replay_error [[buffer(9)]],
    constant KangarooWalkParams& params [[buffer(10)]],
    uint state_index [[thread_position_in_grid]])
{
    kangaroo_replay_wide_impl(
        states,
        jumps1,
        jumps2,
        jumps3,
        hop_metadata,
        dp_x,
        dp_counts,
        output,
        output_count,
        replay_error,
        params,
        state_index);
}
