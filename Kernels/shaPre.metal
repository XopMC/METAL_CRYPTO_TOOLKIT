#include <metal_stdlib>

using namespace metal;

kernel void shaPre(constant ulong& prefixLen [[buffer(0)]],
                   device uint* hashPre [[buffer(1)]],
                   uint tid [[thread_position_in_grid]])
{
    (void)prefixLen;
    (void)hashPre;
    (void)tid;
}
