#include "../KernelState.metalh"

kernel void copyXorUncompressedFilter(device XorFilterState& filters [[buffer(0)]],
                          device FilterStorageState& storage [[buffer(1)]],
                          constant int& count [[buffer(2)]],
                          constant ulong& size_h [[buffer(3)]],
                          constant ulong& arrayLength_h [[buffer(4)]],
                          constant ulong& segmentCount_h [[buffer(5)]],
                          constant ulong& segmentCountLength_h [[buffer(6)]],
                          constant ulong& segmentLength_h [[buffer(7)]],
                          constant ulong& segmentLengthMask_h [[buffer(8)]]) {
    (void)segmentCountLength_h;
    (void)segmentLength_h;
    (void)segmentLengthMask_h;
    if (count < 0 || count >= int(kXorFilterSlots)) {
        return;
    }
    storage.xorUnCount = uint(count + 1);
    filters.uncompressed.size[count] = size_h;
    filters.uncompressed.arrayLength[count] = arrayLength_h;
    filters.uncompressed.segmentCount[count] = segmentCount_h;
}
