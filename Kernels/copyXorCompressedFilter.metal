#include "../KernelState.metalh"

kernel void copyXorCompressedFilter(device XorFilterState& filters [[buffer(0)]],
                        device FilterStorageState& storage [[buffer(1)]],
                        constant int& count [[buffer(2)]],
                        constant ulong& size_h [[buffer(3)]],
                        constant ulong& arrayLength_h [[buffer(4)]],
                        constant ulong& segmentCount_h [[buffer(5)]],
                        constant ulong& segmentCountLength_h [[buffer(6)]],
                        constant ulong& segmentLength_h [[buffer(7)]],
                        constant ulong& segmentLengthMask_h [[buffer(8)]]) {
    if (count < 0 || count >= int(kXorFilterSlots)) {
        return;
    }
    storage.xorCount = uint(count + 1);
    filters.x.size[count] = size_h;
    filters.x.arrayLength[count] = arrayLength_h;
    filters.x.segmentCount[count] = segmentCount_h;
    filters.x.segmentCountLength[count] = segmentCountLength_h;
    filters.x.segmentLength[count] = segmentLength_h;
    filters.x.segmentLengthMask[count] = segmentLengthMask_h;
}
