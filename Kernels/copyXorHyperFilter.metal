#include "../KernelState.metalh"

kernel void copyXorHyperFilter(device XorFilterState& filters [[buffer(0)]],
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
    storage.xorHcCount = uint(count + 1);
    filters.hc.size[count] = size_h;
    filters.hc.arrayLength[count] = arrayLength_h;
    filters.hc.segmentCount[count] = segmentCount_h;
    filters.hc.segmentCountLength[count] = segmentCountLength_h;
    filters.hc.segmentLength[count] = segmentLength_h;
    filters.hc.segmentLengthMask[count] = segmentLengthMask_h;
}
