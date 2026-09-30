#include "../MetalLaunchPolicy.h"
#include <cstdlib>
#include <iostream>

static void check(bool passed, const char* name) {
    if (!passed) { std::cerr << "FAILED: " << name << '\n'; std::exit(1); }
}

int main() {
    using namespace metal_crypto;
    for (const char* name : {"Apple M1", "Apple M1 Pro", "Apple M1 Max", "Apple M1 Ultra"})
        check(isM1Device(name), "M1 variants");
    for (const char* name : {"Apple M2", "Apple M3 Max", "Apple M4 Max", "Apple M10", "Apple M1 Experimental"})
        check(!isM1Device(name), "other devices untouched");
    check(!isM1Device(nullptr), "null device");
    auto g = smallBatchGeometry({224, 256}, 7, false, false);
    check(g.blocks == 28 && g.threads == 32, "issue 3 M1 geometry");
    g = smallBatchGeometry({1280, 256}, 32, false, false);
    check(g.blocks == 32 && g.threads == 32, "M1 Max bounded batch");
    g = smallBatchGeometry({4, 8}, 7, true, true);
    check(g.blocks == 4 && g.threads == 8, "both explicit dimensions");
    g = smallBatchGeometry({4, 256}, 7, true, false);
    check(g.blocks == 4 && g.threads == 32, "explicit blocks");
    g = smallBatchGeometry({224, 4}, 7, false, true);
    check(g.blocks == 28 && g.threads == 4, "explicit threads");
    g = smallBatchGeometry({2, 8}, 0, false, false);
    check(g.blocks == 2 && g.threads == 8, "never increase existing geometry");
    std::cout << "Metal launch policy tests passed\n";
}
