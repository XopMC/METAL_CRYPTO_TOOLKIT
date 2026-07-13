#include <metal_stdlib>
#include "../KernelState.metalh"
#include "BigIntFunc.metalh"
#include "FilterCommon.metalh"
#include "GPUHash.metalh"
#include "HashFunc.metalh"
#include "IcpFunc.metalh"
#include "Pbkdf2Func.metalh"
#include "AdaFunc.metalh"
#include "TonFunc.metalh"
#include "../lib/secp256k1/secp256k1.metalh"
#include "../sr25519-donna-32bit/ed25519-donna/ed25519.metalh"
#include "../sr25519-donna-32bit/sr25519.metalh"
#include "MnemonicFunc.metalh"

using namespace metal;

kernel void metal_runtime_smoke(device RuntimeConfig& config [[buffer(0)]],
                                device FoundBufferLayout& founds [[buffer(1)]],
                                uint tid [[thread_position_in_grid]]) {
    if (tid != 0) {
        return;
    }
    founds.maxFounds = config.maxFounds;
}
