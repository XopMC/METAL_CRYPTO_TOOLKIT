#include <metal_stdlib>
#include "HashFunc.metalh"

using namespace metal;

kernel void workerDerThread_precompute_master_ed_hmac(const device uchar* d_master_ed [[buffer(0)]],
                                                      device hmac_sha512_precomp_t* d_master_ed_hmac_precomp [[buffer(1)]],
                                                      uint tid [[thread_position_in_grid]]) {
    if (tid != 0u) {
        return;
    }
    if (d_master_ed == nullptr || d_master_ed_hmac_precomp == nullptr) {
        return;
    }

    const device extended_private_key_t* master_private =
        reinterpret_cast<const device extended_private_key_t*>(d_master_ed);

    thread uint chain_code_words[8];
    const device uint* chain_code_src = reinterpret_cast<const device uint*>(master_private->chain_code);
    for (int i = 0; i < 8; i++) {
        chain_code_words[i] = chain_code_src[i];
    }

    thread hmac_sha512_precomp_t local_precomp;
    hmac_sha512_const_precompute(chain_code_words, &local_precomp);
    *d_master_ed_hmac_precomp = local_precomp;
}
