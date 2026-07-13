#include "WorkerCommon.metalh"

kernel void worker_gen(device bool* isResult [[buffer(0)]],
                       device bool* buffResult [[buffer(1)]],
                       constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                       constant ulong& precPitch [[buffer(3)]],
                       const device uint* d_derivations [[buffer(4)]],
                       const device uint* derindex [[buffer(5)]],
                       constant uint& der_indexes_size [[buffer(6)]],
                       constant uint& der_start_index [[buffer(7)]],
                       constant ulong& seed_d [[buffer(8)]],
                       constant ulong& seed_count [[buffer(9)]],
                       constant bool& is_64 [[buffer(10)]],
                       constant int& entropy_len_in [[buffer(11)]],
                       constant int& mode [[buffer(12)]],
                       constant int& gen [[buffer(13)]],
                       const device char* passwd [[buffer(14)]],
                       constant uint& pass_size [[buffer(15)]],
                       constant uint& starter_pass [[buffer(16)]],
                       constant bool& custom_size [[buffer(17)]],
                       constant int& custom_len [[buffer(18)]],
                       constant uchar& entropy_mode [[buffer(19)]],
                       constant uint& iter [[buffer(20)]],
                       constant ulong& round [[buffer(21)]],
                       constant bool& dub_mnem [[buffer(22)]],
                       const device WorkerRuntimeBuffers& runtime [[buffer(23)]],
                       uint tid [[thread_position_in_grid]]) {
    (void)dub_mnem;
    if (ulong(tid) >= seed_count) {
        return;
    }
    const ulong seed_l = seed_d + ulong(tid);
    if (!is_64 && seed_l > 0xfffffffful) {
        return;
    }

    WorkerEnv env;
    FoundBuffers found;
    if (!worker_init_env(env, found, isResult, buffResult, precPtr, precPitch, runtime)) {
        return;
    }

    int entropy_len = entropy_len_in;
    uchar entropy[128] = { 0 };
    if (!worker_entropy_fill_fallback(entropy_len, entropy, seed_l, is_64, mode, gen, (*env.config).skip64)) {
        return;
    }

    char entropy_buf[512] = { 0 };
    for (int i = 0; i < entropy_len && i < 128; ++i) {
        entropy_buf[i] = char(entropy[i]);
    }
    ulong material_len = ulong(max(entropy_len, 0));
    worker_transform_material(entropy_buf, material_len, entropy_mode, iter, (*env.config).utf8 != 0u, false);
    entropy_len = int(material_len);
    if (custom_size) {
        entropy_len = custom_len;
    }
    if (entropy_len < 0) {
        return;
    }
    entropy_len = min(entropy_len, 128);
    for (int i = 0; i < entropy_len; ++i) {
        entropy[i] = uchar(entropy_buf[i]);
    }

    char toHash[512] = { 0 };
    size_t len = 0u;
    dict_t words = dict_at(int((*env.config).dictLang));
    if ((*env.config).electrum == 0u) {
        GenerateMnemonic(reinterpret_cast<thread char*>(entropy), size_t(entropy_len),
                         toHash, int((*env.config).dictLang), runtime.customDict, len, (*env.config).oldElectrum);
    } else {
        GenerateMnemonicElectrumV2(reinterpret_cast<thread char*>(entropy), size_t(entropy_len),
                                   toHash, words, len, (*env.config).electrumSegwit,
                                   (*env.config).electrum128, (*env.config).electrumCakeWallet);
        if (len == 0u) {
            return;
        }
    }

    worker_process_candidate(env, toHash, ulong(len), d_derivations, derindex, der_indexes_size,
                             der_start_index, passwd, pass_size, starter_pass, round,
                             ulong(tid), true, seed_l, iter, true);
}
