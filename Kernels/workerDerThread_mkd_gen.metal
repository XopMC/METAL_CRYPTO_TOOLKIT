#include "WorkerDerThreadSetupCommon.metalh"

kernel void workerDerThread_mkd_gen(constant ulong& seed_d [[buffer(0)]],
                                    constant int& entropy_bytes [[buffer(1)]],
                                    constant int& gen [[buffer(2)]],
                                    device uchar* d_master_secp [[buffer(3)]],
                                    device uchar* d_master_ed [[buffer(4)]],
                                    device uchar* d_master_cardano_icarus [[buffer(5)]],
                                    device uchar* d_master_cardano_daedalus [[buffer(6)]],
                                    device uchar* d_master_cardano_ledger [[buffer(7)]],
                                    device uchar* d_master_cardano_byron_legacy [[buffer(8)]],
                                    device uchar* d_entropy_out [[buffer(9)]],
                                    device uint* d_entropy_len [[buffer(10)]],
                                    device uchar* d_entropy_valid [[buffer(11)]],
                                    device char* d_save_str [[buffer(12)]],
                                    device uint* d_save_len [[buffer(13)]],
                                    constant uchar& mode [[buffer(14)]],
                                    constant uchar& entropy_mode_p [[buffer(15)]],
                                    const device char* passphrase_dev [[buffer(16)]],
                                    constant uint& pass_len [[buffer(17)]],
                                    constant bool& is_64 [[buffer(18)]],
                                    device RuntimeConfig& config [[buffer(19)]],
                                    const device char* dict_words [[buffer(20)]],
                                    uint tid [[thread_position_in_grid]]) {
    (void)entropy_mode_p;
    if (tid != 0u) {
        return;
    }

    uchar entropy[128] = { 0 };
    if (!der_setup_entropy_fill(entropy_bytes, entropy, seed_d, is_64, gen, config.skip64)) {
        return;
    }

    char passphrase[128] = { 0 };
    const uint pass_copy = min(pass_len, 128u);
    if (passphrase_dev != nullptr) {
        der_copy_device_char_to_thread(passphrase, passphrase_dev, pass_copy);
    }

    uchar material[512] = { 0 };
    ulong material_len = ulong(min(entropy_bytes, 128));
    char save_str[512] = { 0 };
    uint save_len = 0u;

    if (mode == 0u) {
        for (uint i = 0u; i < uint(material_len); ++i) {
            material[i] = entropy[i];
        }
        mnw_hexing(entropy, min(uint(material_len), 32u), reinterpret_cast<thread uchar*>(save_str), 64u);
        save_len = min(uint(material_len), 32u) * 2u;
    } else {
        char phrase[512] = { 0 };
        size_t phrase_len = 0;
        dict_t dict = dict_at(int(config.dictLang));
        if (config.electrum == 0u) {
            der_setup_generate_mnemonic(entropy, size_t(material_len), phrase,
                                        int(config.dictLang), dict_words, phrase_len,
                                        config.oldElectrum);
        } else {
            GenerateMnemonicElectrumV2(reinterpret_cast<thread char*>(entropy), size_t(material_len),
                                       phrase, dict, phrase_len, config.electrumSegwit,
                                       config.electrum128, config.electrumCakeWallet);
        }
        if (phrase_len == 0ul || phrase_len > 512ul) {
            return;
        }
        material_len = phrase_len;
        for (uint i = 0u; i < uint(phrase_len); ++i) {
            material[i] = uchar(phrase[i]);
            save_str[i] = phrase[i];
        }
        save_len = uint(phrase_len);
    }

    extended_private_key_t secp_master = {};
    extended_private_key_t ed_master = {};
    cardano_extended_private_key_t cardano_icarus = {};
    cardano_extended_private_key_t cardano_daedalus = {};
    cardano_extended_private_key_t cardano_ledger = {};
    cardano_extended_private_key_t cardano_byron = {};
    uchar entropy_out[64] = { 0 };
    uint entropy_len_out = min(uint(max(entropy_bytes, 0)), 64u);
    uchar entropy_valid_out = mode == 0u ? 0u : 1u;
    for (uint i = 0u; i < entropy_len_out; ++i) {
        entropy_out[i] = entropy[i];
    }

    der_setup_hash_to_master(material, material_len, entropy, uint(max(entropy_bytes, 0)),
                             passphrase, pass_copy, mode, config,
                             secp_master, ed_master, cardano_icarus, cardano_daedalus,
                             cardano_ledger, cardano_byron, entropy_out, entropy_len_out,
                             entropy_valid_out);

    der_store_master_extended(d_master_secp, secp_master);
    der_store_master_extended(d_master_ed, ed_master);
    der_store_cardano_xprv(d_master_cardano_icarus, cardano_icarus);
    der_store_cardano_xprv(d_master_cardano_daedalus, cardano_daedalus);
    der_store_cardano_xprv(d_master_cardano_ledger, cardano_ledger);
    der_store_cardano_xprv(d_master_cardano_byron_legacy, cardano_byron);
    if (d_entropy_out != nullptr) {
        der_copy_thread_uchar_to_device(d_entropy_out, entropy_out, 64u);
    }
    if (d_entropy_len != nullptr) {
        *d_entropy_len = entropy_len_out;
    }
    if (d_entropy_valid != nullptr) {
        *d_entropy_valid = entropy_valid_out;
    }
    der_setup_save_string(d_save_str, d_save_len, save_str, save_len);
}
