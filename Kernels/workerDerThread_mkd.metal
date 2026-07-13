#include "WorkerDerThreadSetupCommon.metalh"

kernel void workerDerThread_mkd(const device char* input_str [[buffer(0)]],
                                constant uint& input_str_len [[buffer(1)]],
                                const device char* passphrase_dev [[buffer(2)]],
                                constant uint& pass_len [[buffer(3)]],
                                device uchar* d_master_secp [[buffer(4)]],
                                device uchar* d_master_ed [[buffer(5)]],
                                device uchar* d_master_cardano_icarus [[buffer(6)]],
                                device uchar* d_master_cardano_daedalus [[buffer(7)]],
                                device uchar* d_master_cardano_ledger [[buffer(8)]],
                                device uchar* d_master_cardano_byron_legacy [[buffer(9)]],
                                device uchar* d_entropy [[buffer(10)]],
                                device uint* d_entropy_len [[buffer(11)]],
                                device uchar* d_entropy_valid [[buffer(12)]],
                                device char* d_save_str [[buffer(13)]],
                                device uint* d_save_len [[buffer(14)]],
                                constant uchar& mode [[buffer(15)]],
                                constant uchar& m_mode [[buffer(16)]],
                                constant uchar& entropy_mode [[buffer(17)]],
                                constant uchar& bip_mode [[buffer(18)]],
                                const device uint* iterations [[buffer(19)]],
                                constant uint& iterations_size [[buffer(20)]],
                                constant uint& iteration_idx [[buffer(21)]],
                                device RuntimeConfig& config [[buffer(22)]],
                                const device char* dict_words [[buffer(23)]],
                                uint tid [[thread_position_in_grid]]) {
    (void)bip_mode;
    if (tid != 0u || input_str == nullptr) {
        return;
    }

    const uint iter = (iterations != nullptr && iterations_size > 0u)
        ? iterations[min(iteration_idx, iterations_size - 1u)]
        : config.pbkdf2Iterations;

    char passphrase[128] = { 0 };
    const uint pass_copy = min(pass_len, 128u);
    if (passphrase_dev != nullptr) {
        der_copy_device_char_to_thread(passphrase, passphrase_dev, pass_copy);
    }

    char save_material[512] = { 0 };
    ulong save_len = 0ul;
    der_setup_copy_input(save_material, save_len, input_str, input_str_len);

    uchar material[512] = { 0 };
    ulong material_len = save_len;
    uchar raw_entropy[64] = { 0 };
    uint raw_entropy_len = 0u;
    for (uint i = 0u; i < uint(save_len); ++i) {
        material[i] = uchar(save_material[i]);
    }

    if (mode == 0u && config.isHex != 0u) {
        der_setup_zero(material, 512u);
        der_setup_unhex_device(input_str, input_str_len, material, 64u);
        material_len = min(input_str_len >> 1u, 64u);
    } else if (mode == 1u && config.isHex != 0u) {
        der_setup_zero(material, 512u);
        der_setup_unhex_device(input_str, input_str_len, material, 512u);
        material_len = min(input_str_len >> 1u, 512u);
    } else if (mode == 2u) {
        worker_transform_material(save_material, material_len, m_mode, iter, config.utf8 != 0u, false);
        for (uint i = 0u; i < uint(material_len); ++i) {
            material[i] = uchar(save_material[i]);
        }
    } else if (mode == 3u) {
        uint entropy_len = uint(material_len);
        if (config.isHex != 0u) {
            der_setup_zero(material, 512u);
            der_setup_unhex_device(input_str, input_str_len, material, 512u);
            entropy_len = min(input_str_len >> 1u, 512u);
        }
        const uint metal_entropy_mode = entropy_mode <= 0x05u ? entropy_mode : 0u;
        if (!mnw_entropy_transform(material, entropy_len, metal_entropy_mode, iter, false, config)) {
            return;
        }
        raw_entropy_len = min(entropy_len, 64u);
        for (uint i = 0u; i < raw_entropy_len; ++i) {
            raw_entropy[i] = material[i];
        }
        char phrase[512] = { 0 };
        size_t phrase_len = 0;
        dict_t dict = dict_at(int(config.dictLang));
        if (config.electrum == 0u) {
            der_setup_generate_mnemonic(material, size_t(entropy_len), phrase,
                                        int(config.dictLang), dict_words, phrase_len,
                                        config.oldElectrum);
        } else {
            GenerateMnemonicElectrumV2(reinterpret_cast<thread char*>(material), size_t(entropy_len),
                                       phrase, dict, phrase_len, config.electrumSegwit,
                                       config.electrum128, config.electrumCakeWallet);
        }
        if (phrase_len == 0ul || phrase_len > 512ul) {
            return;
        }
        material_len = phrase_len;
        for (uint i = 0u; i < uint(phrase_len); ++i) {
            material[i] = uchar(phrase[i]);
            save_material[i] = phrase[i];
        }
        save_len = phrase_len;
    }

    extended_private_key_t secp_master = {};
    extended_private_key_t ed_master = {};
    cardano_extended_private_key_t cardano_icarus = {};
    cardano_extended_private_key_t cardano_daedalus = {};
    cardano_extended_private_key_t cardano_ledger = {};
    cardano_extended_private_key_t cardano_byron = {};
    uchar entropy_out[64] = { 0 };
    uint entropy_len_out = 0u;
    uchar entropy_valid_out = 0u;

    der_setup_hash_to_master(material, material_len, raw_entropy, raw_entropy_len,
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
    if (d_entropy != nullptr) {
        der_copy_thread_uchar_to_device(d_entropy, entropy_out, 64u);
    }
    if (d_entropy_len != nullptr) {
        *d_entropy_len = entropy_len_out;
    }
    if (d_entropy_valid != nullptr) {
        *d_entropy_valid = entropy_valid_out;
    }
    if (mode == 3u) {
        der_setup_save_string(d_save_str, d_save_len, save_material, uint(save_len));
    } else {
        const uint original_len = min(input_str_len, 511u);
        for (uint i = 0u; i < original_len; ++i) {
            d_save_str[i] = input_str[i];
        }
        d_save_str[original_len] = '\0';
        *d_save_len = original_len;
    }
}
