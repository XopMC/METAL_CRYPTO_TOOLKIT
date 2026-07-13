#include "WorkerCommon.metalh"

constant uint DERTHREAD_SUBSTRATE_PATH_COUNT [[function_constant(69)]];
constant bool DERTHREAD_DOT_ENABLED [[function_constant(70)]];

static inline void der_load_cardano_xprv(const device uchar* src,
                                         thread cardano_extended_private_key_t& out) {
    const device cardano_extended_private_key_t* in =
        reinterpret_cast<const device cardano_extended_private_key_t*>(src);
    for (uint i = 0u; i < 64u; ++i) {
        out.key[i] = in->key[i];
    }
    for (uint i = 0u; i < 32u; ++i) {
        out.chain_code[i] = in->chain_code[i];
    }
}

static inline void der_get_child_key_cardano_ed25519(
    const thread cardano_extended_private_key_t& master,
    const device uint* derivations,
    uint path_offset,
    uint path_len,
    thread cardano_extended_private_key_t& out) {
    out = master;
    for (uint i = 0u; i < path_len; ++i) {
        const uint index = derivations[path_offset + i];
        if (index < 0x80000000u) {
            ed25519_bip32_ckd_priv_normal(&out, &out, index);
        } else {
            ed25519_bip32_ckd_priv_hardened(&out, &out, index);
        }
    }
}

static inline void der_get_child_key_cardano_byron_legacy(
    const thread cardano_extended_private_key_t& master,
    const device uint* derivations,
    uint path_offset,
    uint path_len,
    thread cardano_extended_private_key_t& out) {
    out = master;
    for (uint i = 0u; i < path_len; ++i) {
        const uint index = derivations[path_offset + i] | 0x80000000u;
        cardano_byron_legacy_ckd_priv_hardened(&out, &out, index);
    }
}

static inline void der_get_child_key_cip1852(const thread extended_private_key_t& master,
                                              const device uint* derivations,
                                              uint path_offset,
                                              uint path_len,
                                              thread uchar out[32]) {
    extended_private_key_t child = master;
    for (uint i = 0u; i < path_len; ++i) {
        const uint index = derivations[path_offset + i];
        if ((index & 0x80000000u) != 0u) {
            ed25519_bip32_ckd_priv_hardened(&child, &child, index);
        } else {
            ed25519_bip32_ckd_priv_normal(&child, &child, index);
        }
    }
    for (uint i = 0u; i < 32u; ++i) {
        out[i] = child.key[i];
    }
}

static inline bool der_path_equal(const device uint* derivations,
                                  uint a_offset,
                                  uint a_len,
                                  uint b_offset,
                                  uint b_len) {
    if (a_len != b_len) {
        return false;
    }
    for (uint i = 0u; i < a_len; ++i) {
        if (derivations[a_offset + i] != derivations[b_offset + i]) {
            return false;
        }
    }
    return true;
}

static inline bool der_ada_pair_seen_before(const device uint* derivations,
                                            const device uint* path_lengths,
                                            uint current_index,
                                            uint path_count,
                                            uint payment_offset,
                                            uint payment_len,
                                            uint stake_offset,
                                            uint stake_len) {
    uint previous_offset = 0u;
    for (uint p = 0u; p < current_index; ++p) {
        const uint previous_len = path_lengths[p];
        const uint next_offset = previous_offset + previous_len;
        if (der_path_equal(derivations, payment_offset, payment_len,
                           previous_offset, previous_len) &&
            der_path_equal(derivations, stake_offset, stake_len,
                           previous_offset, previous_len)) {
            return true;
        }
        if (p + 1u < path_count) {
            const uint next_len = path_lengths[p + 1u];
            const bool forward =
                der_path_equal(derivations, payment_offset, payment_len,
                               previous_offset, previous_len) &&
                der_path_equal(derivations, stake_offset, stake_len,
                               next_offset, next_len);
            const bool reverse =
                der_path_equal(derivations, payment_offset, payment_len,
                               next_offset, next_len) &&
                der_path_equal(derivations, stake_offset, stake_len,
                               previous_offset, previous_len);
            if (forward || reverse) {
                return true;
            }
        }
        previous_offset += previous_len;
    }
    return false;
}

static inline void der_apply_round(thread uchar key[32], long current_round) {
    if (current_round < 0l) {
        bump_key_256(key, ulong(-current_round), false);
    } else if (current_round > 0l) {
        bump_key_256(key, ulong(current_round), true);
    }
}

static inline void der_emit_dot_substrate_from_entropy(
    thread WorkerEnv& env,
    const thread char* save_str,
    ulong save_len,
    const device uchar* entropy,
    uint entropy_len,
    const device char* passphrase,
    uint pass_len,
    ulong round,
    bool store_seed,
    ulong seed_value,
    uint substrate_path_count) {
    if (entropy == nullptr || env.substratePaths == nullptr) {
        return;
    }

    uchar root_seed[64] = { 0 };
    uchar mnemonic_salt[512] = { 0 };
    for (uint i = 0u; i < 8u; ++i) {
        mnemonic_salt[i] = recovery_salt[i];
    }
    for (uint i = 0u; i < pass_len; ++i) {
        mnemonic_salt[8u + i] = uchar(passphrase[i]);
    }
    fastpbkdf2_hmac_sha512(entropy, ulong(entropy_len), mnemonic_salt,
                           ulong(8u + pass_len), (*env.config).pbkdf2Iterations,
                           root_seed, 64ul);

    uchar round_seed[64] = { 0 };
    adadot_copy_thread_bytes(round_seed, root_seed, 64u);
    if (round > 0ul) {
        bump_key_256(round_seed, round, false);
    }

    const uint path_count = min(substrate_path_count, uint(kSubstrateMaxPaths));
    for (ulong s = 0ul; s <= 2ul * round; ++s) {
        const long current_round = long(s) - long(round);

        for (uint sp = 0u; sp < path_count; ++sp) {
            const device SubstratePathDevice& substrate_path = env.substratePaths[sp];
            uchar path_seed[64] = { 0 };
            if (substrate_path.password_len > 0u) {
                uchar path_salt[512] = { 0 };
                for (uint i = 0u; i < 8u; ++i) {
                    path_salt[i] = recovery_salt[i];
                }
                const uint password_len = substrate_path.password_len;
                for (uint i = 0u; i < password_len; ++i) {
                    path_salt[8u + i] = substrate_path.password[i];
                }
                fastpbkdf2_hmac_sha512(entropy, ulong(entropy_len), path_salt,
                                       ulong(8u + password_len), (*env.config).pbkdf2Iterations,
                                       path_seed, 64ul);
                der_apply_round(path_seed, current_round);
            } else {
                adadot_copy_thread_bytes(path_seed, round_seed, 64u);
            }

            uchar ed_path_seed[32] = { 0 };
            if (adadot_substrate_derive_ed25519_seed(ed_path_seed, path_seed, substrate_path)) {
                adadot_emit_dot_ed25519_seed(
                    env.isResult, env.buffResult, save_str, save_len, ed_path_seed,
                    substrate_path.save_index, current_round, 0u, passphrase, pass_len,
                    0ul, store_seed, seed_value, 0u, false, *env.config, *env.filters,
                    *env.filterStorage, env.bloomStorage, env.xorStorage, env.xorUnStorage,
                    env.xorUcStorage, env.xorHcStorage, env.found);
            }
        }

        if (dot_type_enabled(*env.config, 0x31u)) {
            for (uint sp = 0u; sp < path_count; ++sp) {
                const device SubstratePathDevice& substrate_path = env.substratePaths[sp];
                uchar path_seed[64] = { 0 };
                if (substrate_path.password_len > 0u) {
                    uchar path_salt[512] = { 0 };
                    for (uint i = 0u; i < 8u; ++i) {
                        path_salt[i] = recovery_salt[i];
                    }
                    const uint password_len = substrate_path.password_len;
                    for (uint i = 0u; i < password_len; ++i) {
                        path_salt[8u + i] = substrate_path.password[i];
                    }
                    fastpbkdf2_hmac_sha512(entropy, ulong(entropy_len), path_salt,
                                           ulong(8u + password_len), (*env.config).pbkdf2Iterations,
                                           path_seed, 64ul);
                    der_apply_round(path_seed, current_round);
                } else {
                    adadot_copy_thread_bytes(path_seed, round_seed, 64u);
                }

                sr25519_keypair path_keypair = { 0 };
                adadot_substrate_derive_sr25519_keypair(path_keypair, path_seed, substrate_path);
                uchar substrate_public[32] = { 0 };
                adadot_copy_thread_bytes(substrate_public, path_keypair + 64, 32u);
                if (adadot_check_hash_words(*env.config, *env.filters, *env.filterStorage,
                                            env.bloomStorage, env.xorStorage, env.xorUnStorage,
                                            env.xorUcStorage, env.xorHcStorage, substrate_public)) {
                    adadot_store_result(env.isResult, env.buffResult, save_str, save_len,
                                        path_seed, nullptr, substrate_public, 32u, 0x31u,
                                        substrate_path.save_index, substrate_path.save_index,
                                        current_round, 0u, passphrase, pass_len, 0ul,
                                        store_seed, seed_value, 0u, false, *env.config, env.found);
                }
            }
        }

        if (s < 2ul * round) {
            bump_key_256(round_seed, 1ul, true);
        }
    }
}

static inline void der_emit_ada_cardano_roots_path(
    thread WorkerEnv& env,
    const thread char* save_str,
    ulong save_len,
    const thread cardano_extended_private_key_t& icarus_master,
    const thread cardano_extended_private_key_t& daedalus_master,
    const thread cardano_extended_private_key_t* ledger_master,
    const thread cardano_extended_private_key_t* byron_legacy_master,
    const device uint* derivations,
    const device uint* path_lengths,
    uint global_path,
    uint path_count,
    uint path_offset,
    uint path_len,
    long current_round,
    const device char* passphrase,
    uint pass_len,
    bool store_seed,
    ulong seed_value) {
    if ((*env.config).bipDerivationsEnabled == 0u ||
        (((*env.config).derivationTypeMask & WORKER_DERIVATION_TYPE_MASK_BIP32_ED25519) == 0u)) {
        return;
    }

    cardano_extended_private_key_t payment_xprv;
    der_get_child_key_cardano_ed25519(icarus_master, derivations, path_offset, path_len,
                                      payment_xprv);
    uchar payment_key[32] = { 0 };
    adadot_copy_thread_bytes(payment_key, payment_xprv.key, 32u);
    der_apply_round(payment_key, current_round);

    uchar payment_pub[32] = { 0 };
    uchar payment_hash[28] = { 0 };
    adadot_ada_scalar_pubkey_hash(payment_key, payment_pub, payment_hash);
    adadot_emit_ada_single_key_addresses_from_hash(
        env.isResult, env.buffResult, save_str, save_len, payment_key, payment_hash, false,
        global_path, current_round, 0u, passphrase, pass_len, 0ul, store_seed, seed_value,
        0u, false, *env.config, *env.filters, *env.filterStorage, env.bloomStorage,
        env.xorStorage, env.xorUnStorage, env.xorUcStorage, env.xorHcStorage, env.found);

    if (adadot_ada_type_enabled(*env.config, 0x10u)) {
        uchar byron_icarus[64] = { 0 };
        byron_icarus_from_xpub(payment_pub, payment_xprv.chain_code, byron_icarus);
        adadot_check_ada_raw(
            env.isResult, env.buffResult, save_str, save_len, payment_key, nullptr,
            byron_icarus, 43u, 0x10u, global_path, global_path, current_round, 0u,
            passphrase, pass_len, 0ul, store_seed, seed_value, 0u, false, *env.config,
            *env.filters, *env.filterStorage, env.bloomStorage, env.xorStorage,
            env.xorUnStorage, env.xorUcStorage, env.xorHcStorage, env.found);
    }

    if (adadot_ada_type_enabled(*env.config, 0x13u)) {
        cardano_extended_private_key_t daedalus_xprv;
        der_get_child_key_cardano_byron_legacy(daedalus_master, derivations, path_offset,
                                               path_len, daedalus_xprv);
        uchar root_pub[32] = { 0 };
        uchar child_pub[32] = { 0 };
        cardano_ed25519_publickey_from_scalar(daedalus_master.key, root_pub);
        cardano_ed25519_publickey_from_scalar(daedalus_xprv.key, child_pub);
        uint account = 0x80000000u;
        uint address = 0x80000000u;
        if (path_len >= 2u) {
            account = derivations[path_offset + path_len - 2u] | 0x80000000u;
            address = derivations[path_offset + path_len - 1u] | 0x80000000u;
        } else if (path_len == 1u) {
            address = derivations[path_offset] | 0x80000000u;
        }
        uchar byron_daedalus[80] = { 0 };
        const ulong byron_len = byron_daedalus_from_root_xpub(
            root_pub, daedalus_master.chain_code, child_pub, daedalus_xprv.chain_code,
            account, address, byron_daedalus);
        if (byron_len > 0ul && byron_len <= 80ul) {
            adadot_check_ada_raw(
                env.isResult, env.buffResult, save_str, save_len, daedalus_xprv.key,
                daedalus_xprv.chain_code, byron_daedalus, uint(byron_len), 0x13u,
                global_path, global_path, current_round, 0u, passphrase, pass_len, 0ul,
                store_seed, seed_value, 0u, false, *env.config, *env.filters,
                *env.filterStorage, env.bloomStorage, env.xorStorage, env.xorUnStorage,
                env.xorUcStorage, env.xorHcStorage, env.found);
        }
    }

    if (byron_legacy_master != nullptr && adadot_ada_type_enabled(*env.config, 0x19u)) {
        cardano_extended_private_key_t legacy_xprv;
        der_get_child_key_cardano_byron_legacy(*byron_legacy_master, derivations, path_offset,
                                               path_len, legacy_xprv);
        uchar root_pub[32] = { 0 };
        uchar child_pub[32] = { 0 };
        cardano_ed25519_publickey_from_scalar(byron_legacy_master->key, root_pub);
        cardano_ed25519_publickey_from_scalar(legacy_xprv.key, child_pub);
        uint account = 0x80000000u;
        uint address = 0x80000000u;
        if (path_len >= 2u) {
            account = derivations[path_offset + path_len - 2u] | 0x80000000u;
            address = derivations[path_offset + path_len - 1u] | 0x80000000u;
        } else if (path_len == 1u) {
            address = derivations[path_offset] | 0x80000000u;
        }
        uchar byron_legacy[80] = { 0 };
        const ulong byron_len = byron_daedalus_from_root_xpub(
            root_pub, byron_legacy_master->chain_code, child_pub, legacy_xprv.chain_code,
            account, address, byron_legacy);
        if (byron_len > 0ul && byron_len <= 80ul) {
            adadot_check_ada_raw(
                env.isResult, env.buffResult, save_str, save_len, legacy_xprv.key,
                legacy_xprv.chain_code, byron_legacy, uint(byron_len), 0x19u,
                global_path, global_path, current_round, 0u, passphrase, pass_len, 0ul,
                store_seed, seed_value, 0u, false, *env.config, *env.filters,
                *env.filterStorage, env.bloomStorage, env.xorStorage, env.xorUnStorage,
                env.xorUcStorage, env.xorHcStorage, env.found);
        }
    }

    if (ledger_master != nullptr &&
        (adadot_ada_type_enabled(*env.config, 0x17u) ||
         adadot_ada_type_enabled(*env.config, 0x18u))) {
        cardano_extended_private_key_t ledger_payment_xprv;
        der_get_child_key_cardano_ed25519(*ledger_master, derivations, path_offset, path_len,
                                          ledger_payment_xprv);
        uchar ledger_payment_key[32] = { 0 };
        adadot_copy_thread_bytes(ledger_payment_key, ledger_payment_xprv.key, 32u);
        der_apply_round(ledger_payment_key, current_round);
        uchar ledger_payment_pub[32] = { 0 };
        uchar ledger_payment_hash[28] = { 0 };
        adadot_ada_scalar_pubkey_hash(ledger_payment_key, ledger_payment_pub,
                                     ledger_payment_hash);

        if (adadot_ada_type_enabled(*env.config, 0x17u)) {
            uchar byron_ledger[64] = { 0 };
            byron_icarus_from_xpub(ledger_payment_pub, ledger_payment_xprv.chain_code,
                                   byron_ledger);
            adadot_check_ada_raw(
                env.isResult, env.buffResult, save_str, save_len, ledger_payment_key,
                nullptr, byron_ledger, 43u, 0x17u, global_path, global_path,
                current_round, 0u, passphrase, pass_len, 0ul, store_seed, seed_value,
                0u, false, *env.config, *env.filters, *env.filterStorage,
                env.bloomStorage, env.xorStorage, env.xorUnStorage, env.xorUcStorage,
                env.xorHcStorage, env.found);
        }

        if (adadot_ada_type_enabled(*env.config, 0x18u) &&
            !der_ada_pair_seen_before(derivations, path_lengths, global_path, path_count,
                                      path_offset, path_len, path_offset, path_len)) {
            adadot_emit_ada_base_pair_from_hashes(
                env.isResult, env.buffResult, save_str, save_len, ledger_payment_key,
                ledger_payment_key, ledger_payment_hash, ledger_payment_hash, global_path,
                global_path, current_round, 0u, passphrase, pass_len, 0ul, store_seed,
                seed_value, 0u, false, 0x18u, *env.config, *env.filters,
                *env.filterStorage, env.bloomStorage, env.xorStorage, env.xorUnStorage,
                env.xorUcStorage, env.xorHcStorage, env.found);
        }

        if (adadot_ada_type_enabled(*env.config, 0x18u) && global_path + 1u < path_count) {
            const uint next_offset = path_offset + path_len;
            const uint next_len = path_lengths[global_path + 1u];
            if (!der_path_equal(derivations, path_offset, path_len, next_offset, next_len)) {
                cardano_extended_private_key_t ledger_stake_xprv;
                der_get_child_key_cardano_ed25519(*ledger_master, derivations, next_offset,
                                                  next_len, ledger_stake_xprv);
                uchar ledger_stake_key[32] = { 0 };
                adadot_copy_thread_bytes(ledger_stake_key, ledger_stake_xprv.key, 32u);
                der_apply_round(ledger_stake_key, current_round);
                uchar ledger_stake_pub[32] = { 0 };
                uchar ledger_stake_hash[28] = { 0 };
                adadot_ada_scalar_pubkey_hash(ledger_stake_key, ledger_stake_pub,
                                             ledger_stake_hash);
                if (!der_ada_pair_seen_before(derivations, path_lengths, global_path,
                                              path_count, path_offset, path_len,
                                              next_offset, next_len)) {
                    adadot_emit_ada_base_pair_from_hashes(
                        env.isResult, env.buffResult, save_str, save_len,
                        ledger_payment_key, ledger_stake_key, ledger_payment_hash,
                        ledger_stake_hash, global_path, global_path + 1u, current_round,
                        0u, passphrase, pass_len, 0ul, store_seed, seed_value, 0u, false,
                        0x18u, *env.config, *env.filters, *env.filterStorage,
                        env.bloomStorage, env.xorStorage, env.xorUnStorage,
                        env.xorUcStorage, env.xorHcStorage, env.found);
                }
                if (!der_ada_pair_seen_before(derivations, path_lengths, global_path,
                                              path_count, next_offset, next_len,
                                              path_offset, path_len)) {
                    adadot_emit_ada_base_pair_from_hashes(
                        env.isResult, env.buffResult, save_str, save_len,
                        ledger_stake_key, ledger_payment_key, ledger_stake_hash,
                        ledger_payment_hash, global_path + 1u, global_path, current_round,
                        0u, passphrase, pass_len, 0ul, store_seed, seed_value, 0u, false,
                        0x18u, *env.config, *env.filters, *env.filterStorage,
                        env.bloomStorage, env.xorStorage, env.xorUnStorage,
                        env.xorUcStorage, env.xorHcStorage, env.found);
                }
            }
        }
    }

    if (adadot_ada_type_enabled(*env.config, 0x11u) &&
        !der_ada_pair_seen_before(derivations, path_lengths, global_path, path_count,
                                  path_offset, path_len, path_offset, path_len)) {
        adadot_emit_ada_base_pair_from_hashes(
            env.isResult, env.buffResult, save_str, save_len, payment_key, payment_key,
            payment_hash, payment_hash, global_path, global_path, current_round, 0u,
            passphrase, pass_len, 0ul, store_seed, seed_value, 0u, false, 0x11u,
            *env.config, *env.filters, *env.filterStorage, env.bloomStorage,
            env.xorStorage, env.xorUnStorage, env.xorUcStorage, env.xorHcStorage,
            env.found);
    }

    if (adadot_ada_type_enabled(*env.config, 0x11u) && global_path + 1u < path_count) {
        const uint next_offset = path_offset + path_len;
        const uint next_len = path_lengths[global_path + 1u];
        if (!der_path_equal(derivations, path_offset, path_len, next_offset, next_len)) {
            cardano_extended_private_key_t stake_xprv;
            der_get_child_key_cardano_ed25519(icarus_master, derivations, next_offset,
                                              next_len, stake_xprv);
            uchar stake_key[32] = { 0 };
            adadot_copy_thread_bytes(stake_key, stake_xprv.key, 32u);
            der_apply_round(stake_key, current_round);
            uchar stake_pub[32] = { 0 };
            uchar stake_hash[28] = { 0 };
            adadot_ada_scalar_pubkey_hash(stake_key, stake_pub, stake_hash);
            if (!der_ada_pair_seen_before(derivations, path_lengths, global_path, path_count,
                                          path_offset, path_len, next_offset, next_len)) {
                adadot_emit_ada_base_pair_from_hashes(
                    env.isResult, env.buffResult, save_str, save_len, payment_key, stake_key,
                    payment_hash, stake_hash, global_path, global_path + 1u, current_round,
                    0u, passphrase, pass_len, 0ul, store_seed, seed_value, 0u, false,
                    0x11u, *env.config, *env.filters, *env.filterStorage,
                    env.bloomStorage, env.xorStorage, env.xorUnStorage, env.xorUcStorage,
                    env.xorHcStorage, env.found);
            }
            if (!der_ada_pair_seen_before(derivations, path_lengths, global_path, path_count,
                                          next_offset, next_len, path_offset, path_len)) {
                adadot_emit_ada_base_pair_from_hashes(
                    env.isResult, env.buffResult, save_str, save_len, stake_key, payment_key,
                    stake_hash, payment_hash, global_path + 1u, global_path, current_round,
                    0u, passphrase, pass_len, 0ul, store_seed, seed_value, 0u, false,
                    0x11u, *env.config, *env.filters, *env.filterStorage,
                    env.bloomStorage, env.xorStorage, env.xorUnStorage, env.xorUcStorage,
                    env.xorHcStorage, env.found);
            }
        }
    }

    adadot_emit_ada_byron_ledger_from_bip32_key(
        env.isResult, env.buffResult, save_str, save_len, payment_key, global_path,
        current_round, 0u, passphrase, pass_len, 0ul, store_seed, seed_value, 0u,
        false, *env.config, *env.filters, *env.filterStorage, env.bloomStorage,
        env.xorStorage, env.xorUnStorage, env.xorUcStorage, env.xorHcStorage, env.found);
}

kernel void workerDerThread(device bool* isResult [[buffer(0)]],
                            device bool* buffResult [[buffer(1)]],
                            constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                            constant ulong& precPitch [[buffer(3)]],
                            const device uchar* d_master_secp [[buffer(4)]],
                            const device uchar* d_master_ed [[buffer(5)]],
                            const device uchar* d_master_cardano_icarus [[buffer(6)]],
                            const device uchar* d_master_cardano_daedalus [[buffer(7)]],
                            const device uchar* d_master_cardano_ledger [[buffer(8)]],
                            const device uchar* d_master_cardano_byron_legacy [[buffer(9)]],
                            const device uchar* d_entropy [[buffer(10)]],
                            const device uint* d_entropy_len [[buffer(11)]],
                            const device uchar* d_entropy_valid [[buffer(12)]],
                            const device char* d_save_str [[buffer(13)]],
                            constant uint& d_save_len [[buffer(14)]],
                            const device char* d_passphrase [[buffer(15)]],
                            constant uint& pass_len [[buffer(16)]],
                            constant ulong& seed_value [[buffer(17)]],
                            constant bool& store_seed [[buffer(18)]],
                            const device uint* d_derivations [[buffer(19)]],
                            const device uint* d_deriv_offsets [[buffer(20)]],
                            const device uint* derindex [[buffer(21)]],
                            constant uint& der_indexes_size [[buffer(22)]],
                            constant uint& der_offset [[buffer(23)]],
                            constant ulong& round [[buffer(24)]],
                            const device WorkerRuntimeBuffers& runtime [[buffer(25)]],
                            const device SubstratePathDevice* d_substrate_paths [[buffer(26)]],
                            uint tid [[thread_position_in_grid]]) {
    const uint global_path = tid + der_offset;
    if (global_path >= der_indexes_size || d_save_str == nullptr) {
        return;
    }

    WorkerEnv env;
    FoundBuffers found;
    if (!worker_init_env(env, found, isResult, buffResult, precPtr, precPitch, runtime)) {
        return;
    }
    env.substratePaths = d_substrate_paths;

    const bool derivation_buffers_valid = d_derivations != nullptr &&
                                          d_deriv_offsets != nullptr &&
                                          derindex != nullptr;
    uint path_offset = 0u;
    uint path_len = 0u;
    if (derivation_buffers_valid) {
        path_offset = d_deriv_offsets[global_path];
        path_len = derindex[global_path];
    }
    const device uint* path = derivation_buffers_valid
        ? d_derivations + path_offset
        : nullptr;
    const bool storeSeed = store_seed;

    char save_str[512] = { 0 };
    const uint save_len = min(d_save_len, 512u);
    der_copy_device_char_to_thread(save_str, d_save_str, save_len);

    extended_private_key_t master_private;
    extended_private_key_t ed_master_private;
    if (d_master_secp != nullptr) {
        der_load_master_extended(d_master_secp, &master_private);
    }
    if (d_master_ed != nullptr) {
        der_load_master_extended(d_master_ed, &ed_master_private);
    }

    const bool run_bip32_paths = derivation_buffers_valid &&
                                 (*env.config).secp256 != 0u &&
                                 (*env.config).bipDerivationsEnabled != 0u &&
                                 (((*env.config).derivationTypeMask & WORKER_DERIVATION_TYPE_MASK_BIP32) != 0u);
    const bool run_slip0010_paths = derivation_buffers_valid &&
                                    (*env.config).ed25519 != 0u &&
                                    (*env.config).bipDerivationsEnabled != 0u &&
                                    (((*env.config).derivationTypeMask & WORKER_DERIVATION_TYPE_MASK_SLIP0010) != 0u);
    const bool run_bip32_ed25519_paths = derivation_buffers_valid &&
                                         (*env.config).ed25519 != 0u &&
                                         (*env.config).bipDerivationsEnabled != 0u &&
                                         (((*env.config).derivationTypeMask & WORKER_DERIVATION_TYPE_MASK_BIP32_ED25519) != 0u);
    const bool run_dot_suri_paths = DERTHREAD_DOT_ENABLED &&
                                    DERTHREAD_SUBSTRATE_PATH_COUNT > 0u &&
                                    env.substratePaths != nullptr;
    const bool entropy_valid = d_entropy_valid != nullptr && d_entropy_valid[0] != 0u;

    cardano_extended_private_key_t cardano_icarus = {};
    cardano_extended_private_key_t cardano_daedalus = {};
    cardano_extended_private_key_t cardano_ledger = {};
    cardano_extended_private_key_t cardano_byron_legacy = {};
    if (entropy_valid) {
        der_load_cardano_xprv(d_master_cardano_icarus, cardano_icarus);
        der_load_cardano_xprv(d_master_cardano_daedalus, cardano_daedalus);
        if (d_master_cardano_ledger != nullptr) {
            der_load_cardano_xprv(d_master_cardano_ledger, cardano_ledger);
        }
        if (d_master_cardano_byron_legacy != nullptr) {
            der_load_cardano_xprv(d_master_cardano_byron_legacy, cardano_byron_legacy);
        }
    }

    if (run_bip32_paths && d_master_secp != nullptr) {
        uchar secp_key[32] = { 0 };
        der_get_child_key_secp256k1(precPtr, size_t(precPitch), &master_private, path, path_len, secp_key);

        uchar next_key[32] = { 0 };
        bool has_next = false;
        const bool emit_ed_targets = (*env.config).edTargetsAny != 0u;
        if (emit_ed_targets && (*env.config).ada != 0u) {
            worker_get_next_secp_key(env, master_private, d_derivations, derindex,
                                     path_offset, path_len, global_path, der_indexes_size,
                                     next_key, has_next);
        }
        if (emit_ed_targets) {
            worker_emit_ed_targets_from_key(env, save_str, ulong(save_len), secp_key,
                                            has_next ? next_key : nullptr, global_path, global_path,
                                            0u, d_passphrase, pass_len, 0ul, round,
                                            storeSeed, seed_value, 0u, false, true);
        }
        worker_emit_secp_targets_from_key(env, save_str, ulong(save_len), secp_key,
                                          global_path, global_path, 0u, d_passphrase,
                                          pass_len, 0ul, round, storeSeed, seed_value,
                                          0u, false);
    }

    if (run_slip0010_paths && d_master_ed != nullptr) {
        uchar ed_key32[32] = { 0 };
        der_get_child_key_ed25519(&ed_master_private, path, path_len, ed_key32);
        if ((*env.config).secpTargetsAny != 0u) {
            worker_emit_secp_targets_from_key(env, save_str, ulong(save_len), ed_key32,
                                              global_path, global_path, 0u, d_passphrase,
                                              pass_len, 0ul, round, storeSeed, seed_value,
                                              0u, false);
        }
        worker_emit_ed_targets_from_key(env, save_str, ulong(save_len), ed_key32, nullptr,
                                        global_path, global_path, 0u, d_passphrase,
                                        pass_len, 0ul, round, storeSeed, seed_value,
                                        0u, false, false);
    }

    if (run_bip32_ed25519_paths && d_master_ed != nullptr) {
        uchar ed_bip32_key[32] = { 0 };
        if (entropy_valid) {
            cardano_extended_private_key_t payment_xprv;
            der_get_child_key_cardano_ed25519(cardano_icarus, d_derivations, path_offset,
                                              path_len, payment_xprv);
            adadot_copy_thread_bytes(ed_bip32_key, payment_xprv.key, 32u);
        } else {
            der_get_child_key_cip1852(ed_master_private, d_derivations, path_offset,
                                      path_len, ed_bip32_key);
        }
        uchar next_key[32] = { 0 };
        bool has_next = false;
        if ((*env.config).ada != 0u && global_path + 1u < der_indexes_size) {
            const uint next_offset = path_offset + path_len;
            const uint next_len = derindex[global_path + 1u];
            if (!der_path_equal(d_derivations, path_offset, path_len,
                                next_offset, next_len)) {
                if (entropy_valid) {
                    cardano_extended_private_key_t stake_xprv;
                    der_get_child_key_cardano_ed25519(cardano_icarus, d_derivations,
                                                      next_offset, next_len, stake_xprv);
                    adadot_copy_thread_bytes(next_key, stake_xprv.key, 32u);
                } else {
                    der_get_child_key_cip1852(ed_master_private, d_derivations,
                                              next_offset, next_len, next_key);
                }
                has_next = true;
            }
        }
        if ((*env.config).secpTargetsAny != 0u) {
            worker_emit_secp_targets_from_key(env, save_str, ulong(save_len), ed_bip32_key,
                                              global_path, global_path, 0u, d_passphrase,
                                              pass_len, 0ul, round, storeSeed, seed_value,
                                              0u, false);
        }
        const bool non_ada_ed_targets =
            (*env.config).solana != 0u || (*env.config).ton != 0u ||
            (*env.config).tonAll != 0u || (*env.config).dot != 0u ||
            (*env.config).aptos != 0u || (*env.config).sui != 0u ||
            (*env.config).xrp != 0u || (*env.config).iota != 0u ||
            (*env.config).icp != 0u || (*env.config).xtz != 0u;
        const bool run_generic_ed_targets = (*env.config).edTargetsAny != 0u &&
            (!entropy_valid || non_ada_ed_targets);
        if (run_generic_ed_targets) {
            worker_emit_ed_targets_from_key(env, save_str, ulong(save_len), ed_bip32_key,
                                            has_next ? next_key : nullptr, global_path, global_path,
                                            0u, d_passphrase, pass_len, 0ul, round, storeSeed,
                                            seed_value, 0u, false, !entropy_valid, !entropy_valid);
        }
        if ((*env.config).ada != 0u && entropy_valid) {
            for (ulong s = 0ul; s <= 2ul * round; ++s) {
                der_emit_ada_cardano_roots_path(
                    env, save_str, ulong(save_len), cardano_icarus, cardano_daedalus,
                    d_master_cardano_ledger != nullptr ? &cardano_ledger : nullptr,
                    d_master_cardano_byron_legacy != nullptr ? &cardano_byron_legacy : nullptr,
                    d_derivations, derindex, global_path, der_indexes_size, path_offset,
                    path_len, long(s) - long(round), d_passphrase, pass_len, storeSeed,
                    seed_value);
            }
        }
    }

    if (run_dot_suri_paths && global_path == 0u) {
        if (entropy_valid) {
            der_emit_dot_substrate_from_entropy(env, save_str, ulong(save_len), d_entropy,
                                                d_entropy_len[0], d_passphrase, pass_len,
                                                round, storeSeed, seed_value,
                                                DERTHREAD_SUBSTRATE_PATH_COUNT);
        } else {
            adadot_emit_dot_substrate_from_seed(
                env.isResult, env.buffResult, save_str, ulong(save_len), ed_master_private.key,
                0l, 0u, d_passphrase, pass_len, 0ul, storeSeed, seed_value, 0u, false,
                *env.config, env.substratePaths, *env.filters, *env.filterStorage,
                env.bloomStorage, env.xorStorage, env.xorUnStorage, env.xorUcStorage,
                env.xorHcStorage, env.found, DERTHREAD_SUBSTRATE_PATH_COUNT);
        }
    }
}
