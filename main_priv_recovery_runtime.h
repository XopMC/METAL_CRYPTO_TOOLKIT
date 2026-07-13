#pragma once

struct PrivRecoveryPreparedTask {
    std::string source;
    uint64_t line_no = 0ull;
    std::string normalized_template;
    std::array<uint8_t, 32> base_private_key{};
    std::vector<int> missing_nibbles;
};

enum class PrivRecoveryFastKind : uint8_t {
    Generic = 0,
    SeqSuffix = 1,
    SeqHybridSuffix = 2,
    SeqContiguousStrided = 3
};

struct PrivRecoveryFastPathPlan {
    PrivRecoveryFastKind kind = PrivRecoveryFastKind::Generic;
    uint64_t step_value = 1ull;
    uint64_t inner_candidate_count = 0ull;
    std::vector<int> outer_missing_positions;
    std::vector<int> fast_missing_positions;
    const char* log_label = "generic";
};

struct PrivRecoveryMissingBlock {
    size_t run_begin = 0u;
    size_t run_end = 0u;
    size_t fast_begin = 0u;
    size_t fast_end = 0u;
    int fast_len = 0;
    int suffix_fixed_nibbles = 0;
};

static inline std::string priv_recovery_trim_copy(const std::string& value) {
    size_t begin = 0u;
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1u])) != 0) {
        --end;
    }
    return value.substr(begin, end - begin);
}

static inline bool priv_recovery_is_hex_char(const char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static inline uint8_t priv_recovery_hex_value(const char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(10 + (c - 'a'));
    }
    return static_cast<uint8_t>(10 + (c - 'A'));
}

static inline void priv_recovery_apply_nibble_host(std::array<uint8_t, 32>& key, const int nibble_pos, const uint8_t nibble) {
    const int byte_index = nibble_pos >> 1;
    if ((nibble_pos & 1) == 0) {
        key[static_cast<size_t>(byte_index)] = static_cast<uint8_t>((key[static_cast<size_t>(byte_index)] & 0x0Fu) | ((nibble & 0x0Fu) << 4));
    }
    else {
        key[static_cast<size_t>(byte_index)] = static_cast<uint8_t>((key[static_cast<size_t>(byte_index)] & 0xF0u) | (nibble & 0x0Fu));
    }
}

static inline std::string priv_recovery_format_ref(const std::string& source, const uint64_t line_no) {
    if (line_no == 0ull) {
        return source;
    }
    return source + ":" + std::to_string(line_no);
}

static inline bool priv_recovery_pow16_u64(const int missing_count, uint64_t& out) {
    out = 1ull;
    if (missing_count < 0 || missing_count > 15) {
        return false;
    }
    out <<= (missing_count * 4);
    return true;
}

static inline int priv_recovery_low_missing_count(const int missing_count) {
    if (missing_count <= 0) {
        return 0;
    }
    return (missing_count > 15) ? 15 : missing_count;
}

static inline int priv_recovery_trailing_block_len(const std::vector<int>& positions) {
    if (positions.empty() || positions.back() != 63) {
        return 0;
    }
    int count = 1;
    for (int i = static_cast<int>(positions.size()) - 2; i >= 0; --i) {
        if (positions[static_cast<size_t>(i)] != positions[static_cast<size_t>(i + 1)] - 1) {
            break;
        }
        ++count;
    }
    return count;
}

static inline bool priv_recovery_find_best_strided_block(const std::vector<int>& positions, PrivRecoveryMissingBlock& best_block) {
    bool found = false;
    int best_len = 0;
    int best_suffix_fixed = 0;

    size_t run_begin = 0u;
    while (run_begin < positions.size()) {
        size_t run_end = run_begin;
        while ((run_end + 1u) < positions.size() && positions[run_end + 1u] == positions[run_end] + 1) {
            ++run_end;
        }

        const int run_len = static_cast<int>(run_end - run_begin + 1u);
        const int suffix_fixed_nibbles = 63 - positions[run_end];
        if (suffix_fixed_nibbles > 0 && suffix_fixed_nibbles <= 15) {
            const int fast_len = std::min(run_len, 15);
            if (!found || fast_len > best_len || (fast_len == best_len && suffix_fixed_nibbles < best_suffix_fixed)) {
                found = true;
                best_len = fast_len;
                best_suffix_fixed = suffix_fixed_nibbles;
                best_block.run_begin = run_begin;
                best_block.run_end = run_end;
                best_block.fast_begin = run_end + 1u - static_cast<size_t>(fast_len);
                best_block.fast_end = run_end;
                best_block.fast_len = fast_len;
                best_block.suffix_fixed_nibbles = suffix_fixed_nibbles;
            }
        }

        run_begin = run_end + 1u;
    }

    return found;
}

static inline bool priv_recovery_key_is_zero(const std::array<uint8_t, 32>& key) {
    for (const uint8_t b : key) {
        if (b != 0u) {
            return false;
        }
    }
    return true;
}

static constexpr uint8_t kPrivRecoverySecpOrder[32] = {
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFEu,
    0xBAu, 0xAEu, 0xDCu, 0xE6u, 0xAFu, 0x48u, 0xA0u, 0x3Bu,
    0xBFu, 0xD2u, 0x5Eu, 0x8Cu, 0xD0u, 0x36u, 0x41u, 0x41u
};

static inline int priv_recovery_compare_secp_order(const std::array<uint8_t, 32>& key) {
    return std::memcmp(key.data(), kPrivRecoverySecpOrder, sizeof(kPrivRecoverySecpOrder));
}

static inline void priv_recovery_mul_u64_u64_to_u128(const uint64_t a, const uint64_t b, uint64_t& out_lo, uint64_t& out_hi) {
    const uint64_t a_lo = static_cast<uint32_t>(a);
    const uint64_t a_hi = a >> 32;
    const uint64_t b_lo = static_cast<uint32_t>(b);
    const uint64_t b_hi = b >> 32;

    const uint64_t p0 = a_lo * b_lo;
    const uint64_t p1 = a_lo * b_hi;
    const uint64_t p2 = a_hi * b_lo;
    const uint64_t p3 = a_hi * b_hi;

    const uint64_t mid = (p0 >> 32) + static_cast<uint32_t>(p1) + static_cast<uint32_t>(p2);
    out_lo = (p0 & 0xFFFFFFFFull) | (mid << 32);
    out_hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
}

static inline bool priv_recovery_add_u128_to_key(const std::array<uint8_t, 32>& key,
                                                  const uint64_t add_lo,
                                                  const uint64_t add_hi,
                                                  std::array<uint8_t, 32>& out) {
    out = key;
    const uint64_t parts[2] = { add_lo, add_hi };
    int byte_index = 31;
    uint64_t carry = 0ull;

    for (int part = 0; part < 2; ++part) {
        uint64_t value = parts[part];
        for (int byte = 0; byte < 8; ++byte, --byte_index) {
            const uint64_t add_byte = value & 0xFFu;
            value >>= 8;
            const uint64_t sum = static_cast<uint64_t>(out[static_cast<size_t>(byte_index)]) + add_byte + carry;
            out[static_cast<size_t>(byte_index)] = static_cast<uint8_t>(sum & 0xFFu);
            carry = sum >> 8;
        }
    }

    while (byte_index >= 0 && carry != 0ull) {
        const uint64_t sum = static_cast<uint64_t>(out[static_cast<size_t>(byte_index)]) + carry;
        out[static_cast<size_t>(byte_index)] = static_cast<uint8_t>(sum & 0xFFu);
        carry = sum >> 8;
        --byte_index;
    }

    return carry == 0ull;
}

static inline bool priv_recovery_materialize_offset_key(const std::array<uint8_t, 32>& key,
                                                        const uint64_t step_value,
                                                        const uint64_t index,
                                                        std::array<uint8_t, 32>& out) {
    uint64_t add_lo = 0ull;
    uint64_t add_hi = 0ull;
    priv_recovery_mul_u64_u64_to_u128(index, step_value, add_lo, add_hi);
    return priv_recovery_add_u128_to_key(key, add_lo, add_hi, out);
}

static inline bool priv_recovery_seq_range_is_safe(const std::array<uint8_t, 32>& batch_start_key,
                                                   const uint64_t step_value,
                                                   const uint64_t range_count) {
    if (range_count == 0ull) {
        return false;
    }
    if (priv_recovery_key_is_zero(batch_start_key)) {
        return false;
    }
    if (priv_recovery_compare_secp_order(batch_start_key) >= 0) {
        return false;
    }

    std::array<uint8_t, 32> end_key{};
    if (!priv_recovery_materialize_offset_key(batch_start_key, step_value, range_count - 1ull, end_key)) {
        return false;
    }
    if (priv_recovery_key_is_zero(end_key)) {
        return false;
    }
    if (priv_recovery_compare_secp_order(end_key) >= 0) {
        return false;
    }
    return true;
}

static inline PrivRecoveryFastPathPlan priv_recovery_classify_fast_path(const PrivRecoveryPreparedTask& task) {
    PrivRecoveryFastPathPlan plan;
    if (Rounds != 0ull || task.missing_nibbles.empty()) {
        return plan;
    }

    const auto& missing = task.missing_nibbles;
    const int trailing_len = priv_recovery_trailing_block_len(missing);
    const int fast_trailing_len = std::min(trailing_len, 15);
    if (fast_trailing_len > 0) {
        uint64_t inner_count = 0ull;
        if (!priv_recovery_pow16_u64(fast_trailing_len, inner_count)) {
            return plan;
        }
        plan.kind = (static_cast<int>(missing.size()) == fast_trailing_len)
            ? PrivRecoveryFastKind::SeqSuffix
            : PrivRecoveryFastKind::SeqHybridSuffix;
        plan.step_value = 1ull;
        plan.inner_candidate_count = inner_count;
        plan.log_label = (plan.kind == PrivRecoveryFastKind::SeqSuffix) ? "secp-vanity-suffix" : "secp-vanity-hybrid";
        plan.outer_missing_positions.assign(missing.begin(), missing.end() - fast_trailing_len);
        plan.fast_missing_positions.assign(missing.end() - fast_trailing_len, missing.end());
        return plan;
    }

    PrivRecoveryMissingBlock best_block;
    if (priv_recovery_find_best_strided_block(missing, best_block)) {
        uint64_t inner_count = 0ull;
        if (!priv_recovery_pow16_u64(best_block.fast_len, inner_count)) {
            return plan;
        }
        plan.kind = PrivRecoveryFastKind::SeqContiguousStrided;
        plan.step_value = 1ull << (best_block.suffix_fixed_nibbles * 4);
        plan.inner_candidate_count = inner_count;
        plan.log_label = "secp-seq-strided";
        plan.fast_missing_positions.assign(missing.begin() + static_cast<std::ptrdiff_t>(best_block.fast_begin),
                                           missing.begin() + static_cast<std::ptrdiff_t>(best_block.fast_end + 1u));
        plan.outer_missing_positions.reserve(missing.size() - static_cast<size_t>(best_block.fast_len));
        for (size_t i = 0u; i < missing.size(); ++i) {
            if (i < best_block.fast_begin || i > best_block.fast_end) {
                plan.outer_missing_positions.emplace_back(missing[i]);
            }
        }
        return plan;
    }

    return plan;
}

static inline void priv_recovery_append_key_line(std::string& out, const std::array<uint8_t, 32>& key) {
    static const char* kHex = "0123456789abcdef";
    const size_t offset = out.size();
    out.resize(offset + 65u);
    char* dst = &out[offset];
    for (size_t i = 0u; i < key.size(); ++i) {
        const uint8_t b = key[i];
        dst[i * 2u] = kHex[b >> 4];
        dst[i * 2u + 1u] = kHex[b & 0x0Fu];
    }
    dst[64] = '\n';
}

static inline void priv_recovery_apply_index_to_positions(std::array<uint8_t, 32>& key,
                                                          const std::vector<int>& positions,
                                                          uint64_t index) {
    for (size_t i = positions.size(); i-- > 0u;) {
        priv_recovery_apply_nibble_host(key, positions[i], static_cast<uint8_t>(index & 0x0Fu));
        index >>= 4;
    }
}

static bool priv_recovery_prepare_task(const std::string& raw_line,
                                       const std::string& source,
                                       const uint64_t line_no,
                                       PrivRecoveryPreparedTask& task,
                                       std::string& err) {
    err.clear();
    task = PrivRecoveryPreparedTask{};
    task.source = source;
    task.line_no = line_no;

    const std::string trimmed = priv_recovery_trim_copy(raw_line);
    if (trimmed.empty()) {
        err = "empty private-key template";
        return false;
    }
    if (trimmed.size() != 64u) {
        err = "private-key template must be exactly 64 hex characters after trimming";
        return false;
    }

    task.normalized_template = trimmed;
    std::transform(task.normalized_template.begin(), task.normalized_template.end(), task.normalized_template.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

    for (size_t i = 0u; i < task.normalized_template.size(); ++i) {
        const char c = task.normalized_template[i];
        if (c == '*') {
            task.missing_nibbles.emplace_back(static_cast<int>(i));
            continue;
        }
        if (!priv_recovery_is_hex_char(c)) {
            err = std::string("invalid character in private-key template: '") + c + "'";
            return false;
        }
        priv_recovery_apply_nibble_host(task.base_private_key, static_cast<int>(i), priv_recovery_hex_value(c));
    }

    if (task.missing_nibbles.size() > 32u) {
        err = "private-key template exceeds the supported limit of 32 wildcard nibbles";
        return false;
    }

    return true;
}




static bool priv_recovery_run_materialized_batch(const std::string& combined, uint64_t& tested, std::string& err) {
    if (combined.empty()) {
        return true;
    }
    std::istringstream stream(combined);
    const ThreadInputSnapshot snap = capture_thread_input_snapshot();
    const metalError_t st = processMetalPRIV(stream);
    restore_thread_input_snapshot(snap);
    if (st != metalSuccess) {
        err = std::string("priv recovery exact batch failed: ") + metalGetErrorString(st);
        return false;
    }
    tested += static_cast<uint64_t>(std::count(combined.begin(), combined.end(), '\n'));
    return true;
}

static bool priv_recovery_run_generic_low_space(const PrivRecoveryPreparedTask& task,
                                                const std::array<uint8_t, 32>& active_base_key,
                                                const std::vector<int>& low_missing_positions,
                                                const uint64_t start,
                                                const uint64_t count,
                                                uint64_t& tested,
                                                std::string& err) {
    err.clear();
    if (count == 0ull) {
        return true;
    }

    const uint64_t nominal_chunk = std::max<uint64_t>(1ull,
        static_cast<uint64_t>(BLOCK_NUMBER) * static_cast<uint64_t>(BLOCK_THREADS) * static_cast<uint64_t>(THREAD_STEPS));
    const uint64_t max_chunk = std::max<uint64_t>(1ull, std::min<uint64_t>(nominal_chunk, 262144ull));

    uint64_t done = 0ull;
    while (done < count) {
        const uint64_t current = std::min<uint64_t>(max_chunk, count - done);
        std::string combined;
        combined.reserve(static_cast<size_t>(current * 65ull));
        for (uint64_t i = 0ull; i < current; ++i) {
            std::array<uint8_t, 32> key = active_base_key;
            priv_recovery_apply_index_to_positions(key, low_missing_positions, start + done + i);
            priv_recovery_append_key_line(combined, key);
        }
        if (!priv_recovery_run_materialized_batch(combined, tested, err)) {
            return false;
        }
        done += current;
    }
    return true;
}

enum class PrivRecoverySecpSeqLaunchKind : uint8_t {
    GenericSeq = 0,
    VanityC,
    VanityU,
    VanityS,
    VanityR,
    VanityE,
    VanityX,
    VanityP2wsh,
    VanityCu,
    VanityCus,
    VanityCusr,
    VanityCuse,
    VanityCusex,
    VanityCusrx,
    VanityCusrxe
};

static thread_local RecoveryGpuDirectContext g_priv_recovery_ctx;

static inline bool priv_recovery_has_supported_secp_targets() {
    return Compressed || Uncompressed || Segwit || P2wsh || Taproot || Ethereum || Xpoint;
}

static inline bool priv_recovery_has_supported_ed_targets() {
    return Solana || Ton || Ton_all;
}

static inline bool priv_recovery_has_unsupported_host_targets() {
    return Dot || Aptos || Sui || Xrp || Exodus || Iota || Ada || Icp || Fil || Xtz || Endomorphism;
}

static inline bool priv_recovery_direct_runtime_allowed() {
    return !FULL && Rounds == 0ull && !priv_recovery_has_unsupported_host_targets() &&
        (priv_recovery_has_supported_secp_targets() || priv_recovery_has_supported_ed_targets());
}

static inline PrivRecoverySecpSeqLaunchKind priv_recovery_select_secp_launch_kind(const PrivRecoveryFastPathPlan& plan) {
    if (!priv_recovery_has_supported_secp_targets() || plan.kind == PrivRecoveryFastKind::Generic || plan.step_value != 1ull) {
        return PrivRecoverySecpSeqLaunchKind::GenericSeq;
    }
    const bool exact_cu = !P2wsh && Compressed && Uncompressed && !Segwit && !Taproot && !Ethereum && !Xpoint;
    const bool exact_cus = !P2wsh && Compressed && Uncompressed && Segwit && !Taproot && !Ethereum && !Xpoint;
    const bool exact_cusr = !P2wsh && Compressed && Uncompressed && Segwit && Taproot && !Ethereum && !Xpoint;
    const bool exact_cuse = !P2wsh && Compressed && Uncompressed && Segwit && !Taproot && Ethereum && !Xpoint;
    const bool exact_cusex = !P2wsh && Compressed && Uncompressed && Segwit && !Taproot && Ethereum && Xpoint;
    const bool exact_cusrx = !P2wsh && Compressed && Uncompressed && Segwit && Taproot && !Ethereum && Xpoint;
    const bool exact_cusrxe = !P2wsh && Compressed && Uncompressed && Segwit && Taproot && Ethereum && Xpoint;
    if (!P2wsh && Compressed && !Uncompressed && !Segwit && !Taproot && !Ethereum && !Xpoint) return PrivRecoverySecpSeqLaunchKind::VanityC;
    if (!P2wsh && !Compressed && Uncompressed && !Segwit && !Taproot && !Ethereum && !Xpoint) return PrivRecoverySecpSeqLaunchKind::VanityU;
    if (!P2wsh && !Compressed && !Uncompressed && Segwit && !Taproot && !Ethereum && !Xpoint) return PrivRecoverySecpSeqLaunchKind::VanityS;
    if (!P2wsh && !Compressed && !Uncompressed && !Segwit && Taproot && !Ethereum && !Xpoint) return PrivRecoverySecpSeqLaunchKind::VanityR;
    if (!P2wsh && !Compressed && !Uncompressed && !Segwit && !Taproot && Ethereum && !Xpoint) return PrivRecoverySecpSeqLaunchKind::VanityE;
    if (!P2wsh && !Compressed && !Uncompressed && !Segwit && !Taproot && !Ethereum && Xpoint) return PrivRecoverySecpSeqLaunchKind::VanityX;
    if (P2wsh && !Compressed && !Uncompressed && !Segwit && !Taproot && !Ethereum && !Xpoint) return PrivRecoverySecpSeqLaunchKind::VanityP2wsh;
    if (exact_cu) return PrivRecoverySecpSeqLaunchKind::VanityCu;
    if (exact_cus) return PrivRecoverySecpSeqLaunchKind::VanityCus;
    if (exact_cusr) return PrivRecoverySecpSeqLaunchKind::VanityCusr;
    if (exact_cuse) return PrivRecoverySecpSeqLaunchKind::VanityCuse;
    if (exact_cusex) return PrivRecoverySecpSeqLaunchKind::VanityCusex;
    if (exact_cusrx) return PrivRecoverySecpSeqLaunchKind::VanityCusrx;
    if (exact_cusrxe) return PrivRecoverySecpSeqLaunchKind::VanityCusrxe;
    return PrivRecoverySecpSeqLaunchKind::GenericSeq;
}

static inline PvkEdLaunchKind priv_recovery_select_ed_launch_kind() {
    if (Solana && Ton_all) return PvkEdLaunchKind::SolanaTonAll;
    if (Solana && Ton) return PvkEdLaunchKind::SolanaTon;
    if (Ton_all) return PvkEdLaunchKind::TonAll;
    if (Ton) return PvkEdLaunchKind::Ton;
    if (Solana) return PvkEdLaunchKind::Solana;
    return PvkEdLaunchKind::Generic;
}

static inline bool priv_recovery_ed_launch_specialized(const PvkEdLaunchKind launch_kind) {
    return launch_kind != PvkEdLaunchKind::Generic;
}

static inline bool priv_recovery_linear_range_is_safe(const std::array<uint8_t, 32>& batch_start_key,
                                                      const uint64_t step_value,
                                                      const uint64_t range_count) {
    if (range_count == 0ull) {
        return false;
    }
    std::array<uint8_t, 32> end_key{};
    return priv_recovery_materialize_offset_key(batch_start_key, step_value, range_count - 1ull, end_key);
}

static inline uint64_t priv_recovery_result_slot_capacity(const RecoveryGpuDirectContext& ctx) {
    return (ctx.batch_capacity == 0ull) ? 1ull : ctx.batch_capacity;
}

static inline uint64_t priv_recovery_slot_capacity_for_keys(const RecoveryGpuDirectContext& ctx,
                                                            const uint64_t keys_per_slot) {
    const uint64_t slots = priv_recovery_result_slot_capacity(ctx);
    if (keys_per_slot == 0ull) {
        return slots;
    }
    if (slots > (std::numeric_limits<uint64_t>::max() / keys_per_slot)) {
        return std::numeric_limits<uint64_t>::max();
    }
    return std::max<uint64_t>(1ull, slots * keys_per_slot);
}

static inline void priv_recovery_save_found_results() {
    SaveResultPRIV(OUT_FILE, Founds, save, Derivations_list);
}

static const char* priv_recovery_kind_label_for_family(const PrivRecoveryFastKind kind, const bool ed_family) {
    switch (kind) {
    case PrivRecoveryFastKind::SeqSuffix:
        return ed_family ? "ed-specialized-suffix" : "secp-seq-suffix";
    case PrivRecoveryFastKind::SeqHybridSuffix:
        return ed_family ? "ed-specialized-hybrid" : "secp-seq-hybrid";
    case PrivRecoveryFastKind::SeqContiguousStrided:
        return ed_family ? "ed-specialized-strided" : "secp-seq-strided";
    default:
        return "generic";
    }
}

static const char* priv_recovery_secp_launch_label(const PrivRecoveryFastPathPlan& plan, const PrivRecoverySecpSeqLaunchKind launch_kind) {
    if (launch_kind != PrivRecoverySecpSeqLaunchKind::GenericSeq && plan.step_value == 1ull) {
        return (plan.kind == PrivRecoveryFastKind::SeqHybridSuffix) ? "secp-vanity-hybrid" : "secp-vanity-suffix";
    }
    return priv_recovery_kind_label_for_family(plan.kind, false);
}

static const char* priv_recovery_ed_launch_label(const PrivRecoveryFastPathPlan& plan, const PvkEdLaunchKind launch_kind) {
    if (!priv_recovery_ed_launch_specialized(launch_kind)) {
        return "generic";
    }
    return priv_recovery_kind_label_for_family(plan.kind, true);
}

static bool priv_recovery_ensure_direct_context(RecoveryGpuDirectContext& ctx, std::string& err) {
    err.clear();
    const uint64_t output_size = static_cast<uint64_t>(BLOCK_NUMBER) * static_cast<uint64_t>(BLOCK_THREADS);
    const uint64_t required_capacity = (output_size == 0ull) ? 1ull : output_size;
    if (ctx.batch_capacity == required_capacity && ctx.buffIsResult != nullptr && ctx.buffDeviceResult != nullptr) {
        return true;
    }
    ctx.batch_capacity = required_capacity;
    const metalError_t st = acquire_shared_result_buffers(ctx.batch_capacity, &ctx.buffIsResult, &ctx.buffDeviceResult);
    if (st != metalSuccess) {
        err = std::string("acquire_shared_result_buffers failed: ") + metalGetErrorString(st);
        return false;
    }
    return true;
}

static bool priv_recovery_ensure_task_constant_buffers(RecoveryGpuDirectContext& ctx,
                                                      const PrivRecoveryPreparedTask& task,
                                                      const std::vector<int>& low_missing_positions,
                                                      std::string& err) {
    err.clear();

    if (ctx.devPvkBaseKey == nullptr) {
        const metalError_t st = metalMalloc(reinterpret_cast<void**>(&ctx.devPvkBaseKey), 32u);
        if (st != metalSuccess) {
            err = "metalMalloc PVK base key failed";
            return false;
        }
    }

    if (low_missing_positions.size() > ctx.devPvkMissingCapacity) {
        if (ctx.devPvkMissingPositions != nullptr) {
            metalFree(ctx.devPvkMissingPositions);
            ctx.devPvkMissingPositions = nullptr;
        }
        if (!low_missing_positions.empty()) {
            const metalError_t st = metalMalloc(reinterpret_cast<void**>(&ctx.devPvkMissingPositions), low_missing_positions.size() * sizeof(int));
            if (st != metalSuccess) {
                err = "metalMalloc PVK missing positions failed";
                return false;
            }
        }
        ctx.devPvkMissingCapacity = low_missing_positions.size();
    }

    const size_t template_bytes = task.normalized_template.size() + 1u;
    if (template_bytes > ctx.devPvkTemplateCapacity) {
        if (ctx.devPvkTemplate != nullptr) {
            metalFree(ctx.devPvkTemplate);
            ctx.devPvkTemplate = nullptr;
        }
        const metalError_t st = metalMalloc(reinterpret_cast<void**>(&ctx.devPvkTemplate), template_bytes);
        if (st != metalSuccess) {
            err = "metalMalloc PVK template failed";
            return false;
        }
        ctx.devPvkTemplateCapacity = template_bytes;
    }

    if (ctx.cachedPvkMissingPositions != low_missing_positions) {
        if (!low_missing_positions.empty()) {
            const metalError_t st = metalMemcpy(ctx.devPvkMissingPositions, low_missing_positions.data(), low_missing_positions.size() * sizeof(int), metalMemcpyHostToDevice);
            if (st != metalSuccess) {
                err = "metalMemcpy PVK missing positions failed";
                return false;
            }
        }
        ctx.cachedPvkMissingPositions = low_missing_positions;
    }

    if (ctx.cachedPvkTemplate != task.normalized_template) {
        const metalError_t st = metalMemcpy(ctx.devPvkTemplate, task.normalized_template.c_str(), template_bytes, metalMemcpyHostToDevice);
        if (st != metalSuccess) {
            err = "metalMemcpy PVK template failed";
            return false;
        }
        ctx.cachedPvkTemplate = task.normalized_template;
    }

    return true;
}

static bool priv_recovery_upload_base_key(RecoveryGpuDirectContext& ctx,
                                         const std::array<uint8_t, 32>& active_base_key,
                                         std::string& err) {
    err.clear();

    if (ctx.devPvkBaseKey == nullptr) {
        const metalError_t st = metalMalloc(reinterpret_cast<void**>(&ctx.devPvkBaseKey), 32u);
        if (st != metalSuccess) {
            err = "metalMalloc PVK base key failed";
            return false;
        }
    }

    if (ctx.cachedPvkBaseKeyValid && ctx.cachedPvkBaseKey == active_base_key) {
        return true;
    }

    const metalError_t st = metalMemcpy(ctx.devPvkBaseKey, active_base_key.data(), 32u, metalMemcpyHostToDevice);
    if (st != metalSuccess) {
        err = "metalMemcpy PVK base key failed";
        return false;
    }
    ctx.cachedPvkBaseKey = active_base_key;
    ctx.cachedPvkBaseKeyValid = true;

    return true;
}

static bool priv_recovery_upload_task_buffers(RecoveryGpuDirectContext& ctx,
                                             const PrivRecoveryPreparedTask& task,
                                             const std::array<uint8_t, 32>& active_base_key,
                                             const std::vector<int>& low_missing_positions,
                                             std::string& err) {
    err.clear();

    if (!priv_recovery_ensure_task_constant_buffers(ctx, task, low_missing_positions, err)) {
        return false;
    }

    return priv_recovery_upload_base_key(ctx, active_base_key, err);
}

static bool priv_recovery_run_low_space(RecoveryGpuDirectContext& ctx,
                                       const PrivRecoveryPreparedTask& task,
                                       const std::array<uint8_t, 32>& active_base_key,
                                       const std::vector<int>& low_missing_positions,
                                       const uint64_t range_start,
                                       const uint64_t range_count,
                                       uint64_t& tested,
                                       std::string& err) {
    err.clear();
    if (range_count == 0ull) {
        return true;
    }

    if (!priv_recovery_upload_task_buffers(ctx, task, active_base_key, low_missing_positions, err)) {
        return false;
    }

    const unsigned int launch_threads = (BLOCK_THREADS == 0u) ? 256u : BLOCK_THREADS;
    const uint64_t hard_batch = priv_recovery_result_slot_capacity(ctx);

    struct PvkRange {
        uint64_t start = 0ull;
        uint64_t count = 0ull;
    };

    std::vector<PvkRange> pending;
    pending.reserve(64u);
    pending.push_back(PvkRange{ range_start, range_count });

    while (!pending.empty()) {
        PvkRange current = pending.back();
        pending.pop_back();
        if (current.count == 0ull) {
            continue;
        }

        if (current.count > hard_batch) {
            pending.push_back(PvkRange{ current.start + hard_batch, current.count - hard_batch });
            current.count = hard_batch;
        }

        const unsigned int launch_blocks = static_cast<unsigned int>(
            std::max<uint64_t>(1ull, (current.count + static_cast<uint64_t>(launch_threads) - 1ull) / static_cast<uint64_t>(launch_threads)));

        clear_result_flag_host(ctx.buffIsResult);
        metal_launch("workerPvkRecoveryBatch", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
            ctx.buffIsResult,
            ctx.buffDeviceResult,
            _dev_precomp,
            pitch,
            ctx.devPvkTemplate,
            static_cast<uint32_t>(task.normalized_template.size()),
            ctx.devPvkBaseKey,
            ctx.devPvkMissingPositions,
            static_cast<int>(low_missing_positions.size()),
            current.start,
            current.count,
            Rounds);

        metalError_t st = metalGetLastError();
        if (st != metalSuccess) {
            err = std::string("PVK recovery kernel launch failed: ") + metalGetErrorString(st);
            return false;
        }

        st = metalDeviceSynchronize();
        if (st != metalSuccess) {
            err = std::string("PVK recovery kernel sync failed: ") + metalGetErrorString(st);
            return false;
        }

        recovery_u64_add_saturating(tested, current.count);
        counterTotal += current.count;

        if (read_result_flag_host(ctx.buffIsResult)) {
            clear_result_flag_host(ctx.buffIsResult);
            priv_recovery_save_found_results();
        }
    }

    return true;
}

static bool priv_recovery_run_low_space_ed_only(RecoveryGpuDirectContext& ctx,
                                               const PrivRecoveryPreparedTask& task,
                                               const std::array<uint8_t, 32>& active_base_key,
                                               const std::vector<int>& low_missing_positions,
                                               const uint64_t range_start,
                                               const uint64_t range_count,
                                               uint64_t& tested,
                                               std::string& err) {
    err.clear();
    if (range_count == 0ull || !priv_recovery_has_supported_ed_targets()) {
        return true;
    }

    if (!priv_recovery_upload_task_buffers(ctx, task, active_base_key, low_missing_positions, err)) {
        return false;
    }

    const unsigned int launch_threads = (BLOCK_THREADS == 0u) ? 256u : BLOCK_THREADS;
    const uint64_t hard_batch = priv_recovery_result_slot_capacity(ctx);

    struct PvkRange {
        uint64_t start = 0ull;
        uint64_t count = 0ull;
    };

    std::vector<PvkRange> pending;
    pending.reserve(64u);
    pending.push_back(PvkRange{ range_start, range_count });

    while (!pending.empty()) {
        PvkRange current = pending.back();
        pending.pop_back();
        if (current.count == 0ull) {
            continue;
        }

        if (current.count > hard_batch) {
            pending.push_back(PvkRange{ current.start + hard_batch, current.count - hard_batch });
            current.count = hard_batch;
        }

        const unsigned int launch_blocks = static_cast<unsigned int>(
            std::max<uint64_t>(1ull, (current.count + static_cast<uint64_t>(launch_threads) - 1ull) / static_cast<uint64_t>(launch_threads)));

        clear_result_flag_host(ctx.buffIsResult);
        metal_launch("workerPvkRecoveryBatchEdOnly", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
            ctx.buffIsResult,
            ctx.buffDeviceResult,
            ctx.devPvkTemplate,
            static_cast<uint32_t>(task.normalized_template.size()),
            ctx.devPvkBaseKey,
            ctx.devPvkMissingPositions,
            static_cast<int>(low_missing_positions.size()),
            current.start,
            current.count,
            Rounds);

        metalError_t st = metalGetLastError();
        if (st != metalSuccess) {
            err = std::string("PVK recovery ED kernel launch failed: ") + metalGetErrorString(st);
            return false;
        }

        st = metalDeviceSynchronize();
        if (st != metalSuccess) {
            err = std::string("PVK recovery ED kernel sync failed: ") + metalGetErrorString(st);
            return false;
        }

        recovery_u64_add_saturating(tested, current.count);
        counterTotal += current.count;

        if (read_result_flag_host(ctx.buffIsResult)) {
            clear_result_flag_host(ctx.buffIsResult);
            priv_recovery_save_found_results();
        }
    }

    return true;
}

static uint32_t priv_recovery_ed_keys_per_thread(const uint64_t step, const PvkEdLaunchKind launch_kind) {
    if (step != 1ull) {
        return 64u;
    }

    switch (launch_kind) {
    case PvkEdLaunchKind::Solana:
        return 512u;
    case PvkEdLaunchKind::Ton:
    case PvkEdLaunchKind::SolanaTon:
        return 128u;
    case PvkEdLaunchKind::TonAll:
    case PvkEdLaunchKind::SolanaTonAll:
        return 64u;
    case PvkEdLaunchKind::Generic:
    default:
        return 64u;
    }
}

static bool priv_recovery_run_seq_space_ed_only(RecoveryGpuDirectContext& ctx,
                                               const PrivRecoveryPreparedTask& task,
                                               const std::array<uint8_t, 32>& active_base_key,
                                               const PrivRecoveryFastPathPlan& fast_plan,
                                               const uint64_t range_start,
                                               const uint64_t range_count,
                                               const bool progress_enabled,
                                               uint64_t& tested,
                                               std::string& err) {
    err.clear();
    if (range_count == 0ull || !priv_recovery_has_supported_ed_targets()) {
        return true;
    }

    const unsigned int launch_threads = (BLOCK_THREADS == 0u) ? 256u : BLOCK_THREADS;
    const PvkEdLaunchKind ed_launch_kind = priv_recovery_select_ed_launch_kind();
    const uint32_t keys_per_thread = priv_recovery_ed_keys_per_thread(fast_plan.step_value, ed_launch_kind);
    const uint64_t launch_capacity = priv_recovery_slot_capacity_for_keys(ctx, static_cast<uint64_t>(keys_per_thread));

    struct PvkRange {
        uint64_t start = 0ull;
        uint64_t count = 0ull;
    };

    std::vector<PvkRange> pending;
    pending.reserve(64u);
    pending.push_back(PvkRange{ range_start, range_count });
    static const std::vector<int> kNoMissingPositions;

    if (!priv_recovery_ensure_task_constant_buffers(ctx, task, kNoMissingPositions, err)) {
        return false;
    }
    if (!priv_recovery_upload_base_key(ctx, active_base_key, err)) {
        return false;
    }

    while (!pending.empty()) {
        PvkRange current = pending.back();
        pending.pop_back();
        if (current.count == 0ull) {
            continue;
        }

        if (current.count > launch_capacity) {
            pending.push_back(PvkRange{ current.start + launch_capacity, current.count - launch_capacity });
            current.count = launch_capacity;
        }

        clear_result_flag_host(ctx.buffIsResult);

        const uint64_t thread_count = (current.count + static_cast<uint64_t>(keys_per_thread) - 1ull) / static_cast<uint64_t>(keys_per_thread);
        const unsigned int launch_blocks = static_cast<unsigned int>(
            std::max<uint64_t>(1ull, (thread_count + static_cast<uint64_t>(launch_threads) - 1ull) / static_cast<uint64_t>(launch_threads)));

        metal_launch("workerPvkRecoverySeqEdOnly", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
            ctx.buffIsResult,
            ctx.buffDeviceResult,
            ctx.devPvkTemplate,
            static_cast<uint32_t>(task.normalized_template.size()),
            ctx.devPvkBaseKey,
            fast_plan.step_value,
            current.start,
            current.count,
            keys_per_thread,
            static_cast<uint8_t>(ed_launch_kind));

        metalError_t st = metalGetLastError();
        if (st != metalSuccess) {
            err = std::string("PVK recovery ED seq kernel launch failed: ") + metalGetErrorString(st);
            return false;
        }

        st = metalDeviceSynchronize();
        if (st != metalSuccess) {
            err = std::string("PVK recovery ED seq kernel sync failed: ") + metalGetErrorString(st);
            return false;
        }

        if (progress_enabled) {
            recovery_u64_add_saturating(tested, current.count);
            counterTotal += current.count;
        }

        if (read_result_flag_host(ctx.buffIsResult)) {
            clear_result_flag_host(ctx.buffIsResult);
            priv_recovery_save_found_results();
        }
    }

    return true;
}

static bool priv_recovery_run_seq_space(RecoveryGpuDirectContext& ctx,
                                       const PrivRecoveryPreparedTask& task,
                                       const std::array<uint8_t, 32>& active_base_key,
                                       const PrivRecoveryFastPathPlan& fast_plan,
                                       const PrivRecoverySecpSeqLaunchKind secp_launch_kind,
                                       const uint64_t range_start,
                                       const uint64_t range_count,
                                       const bool progress_enabled,
                                       uint64_t& tested,
                                       std::string& err) {
    err.clear();
    if (range_count == 0ull) {
        return true;
    }

    const unsigned int launch_threads = (BLOCK_THREADS == 0u) ? 256u : BLOCK_THREADS;
    const uint64_t keys_per_thread = (fast_plan.step_value == 1ull) ? 1024ull : 64ull;
    const uint64_t launch_capacity = priv_recovery_slot_capacity_for_keys(ctx, keys_per_thread);

    struct PvkRange {
        uint64_t start = 0ull;
        uint64_t count = 0ull;
    };

    std::vector<PvkRange> pending;
    pending.reserve(64u);
    pending.push_back(PvkRange{ range_start, range_count });
    static const std::vector<int> kNoMissingPositions;

    if (!priv_recovery_ensure_task_constant_buffers(ctx, task, kNoMissingPositions, err)) {
        return false;
    }
    if (!priv_recovery_upload_base_key(ctx, active_base_key, err)) {
        return false;
    }

    metal_launch("compute_P0_H_kernel", MetalGridSize(1), MetalGridSize(1), ctx.devPvkBaseKey, fast_plan.step_value, _dev_precomp, pitch, 1);
    metalError_t st = metalGetLastError();
    if (st != metalSuccess) {
        err = std::string("PVK seq compute_P0_H launch failed: ") + metalGetErrorString(st);
        return false;
    }

    while (!pending.empty()) {
        PvkRange current = pending.back();
        pending.pop_back();
        if (current.count == 0ull) {
            continue;
        }

        if (current.count > launch_capacity) {
            pending.push_back(PvkRange{ current.start + launch_capacity, current.count - launch_capacity });
            current.count = launch_capacity;
        }

        clear_result_flag_host(ctx.buffIsResult);

        const uint64_t thread_count = (current.count + keys_per_thread - 1ull) / keys_per_thread;
        const unsigned int launch_blocks = static_cast<unsigned int>(
            std::max<uint64_t>(1ull, (thread_count + static_cast<uint64_t>(launch_threads) - 1ull) / static_cast<uint64_t>(launch_threads)));

        switch (secp_launch_kind) {
        case PrivRecoverySecpSeqLaunchKind::VanityC:
            metal_launch("workerPvkRecoverySeqCompressed", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityU:
            metal_launch("workerPvkRecoverySeqVanityU", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityS:
            metal_launch("workerPvkRecoverySeqVanityS", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityR:
            metal_launch("workerPvkRecoverySeqVanityR", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityE:
            metal_launch("workerPvkRecoverySeqVanityE", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityX:
            metal_launch("workerPvkRecoverySeqVanityX", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityP2wsh:
            metal_launch("workerPvkRecoverySeqVanityP2wsh", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityCu:
            metal_launch("workerPvkRecoverySeqVanityCu", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityCus:
            metal_launch("workerPvkRecoverySeqVanityCus", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityCusr:
            metal_launch("workerPvkRecoverySeqVanityCusr", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityCuse:
            metal_launch("workerPvkRecoverySeqVanityCuse", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityCusex:
            metal_launch("workerPvkRecoverySeqVanityCusex", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityCusrx:
            metal_launch("workerPvkRecoverySeqVanityCusrx", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::VanityCusrxe:
            metal_launch("workerPvkRecoverySeqVanityCusrxe", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        case PrivRecoverySecpSeqLaunchKind::GenericSeq:
        default:
            metal_launch("workerPvkRecoverySeqSecp", MetalGridSize(launch_blocks), MetalGridSize(launch_threads),
                ctx.buffIsResult,
                ctx.buffDeviceResult,
                _dev_precomp,
                pitch,
                ctx.devPvkTemplate,
                static_cast<uint32_t>(task.normalized_template.size()),
                ctx.devPvkBaseKey,
                fast_plan.step_value,
                current.start,
                current.count);
            break;
        }

        st = metalGetLastError();
        if (st != metalSuccess) {
            err = std::string("PVK seq kernel launch failed: ") + metalGetErrorString(st);
            return false;
        }

        st = metalDeviceSynchronize();
        if (st != metalSuccess) {
            err = std::string("PVK seq kernel sync failed: ") + metalGetErrorString(st);
            return false;
        }

        if (progress_enabled) {
            recovery_u64_add_saturating(tested, current.count);
            counterTotal += current.count;
        }

        if (read_result_flag_host(ctx.buffIsResult)) {
            clear_result_flag_host(ctx.buffIsResult);
            priv_recovery_save_found_results();
        }
    }

    return true;
}

static bool priv_recovery_run_task_direct(RecoveryGpuDirectContext& ctx,
                                  const PrivRecoveryPreparedTask& task,
                                  uint64_t& tested,
                                  uint64_t& emitted,
                                  std::string& err) {
    tested = 0ull;
    emitted = 0ull;
    err.clear();

    if (task.missing_nibbles.empty()) {
        if (recovery_partition_is_log_owner()) {
            printf("[!] PRIV recovery task: %s | missing=0 | engine=generic [!]\n",
                priv_recovery_format_ref(task.source, task.line_no).c_str());
        }

        const uint64_t total_candidates = 1ull;
        uint64_t partition_start = 0ull;
        uint64_t partition_count = total_candidates;
        recovery_partition_take_span(total_candidates, partition_start, partition_count);
        if (partition_count == 0ull) {
            return true;
        }

        const std::vector<int> no_missing_positions;
        return priv_recovery_run_generic_low_space(task, task.base_private_key, no_missing_positions, partition_start, partition_count, tested, err);
    }

    const PrivRecoveryFastPathPlan fast_plan = priv_recovery_classify_fast_path(task);
    const bool direct_runtime_allowed = priv_recovery_direct_runtime_allowed();
    const bool candidate_fast_plan = direct_runtime_allowed && !FULL && fast_plan.kind != PrivRecoveryFastKind::Generic;
    const bool use_secp_fast = candidate_fast_plan && priv_recovery_has_supported_secp_targets();
    const PrivRecoverySecpSeqLaunchKind secp_launch_kind = use_secp_fast
        ? priv_recovery_select_secp_launch_kind(fast_plan)
        : PrivRecoverySecpSeqLaunchKind::GenericSeq;
    const PvkEdLaunchKind ed_launch_kind = (candidate_fast_plan && priv_recovery_has_supported_ed_targets())
        ? priv_recovery_select_ed_launch_kind()
        : PvkEdLaunchKind::Generic;
    const bool secp_uses_vanity = use_secp_fast && secp_launch_kind != PrivRecoverySecpSeqLaunchKind::GenericSeq;
    const bool use_ed_fast = candidate_fast_plan && priv_recovery_has_supported_ed_targets() && priv_recovery_ed_launch_specialized(ed_launch_kind);
    const bool mixed_split_fast = use_secp_fast && use_ed_fast;
    const bool use_fast_path = use_secp_fast || use_ed_fast;
    const char* engine_label = "generic";
    if (use_fast_path) {
        if (mixed_split_fast) {
            engine_label = secp_uses_vanity ? "mixed-split-vanity" : "mixed-split-seq";
        }
        else if (use_secp_fast) {
            engine_label = priv_recovery_secp_launch_label(fast_plan, secp_launch_kind);
        }
        else if (use_ed_fast) {
            engine_label = priv_recovery_ed_launch_label(fast_plan, ed_launch_kind);
        }
    }
    if (recovery_partition_is_log_owner()) {
        printf("[!] PRIV recovery task: %s | missing=%llu | engine=%s [!]\n",
            priv_recovery_format_ref(task.source, task.line_no).c_str(),
            static_cast<unsigned long long>(task.missing_nibbles.size()),
            engine_label);
    }

    if (direct_runtime_allowed && !priv_recovery_ensure_direct_context(ctx, err)) {
        return false;
    }

    std::vector<int> generic_outer_missing_positions;
    std::vector<int> generic_inner_missing_positions;
    if (!use_fast_path) {
        const int missing_count = static_cast<int>(task.missing_nibbles.size());
        const int generic_inner_count = priv_recovery_low_missing_count(missing_count);
        const int generic_outer_count = missing_count - generic_inner_count;
        generic_outer_missing_positions.reserve(static_cast<size_t>(generic_outer_count));
        generic_inner_missing_positions.reserve(static_cast<size_t>(generic_inner_count));
        for (int i = 0; i < missing_count; ++i) {
            if (i < generic_outer_count) {
                generic_outer_missing_positions.emplace_back(task.missing_nibbles[static_cast<size_t>(i)]);
            }
            else {
                generic_inner_missing_positions.emplace_back(task.missing_nibbles[static_cast<size_t>(i)]);
            }
        }
    }

    const std::vector<int>& outer_missing_positions = use_fast_path ? fast_plan.outer_missing_positions : generic_outer_missing_positions;
    const std::vector<int>& inner_missing_positions = use_fast_path ? fast_plan.fast_missing_positions : generic_inner_missing_positions;
    const int outer_missing_count = static_cast<int>(outer_missing_positions.size());
    const int inner_missing_count = use_fast_path
        ? static_cast<int>(fast_plan.fast_missing_positions.size())
        : priv_recovery_low_missing_count(static_cast<int>(task.missing_nibbles.size()));

    uint64_t inner_candidates = 0ull;
    if (use_fast_path) {
        inner_candidates = fast_plan.inner_candidate_count;
    }
    else if (!priv_recovery_pow16_u64(inner_missing_count, inner_candidates)) {
        err = "invalid wildcard split for PVK recovery";
        return false;
    }

    uint64_t partition_inner_start = 0ull;
    uint64_t partition_inner_count = inner_candidates;
    if (outer_missing_count == 0) {
        recovery_partition_take_span(inner_candidates, partition_inner_start, partition_inner_count);
    }

    std::array<uint8_t, 32> active_base_key = task.base_private_key;
    std::vector<uint8_t> outer_digits(static_cast<size_t>(outer_missing_count), 0u);

    auto run_generic = [&](const uint64_t start, const uint64_t count) -> bool {
        if (!direct_runtime_allowed) {
            return priv_recovery_run_generic_low_space(task, active_base_key, inner_missing_positions, start, count, tested, err);
        }
        if (priv_recovery_has_supported_ed_targets() && !priv_recovery_has_supported_secp_targets()) {
            return priv_recovery_run_low_space_ed_only(ctx, task, active_base_key, inner_missing_positions, start, count, tested, err);
        }
        return priv_recovery_run_low_space(ctx, task, active_base_key, inner_missing_positions, start, count, tested, err);
    };

    auto run_selected = [&](const uint64_t start, const uint64_t count) -> bool {
        if (!use_fast_path) {
            return run_generic(start, count);
        }
        const bool secp_safe = !use_secp_fast || priv_recovery_seq_range_is_safe(active_base_key, fast_plan.step_value, inner_candidates);
        const bool ed_safe = !use_ed_fast || priv_recovery_linear_range_is_safe(active_base_key, fast_plan.step_value, inner_candidates);
        if (!secp_safe || !ed_safe) {
            return run_generic(start, count);
        }

        if (use_secp_fast && use_ed_fast) {
            const unsigned int launch_threads = (BLOCK_THREADS == 0u) ? 256u : BLOCK_THREADS;
            const unsigned int configured_blocks = (BLOCK_NUMBER == 0u) ? 1024u : BLOCK_NUMBER;
            const uint64_t secp_keys_per_thread = (fast_plan.step_value == 1ull) ? 1024ull : 64ull;
            const uint64_t ed_keys_per_thread = static_cast<uint64_t>(priv_recovery_ed_keys_per_thread(fast_plan.step_value, ed_launch_kind));
            const uint64_t secp_capacity = std::max<uint64_t>(1ull,
                static_cast<uint64_t>(configured_blocks) * static_cast<uint64_t>(launch_threads) * secp_keys_per_thread);
            const uint64_t ed_capacity = std::max<uint64_t>(1ull,
                static_cast<uint64_t>(configured_blocks) * static_cast<uint64_t>(launch_threads) * ed_keys_per_thread);
            const uint64_t mixed_capacity = std::max(secp_capacity, ed_capacity);

            uint64_t done = 0ull;
            while (done < count) {
                const uint64_t current = std::min<uint64_t>(mixed_capacity, count - done);
                if (!priv_recovery_run_seq_space(ctx, task, active_base_key, fast_plan, secp_launch_kind, start + done, current, false, tested, err)) {
                    return false;
                }
                if (!priv_recovery_run_seq_space_ed_only(ctx, task, active_base_key, fast_plan, start + done, current, false, tested, err)) {
                    return false;
                }
                recovery_u64_add_saturating(tested, current);
                counterTotal += current;
                done += current;
            }
            return true;
        }

        if (use_secp_fast) {
            if (!priv_recovery_run_seq_space(ctx, task, active_base_key, fast_plan, secp_launch_kind, start, count, true, tested, err)) {
                return false;
            }
        }
        if (use_ed_fast) {
            if (!priv_recovery_run_seq_space_ed_only(ctx, task, active_base_key, fast_plan, start, count, true, tested, err)) {
                return false;
            }
        }
        return true;
    };

    if (outer_missing_count == 0) {
        if (!run_selected(partition_inner_start, partition_inner_count)) {
            return false;
        }
    }
    else {
        uint64_t outer_combo_index = 0ull;
        for (;;) {
            active_base_key = task.base_private_key;
            for (int i = 0; i < outer_missing_count; ++i) {
                priv_recovery_apply_nibble_host(active_base_key, outer_missing_positions[static_cast<size_t>(i)], outer_digits[static_cast<size_t>(i)]);
            }

            if (!recovery_partition_skip_high_combo(outer_combo_index)) {
                if (!run_selected(0ull, inner_candidates)) {
                    return false;
                }
            }
            ++outer_combo_index;

            int carry_idx = 0;
            for (; carry_idx < outer_missing_count; ++carry_idx) {
                const uint8_t next = static_cast<uint8_t>(outer_digits[static_cast<size_t>(carry_idx)] + 1u);
                if (next < 16u) {
                    outer_digits[static_cast<size_t>(carry_idx)] = next;
                    break;
                }
                outer_digits[static_cast<size_t>(carry_idx)] = 0u;
            }

            if (carry_idx == outer_missing_count) {
                break;
            }
        }
    }

    emitted = tested;
    return true;
}


static bool priv_recovery_run_prepared_task(const PrivRecoveryPreparedTask& task,
                                            uint64_t& tested,
                                            std::string& err) {
    uint64_t emitted = 0ull;
    return priv_recovery_run_task_direct(g_priv_recovery_ctx, task, tested, emitted, err);
}


static bool priv_recovery_validate_cli(std::string& err) {
    err.clear();
    if (!IS_PRIV || !IS_PRIV_RECOVERY) {
        return true;
    }
    if (Ton && Ton_all) {
        err = "-priv -recovery does not allow -c tT. Use either 't' or 'T' because 'T' already includes 't'.";
        return false;
    }
    if (seqMode || !start_point.empty() || end_point_set || !end_point.empty() || backward || both || isRandom || use_n_count) {
        err = "-priv -recovery cannot be combined with -start/-end/-step/-back/-both/-random/-n.";
        return false;
    }
    if (step != 1ull || seq_priv_use_step_schedule || seq_priv_has_end_step || seq_priv_has_add_plus_step) {
        err = "-priv -recovery always scans contiguous candidate ranges; -step and step schedules are not allowed.";
        return false;
    }
    if (prng_gen || prng64_gen) {
        err = "-priv -recovery cannot be combined with -prng/-prng64.";
        return false;
    }
    if (IS_PRIV_SWAP || IS_PRIV_BYTE || IS_PRIV_HASH || IS_PRIV_PLUS || IS_PRIV_PLUS_256 || IS_PRIV_PATTERN) {
        err = "-priv -recovery cannot be combined with numeric -priv submodes 0..6.";
        return false;
    }
    if (priv_pattern_arg_seen || priv_pattern_last_cycle || !PvkBytes.empty()) {
        err = "-priv -recovery cannot be combined with -pb/-last or byte-pattern options.";
        return false;
    }
    if (use_custom_size || !Sizes.empty() || dub_mnem) {
        err = "-priv -recovery cannot be combined with generator/custom-size recovery options.";
        return false;
    }
    return true;
}

static metalError_t priv_recovery_process_stream_impl(std::istream& stream, const std::string& source_label) {
    if (recovery_partition_is_log_owner()) {
        if (IS_HEX) {
            fprintf(stderr, "[!] Warning: -hex is implicit in -priv -recovery and will be treated as a no-op [!]\n");
        }
        else {
            fprintf(stderr, "[!] Info: -priv -recovery forces HEX semantics for recovered private keys [!]\n");
        }
    }
    IS_HEX = true;
    metal_launch("setHEX", MetalGridSize(1), MetalGridSize(1));
    metalError_t hex_status = metalDeviceSynchronize();
    if (hex_status != metalSuccess) {
        fprintf(stderr, "[!] Error: failed to enable HEX input semantics for priv recovery: %s [!]\n",
            metalGetErrorString(hex_status));
        return hex_status;
    }

    uint64_t tested_total = 0ull;
    uint64_t emitted_total = 0ull;
    uint64_t processed_total = 0ull;
    uint64_t skipped_total = 0ull;
    uint64_t line_no = 0ull;
    std::string raw_line;

    while (std::getline(stream, raw_line)) {
        ++line_no;
        const std::string trimmed = priv_recovery_trim_copy(raw_line);
        if (trimmed.empty()) {
            continue;
        }

        PrivRecoveryPreparedTask task;
        std::string prep_err;
        if (!priv_recovery_prepare_task(trimmed, source_label, line_no, task, prep_err)) {
            fprintf(stderr, "[!] PRIV recovery skip: %s -> %s [!]\n",
                priv_recovery_format_ref(source_label, line_no).c_str(), prep_err.c_str());
            ++skipped_total;
            continue;
        }

        auto run_one_task = [&](uint64_t& task_tested_total) -> metalError_t {
            uint64_t local_tested = 0ull;
            std::string task_err;
            if (!priv_recovery_run_prepared_task(task, local_tested, task_err)) {
                fprintf(stderr, "[!] PRIV recovery error: %s -> %s [!]\n",
                    priv_recovery_format_ref(task.source, task.line_no).c_str(),
                    task_err.empty() ? "execution failed" : task_err.c_str());
                return metalErrorInvalidValue;
            }
            task_tested_total = local_tested;
            g_recovery_run_stats.tested_total = local_tested;
            g_recovery_run_stats.emitted_total = local_tested;
            return metalSuccess;
        };

        metalError_t st = metalSuccess;
        uint64_t task_tested_total = 0ull;
        if (is_multi_gpu_active() && !g_disable_multi_gpu_dispatch) {
            std::atomic<uint64_t> tested_sum{ 0ull };
            st = dispatch_recovery_mode_multi_gpu("processMetalPRIVRecovery", [&]() -> metalError_t {
                uint64_t local_tested = 0ull;
                metalError_t local_st = run_one_task(local_tested);
                tested_sum.fetch_add(local_tested, std::memory_order_relaxed);
                return local_st;
            });
            task_tested_total = tested_sum.load(std::memory_order_relaxed);
        }
        else {
            st = run_one_task(task_tested_total);
        }
        if (st != metalSuccess) {
            return st;
        }

        ++processed_total;
        tested_total += task_tested_total;
        emitted_total += task_tested_total;

        if (recovery_partition_is_log_owner()) {
            printf("[!] PRIV recovery done: %s | tested=%llu [!]\n",
                priv_recovery_format_ref(source_label, line_no).c_str(),
                static_cast<unsigned long long>(task_tested_total));
        }
    }

    g_recovery_run_stats.tested_total = tested_total;
    g_recovery_run_stats.emitted_total = emitted_total;
    if (recovery_partition_is_log_owner()) {
        printf("[!] PRIV recovery summary: source=%s processed=%llu skipped=%llu tested=%llu [!]\n",
            source_label.c_str(),
            static_cast<unsigned long long>(processed_total),
            static_cast<unsigned long long>(skipped_total),
            static_cast<unsigned long long>(tested_total));
    }
    return metalSuccess;
}

metalError_t processMetalPRIVRecovery(std::istream& stream) {
    return priv_recovery_process_stream_impl(stream, PHRASE_IN ? std::string("stdin") : std::string("stream"));
}

metalError_t processMetalPRIVRecoveryFile(const vector<string>& mnemonicFiles) {
    for (size_t i = 0u; i < mnemonicFiles.size(); ++i) {
        std::ifstream fin(mnemonicFiles[i], std::ios::binary);
        if (!fin.is_open()) {
            fprintf(stderr, "[!] Error: unable to open recovery input file %s [!]\n", mnemonicFiles[i].c_str());
            return metalErrorInvalidValue;
        }
        tune_ifstream_buffer(fin);
        print_opened_input_file(mnemonicFiles[i]);
        const metalError_t st = priv_recovery_process_stream_impl(fin, mnemonicFiles[i]);
        if (st != metalSuccess) {
            return st;
        }
    }
    return metalSuccess;
}
