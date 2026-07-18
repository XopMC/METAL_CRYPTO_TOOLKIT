#include "PoetryHost.h"

static std::vector<PoetryPreparedTemplate> g_poetry_templates;
static PoetryDictionaryHost g_poetry_dictionary;

struct PoetryDispatchHost {
    uint64_t stride_or_random_limit;
    uint32_t thread_count_per_template;
    uint32_t reserved;
};

static_assert(sizeof(PoetryDispatchHost) == 16u, "Poetry dispatch ABI mismatch");

static bool poetry_templates_equal_for_batch(const PoetryPreparedTemplate& left,
                                             const PoetryPreparedTemplate& right) {
    return left.device.random_mode == 0u && right.device.random_mode == 0u &&
        left.normalized_phrase == right.normalized_phrase &&
        std::memcmp(&left.device, &right.device, sizeof(PoetryTemplateDevice)) == 0;
}

static uint64_t poetry_finite_useful_thread_count(uint8_t wildcard_count) {
    uint64_t combinations = 1u;
    for (uint8_t index = 0u; index < wildcard_count; ++index) {
        if (combinations > std::numeric_limits<uint64_t>::max() /
                               static_cast<uint64_t>(POETRY_WORD_COUNT)) {
            return std::numeric_limits<uint64_t>::max();
        }
        combinations *= static_cast<uint64_t>(POETRY_WORD_COUNT);
    }
    return combinations / static_cast<uint64_t>(THREAD_STEPS) +
        (combinations % static_cast<uint64_t>(THREAD_STEPS) != 0u ? 1u : 0u);
}

static uint32_t poetry_launch_block_count(const GpuRuntimeContext& context,
                                          const PoetryPreparedTemplate& prepared,
                                          size_t gpu_count) {
    if (prepared.device.random_mode != 0u || context.block_threads == 0u || gpu_count == 0u) {
        return context.block_number;
    }
    const uint64_t useful_threads =
        poetry_finite_useful_thread_count(prepared.device.wildcard_count);
    const uint64_t threads_for_gpu = useful_threads / static_cast<uint64_t>(gpu_count) +
        (useful_threads % static_cast<uint64_t>(gpu_count) != 0u ? 1u : 0u);
    const uint64_t required_blocks = threads_for_gpu /
            static_cast<uint64_t>(context.block_threads) +
        (threads_for_gpu % static_cast<uint64_t>(context.block_threads) != 0u ? 1u : 0u);
    return static_cast<uint32_t>(std::max<uint64_t>(
        1u, std::min<uint64_t>(context.block_number, required_blocks)));
}

static metalError_t processMetalPoetryGpuSlot(const GpuRuntimeContext& context,
                                              uint32_t launch_block_number,
                                              uint64_t global_thread_prefix,
                                              uint64_t global_stride,
                                              const PoetryPreparedTemplate* prepared_templates,
                                              size_t batch_template_count,
                                              const PoetryDictionaryHost& dictionary,
                                              bool random_quota_enabled,
                                              uint64_t random_candidate_quota) {
    if (prepared_templates == nullptr || batch_template_count == 0u) {
        return metalErrorInvalidValue;
    }
    const PoetryPreparedTemplate& prepared = prepared_templates[0];
    const uint64_t thread_count64 = static_cast<uint64_t>(launch_block_number) *
        static_cast<uint64_t>(context.block_threads);
    if (thread_count64 == 0u || thread_count64 > std::numeric_limits<uint32_t>::max()) {
        return metalErrorInvalidConfiguration;
    }
    if (batch_template_count > std::numeric_limits<uint64_t>::max() / thread_count64 ||
        batch_template_count > std::numeric_limits<uint32_t>::max() /
                                   static_cast<uint64_t>(launch_block_number)) {
        return metalErrorInvalidConfiguration;
    }
    const uint64_t batch_thread_count64 =
        thread_count64 * static_cast<uint64_t>(batch_template_count);
    if (batch_thread_count64 > std::numeric_limits<uint32_t>::max()) {
        return metalErrorInvalidConfiguration;
    }
    const uint32_t batch_launch_block_number = static_cast<uint32_t>(
        static_cast<uint64_t>(launch_block_number) *
        static_cast<uint64_t>(batch_template_count));
    const uint32_t thread_count = static_cast<uint32_t>(thread_count64);
    const uint64_t candidates_per_launch =
        batch_thread_count64 * static_cast<uint64_t>(THREAD_STEPS);
    const bool bounded_random = prepared.device.random_mode != 0u && random_quota_enabled;
    if (bounded_random && random_candidate_quota == 0u) {
        return metalSuccess;
    }

    bool* buffIsResult = nullptr;
    bool* buffDeviceResult = nullptr;
    PoetryTemplateDevice* device_template = nullptr;
    PoetryThreadState* device_states = nullptr;
    char* device_dictionary_blob = nullptr;
    uint16_t* device_dictionary_offsets = nullptr;
    uint8_t* device_dictionary_lengths = nullptr;
    uint64_t* device_processed = nullptr;
    uint32_t* device_active = nullptr;

    auto cleanup = [&]() {
        if (device_template != nullptr) metalFree(device_template);
        if (device_states != nullptr) metalFree(device_states);
        if (device_dictionary_blob != nullptr) metalFree(device_dictionary_blob);
        if (device_dictionary_offsets != nullptr) metalFree(device_dictionary_offsets);
        if (device_dictionary_lengths != nullptr) metalFree(device_dictionary_lengths);
        if (device_processed != nullptr) metalFree(device_processed);
        if (device_active != nullptr) metalFree(device_active);
    };
    auto checked = [&](metalError_t status, const char* operation) -> bool {
        if (status == metalSuccess) return true;
        fprintf(stderr, "[!] Poetry GPU %d: %s failed: %s [!]\n",
                context.device_id, operation, metalGetErrorString(status));
        return false;
    };

    metalError_t status = acquire_shared_result_buffers(
        batch_thread_count64 * static_cast<uint64_t>(THREAD_STEPS),
        &buffIsResult,
        &buffDeviceResult);
    if (!checked(status, "acquire_shared_result_buffers")) return status;

    status = metalMalloc(&device_template,
                         batch_template_count * sizeof(PoetryTemplateDevice));
    if (!checked(status, "allocate template")) { cleanup(); return status; }
    status = metalMalloc(&device_states,
                         batch_thread_count64 * sizeof(PoetryThreadState));
    if (!checked(status, "allocate states")) { cleanup(); return status; }
    status = metalMalloc(&device_dictionary_blob, dictionary.blob.size());
    if (!checked(status, "allocate dictionary")) { cleanup(); return status; }
    status = metalMalloc(&device_dictionary_offsets, dictionary.offsets.size() * sizeof(uint16_t));
    if (!checked(status, "allocate dictionary offsets")) { cleanup(); return status; }
    status = metalMalloc(&device_dictionary_lengths, dictionary.lengths.size() * sizeof(uint8_t));
    if (!checked(status, "allocate dictionary lengths")) { cleanup(); return status; }
    status = metalMalloc(&device_processed, sizeof(uint64_t));
    if (!checked(status, "allocate processed counter")) { cleanup(); return status; }
    status = metalMalloc(&device_active, sizeof(uint32_t));
    if (!checked(status, "allocate active counter")) { cleanup(); return status; }

    std::vector<PoetryTemplateDevice> host_templates(batch_template_count);
    for (size_t index = 0u; index < batch_template_count; ++index) {
        host_templates[index] = prepared_templates[index].device;
    }
    status = metalMemcpy(device_template, host_templates.data(),
                         host_templates.size() * sizeof(PoetryTemplateDevice),
                         metalMemcpyHostToDevice);
    if (!checked(status, "copy template")) { cleanup(); return status; }
    status = metalMemcpy(device_dictionary_blob, dictionary.blob.data(), dictionary.blob.size(), metalMemcpyHostToDevice);
    if (!checked(status, "copy dictionary")) { cleanup(); return status; }
    status = metalMemcpy(device_dictionary_offsets, dictionary.offsets.data(),
                         dictionary.offsets.size() * sizeof(uint16_t), metalMemcpyHostToDevice);
    if (!checked(status, "copy dictionary offsets")) { cleanup(); return status; }
    status = metalMemcpy(device_dictionary_lengths, dictionary.lengths.data(),
                         dictionary.lengths.size() * sizeof(uint8_t), metalMemcpyHostToDevice);
    if (!checked(status, "copy dictionary lengths")) { cleanup(); return status; }

    const uint64_t seed_nonce = static_cast<uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count()) ^
        (global_thread_prefix * 0x9e3779b97f4a7c15ull) ^
        static_cast<uint64_t>(context.device_id + 1);
    const uint32_t gpu_id = static_cast<uint32_t>(context.device_id);
    status = metal_launch("initPoetryThreadStates", batch_launch_block_number, context.block_threads,
                          device_states, thread_count, device_template, global_thread_prefix,
                          gpu_id, seed_nonce);
    if (!checked(status, "initPoetryThreadStates launch")) { cleanup(); return status; }
    status = metalDeviceSynchronize();
    if (!checked(status, "initPoetryThreadStates sync")) { cleanup(); return status; }

    const uint64_t round_multiplier = Rounds * 2ull + 1ull;
    uint64_t random_processed = 0u;
    while (isRun) {
        @autoreleasepool {
            if (bounded_random && random_processed >= random_candidate_quota) break;
            uint64_t random_candidate_limit = candidates_per_launch;
            if (bounded_random) {
                random_candidate_limit = std::min(
                    candidates_per_launch,
                    random_candidate_quota - random_processed);
            }
            const PoetryDispatchHost dispatch{
                prepared.device.random_mode != 0u ? random_candidate_limit : global_stride,
                thread_count,
                0u,
            };
            status = metalMemset(device_processed, 0, sizeof(uint64_t));
            if (!checked(status, "clear processed counter")) break;
            status = metalMemset(device_active, 0, sizeof(uint32_t));
            if (!checked(status, "clear active counter")) break;

            status = metal_launch("workerPoetry", batch_launch_block_number, context.block_threads,
                                  buffIsResult, buffDeviceResult, device_template, device_states,
                                  dispatch, device_dictionary_blob, device_dictionary_offsets,
                                  device_dictionary_lengths, device_processed, device_active,
                                  context.dev_precomp, context.pitch, Rounds);
            if (!checked(status, "workerPoetry launch")) break;
            status = metalDeviceSynchronize();
            if (!checked(status, "workerPoetry sync")) break;

            uint64_t processed = 0u;
            uint32_t active = 0u;
            status = metalMemcpy(&processed, device_processed, sizeof(processed), metalMemcpyDeviceToHost);
            if (!checked(status, "copy processed counter")) break;
            status = metalMemcpy(&active, device_active, sizeof(active), metalMemcpyDeviceToHost);
            if (!checked(status, "copy active counter")) break;
            if (bounded_random) {
                if (processed > random_candidate_limit) {
                    status = metalErrorUnknown;
                    fprintf(stderr, "[!] Poetry GPU %d: random batch exceeded its candidate limit [!]\n",
                            context.device_id);
                    break;
                }
                random_processed += static_cast<uint64_t>(processed);
                if (processed == 0u && random_processed < random_candidate_quota) {
                    status = metalErrorUnknown;
                    fprintf(stderr, "[!] Poetry GPU %d: random batch made no progress [!]\n",
                            context.device_id);
                    break;
                }
            }
            counterTotal += static_cast<uint64_t>(processed) * round_multiplier;

            if (read_result_flag_host(buffIsResult)) {
                clear_result_flag_host(buffIsResult);
                SaveResultPoetry(OUT_FILE, Founds, save, Derivations_list);
            }
            if (prepared.device.random_mode == 0u && active == 0u) break;
            if (bounded_random && random_processed >= random_candidate_quota) break;
        }
    }

    if (status == metalSuccess && read_result_flag_host(buffIsResult)) {
        clear_result_flag_host(buffIsResult);
        SaveResultPoetry(OUT_FILE, Founds, save, Derivations_list);
    }
    cleanup();
    return status;
}

static metalError_t processMetalPoetry() {
    if (g_gpu_contexts.empty()) return metalErrorInvalidDevice;

    std::vector<uint64_t> random_capacities(g_gpu_contexts.size(), 0u);
    uint64_t global_stride = 0u;
    for (size_t i = 0; i < g_gpu_contexts.size(); ++i) {
        const uint64_t count = static_cast<uint64_t>(g_gpu_contexts[i].block_number) *
            static_cast<uint64_t>(g_gpu_contexts[i].block_threads);
        if (count == 0u || global_stride > std::numeric_limits<uint64_t>::max() - count) {
            return metalErrorInvalidConfiguration;
        }
        if (count > std::numeric_limits<uint64_t>::max() / static_cast<uint64_t>(THREAD_STEPS)) {
            return metalErrorInvalidConfiguration;
        }
        random_capacities[i] = count * static_cast<uint64_t>(THREAD_STEPS);
        global_stride += count;
    }
    if (global_stride > std::numeric_limits<uint64_t>::max() / static_cast<uint64_t>(THREAD_STEPS)) {
        return metalErrorInvalidConfiguration;
    }
    const uint64_t global_random_capacity = global_stride * static_cast<uint64_t>(THREAD_STEPS);
    const bool cycling_random = isRandom && use_n_count;
    uint64_t cycle = 1u;

    do {
        for (size_t template_index = 0;
             template_index < g_poetry_templates.size() && isRun;
             ++template_index) {
            const PoetryPreparedTemplate &prepared =
                g_poetry_templates[template_index];
            STATUS = prepared.normalized_phrase;
            const bool random_mode = prepared.device.random_mode != 0u;
            std::vector<uint32_t> template_launch_blocks(g_gpu_contexts.size(), 0u);
            std::vector<uint64_t> template_prefixes(g_gpu_contexts.size(), 0u);
            uint64_t template_stride = 0u;
            for (size_t gpu_index = 0; gpu_index < g_gpu_contexts.size(); ++gpu_index) {
                const GpuRuntimeContext& context = g_gpu_contexts[gpu_index];
                template_launch_blocks[gpu_index] = poetry_launch_block_count(
                    context, prepared, g_gpu_contexts.size());
                template_prefixes[gpu_index] = template_stride;
                const uint64_t launched_threads =
                    static_cast<uint64_t>(template_launch_blocks[gpu_index]) *
                    static_cast<uint64_t>(context.block_threads);
                if (template_stride > std::numeric_limits<uint64_t>::max() - launched_threads) {
                    return metalErrorInvalidConfiguration;
                }
                template_stride += launched_threads;
            }
            if (template_stride == 0u) return metalErrorInvalidConfiguration;
            size_t batch_template_count = 1u;
            if (!random_mode && host_silent_mode) {
                size_t batch_limit = g_poetry_templates.size() - template_index;
                for (size_t gpu_index = 0u; gpu_index < g_gpu_contexts.size(); ++gpu_index) {
                    const uint32_t launch_blocks = template_launch_blocks[gpu_index];
                    if (launch_blocks == 0u) return metalErrorInvalidConfiguration;
                    batch_limit = std::min(
                        batch_limit,
                        static_cast<size_t>(g_gpu_contexts[gpu_index].block_number /
                                            launch_blocks));
                }
                while (batch_template_count < batch_limit &&
                       poetry_templates_equal_for_batch(
                           prepared,
                           g_poetry_templates[template_index + batch_template_count])) {
                    ++batch_template_count;
                }
            }
            if (random_mode) {
                if (cycling_random) {
                    printf(
                        "[!] Poetry task %llu/%llu: words=%u missing=%u random "
                        "combinations=%llu cycle=%llu [!]\n",
                        static_cast<unsigned long long>(template_index + 1u),
                        static_cast<unsigned long long>(
                            g_poetry_templates.size()),
                        static_cast<unsigned int>(prepared.device.word_count),
                        static_cast<unsigned int>(
                            prepared.device.wildcard_count),
                        static_cast<unsigned long long>(n_number),
                        static_cast<unsigned long long>(cycle));
                } else {
                    printf(
                        "[!] Poetry task %llu/%llu: words=%u missing=%u random "
                        "[!]\n",
                        static_cast<unsigned long long>(template_index + 1u),
                        static_cast<unsigned long long>(
                            g_poetry_templates.size()),
                        static_cast<unsigned int>(prepared.device.word_count),
                        static_cast<unsigned int>(
                            prepared.device.wildcard_count));
                }
            } else {
                printf(
                    "[!] Poetry task %llu/%llu: words=%u missing=%u "
                    "combinations=%s [!]\n",
                    static_cast<unsigned long long>(template_index + 1u),
                    static_cast<unsigned long long>(g_poetry_templates.size()),
                    static_cast<unsigned int>(prepared.device.word_count),
                    static_cast<unsigned int>(prepared.device.wildcard_count),
                    prepared.combination_count.c_str());
            }
            for (size_t batch_index = 1u; batch_index < batch_template_count; ++batch_index) {
                const PoetryPreparedTemplate& batched =
                    g_poetry_templates[template_index + batch_index];
                printf(
                    "[!] Poetry task %llu/%llu: words=%u missing=%u "
                    "combinations=%s [!]\n",
                    static_cast<unsigned long long>(template_index + batch_index + 1u),
                    static_cast<unsigned long long>(g_poetry_templates.size()),
                    static_cast<unsigned int>(batched.device.word_count),
                    static_cast<unsigned int>(batched.device.wildcard_count),
                    batched.combination_count.c_str());
            }

            std::vector<uint64_t> random_quotas(g_gpu_contexts.size(), 0u);
            if (cycling_random) {
                const uint64_t full_launches =
                    n_number / global_random_capacity;
                const uint64_t final_launch_candidates =
                    n_number % global_random_capacity;
                uint64_t capacity_prefix = 0u;
                for (size_t gpu_index = 0; gpu_index < random_capacities.size();
                     ++gpu_index) {
                    const uint64_t capacity = random_capacities[gpu_index];
                    random_quotas[gpu_index] = full_launches * capacity;
                    if (final_launch_candidates > capacity_prefix) {
                        random_quotas[gpu_index] +=
                            std::min(capacity,
                                     final_launch_candidates - capacity_prefix);
                    }
                    capacity_prefix += capacity;
                }
            }

            std::vector<metalError_t> statuses(g_gpu_contexts.size(),
                                               metalSuccess);
            std::vector<std::thread> workers;
            workers.reserve(g_gpu_contexts.size());
            for (size_t gpu_index = 0; gpu_index < g_gpu_contexts.size();
                 ++gpu_index) {
                workers.emplace_back([&, gpu_index]() {
                    {
                        std::lock_guard<std::mutex> lock(
                            g_metal_context_api_mutex);
                        if (!activate_gpu_context(g_gpu_contexts[gpu_index])) {
                            statuses[gpu_index] = metalErrorInvalidDevice;
                            return;
                        }
                    }
                    statuses[gpu_index] = processMetalPoetryGpuSlot(
                        g_gpu_contexts[gpu_index], template_launch_blocks[gpu_index],
                        template_prefixes[gpu_index], template_stride,
                        &g_poetry_templates[template_index], batch_template_count,
                        g_poetry_dictionary,
                        cycling_random, random_quotas[gpu_index]);
                });
            }
            for (std::thread &worker : workers) {
                if (worker.joinable())
                    worker.join();
            }

            {
                std::lock_guard<std::mutex> lock(g_metal_context_api_mutex);
                activate_gpu_context(g_gpu_contexts.front());
            }
            for (size_t gpu_index = 0; gpu_index < statuses.size();
                 ++gpu_index) {
                if (statuses[gpu_index] != metalSuccess) {
                    fprintf(stderr,
                            "[!] Poetry task failed on GPU %d: %s [!]\n",
                            g_gpu_contexts[gpu_index].device_id,
                            metalGetErrorString(statuses[gpu_index]));
                    return statuses[gpu_index];
                }
            }
            template_index += batch_template_count - 1u;
        }
        if (!cycling_random)
            break;
        if (cycle != std::numeric_limits<uint64_t>::max())
            ++cycle;
    } while (isRun);
    return metalSuccess;
}
