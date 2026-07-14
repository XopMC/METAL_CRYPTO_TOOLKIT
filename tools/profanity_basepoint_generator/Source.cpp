#include "MetalBackend.h"
#include "SecpPrecompute.h"
#include "Kernels/ProfanityHost.h"
#include "host_secp/secp256k1.h"
#include "host_secp/secp256k1_field.h"
#include "host_secp/secp256k1_group.h"
#include "host_secp/secp256k1_scalar.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

#ifndef PROFANITY_PRECOMPUTE_BITS
#define PROFANITY_PRECOMPUTE_BITS 14
#endif
#ifndef PROFANITY_CURVE_BATCH_SIZE
#define PROFANITY_CURVE_BATCH_SIZE 256
#endif

constexpr uint64_t kLineSize = 41u;
constexpr uint64_t kTaskSeeds = 16384u;
constexpr size_t kCurveBatchSize = PROFANITY_CURVE_BATCH_SIZE;
constexpr unsigned int kPrecomputeBits = PROFANITY_PRECOMPUTE_BITS;
constexpr uint64_t kFlushBytes = uint64_t{256} << 20u;
constexpr char kDefaultOutput[] = "PROFANITY_BASEPOINT.txt";

std::atomic<bool> g_stop_requested{false};

struct Options {
    std::filesystem::path output = kDefaultOutput;
    uint32_t start_seed = 0u;
    uint32_t end_seed = std::numeric_limits<uint32_t>::max();
    unsigned int threads = 1u;
    bool resume = false;
};

struct ResultChunk {
    uint64_t task_id = 0u;
    uint64_t seed_count = 0u;
    std::string data;
};

struct CurveScratch {
    std::array<secp256k1_gej, kCurveBatchSize> points{};
    std::array<secp256k1_fe, kCurveBatchSize> z_values{};
    std::array<secp256k1_fe, kCurveBatchSize> z_inverse{};
};

void handle_signal(int) {
    g_stop_requested.store(true, std::memory_order_relaxed);
}

void print_help() {
    std::cout
        << "profanity_basepoint_generator - build the Profanity recovery basepoint source list\n\n"
        << "Usage:\n"
        << "  profanity_basepoint_generator [output.txt] [-s HEX32] [-e HEX32] [-t N] [--resume]\n\n"
        << "Options:\n"
        << "  -s HEX32    First seed32, inclusive (default: 00000000)\n"
        << "  -e HEX32    Last seed32, inclusive (default: ffffffff)\n"
        << "  -t N        Worker threads, 1..256 (default: logical CPU count)\n"
        << "  --resume    Continue a fixed-width partial output file\n"
        << "  -h, --help  Show this help\n\n"
        << "Default output: " << kDefaultOutput << "\n"
        << "Each seed produces one line containing the first 20 bytes of its canonical\n"
        << "secp256k1 affine-X coordinate as 40 lowercase hex characters.\n";
}

bool parse_hex32(const std::string& raw, uint32_t& value) {
    std::string text = raw;
    if (text.size() >= 2u && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.erase(0u, 2u);
    }
    if (text.empty() || text.size() > 8u) {
        return false;
    }
    uint64_t parsed = 0u;
    for (const char c : text) {
        uint8_t digit = 0u;
        if (c >= '0' && c <= '9') {
            digit = static_cast<uint8_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = static_cast<uint8_t>(10 + c - 'a');
        } else if (c >= 'A' && c <= 'F') {
            digit = static_cast<uint8_t>(10 + c - 'A');
        } else {
            return false;
        }
        parsed = (parsed << 4u) | digit;
    }
    value = static_cast<uint32_t>(parsed);
    return true;
}

bool parse_thread_count(const std::string& raw, unsigned int& value) {
    try {
        size_t consumed = 0u;
        const unsigned long parsed = std::stoul(raw, &consumed, 10);
        if (consumed != raw.size() || parsed < 1u || parsed > 256u) {
            return false;
        }
        value = static_cast<unsigned int>(parsed);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool parse_options(int argc, char** argv, Options& options, bool& help_requested) {
    help_requested = false;
    const unsigned int detected = std::thread::hardware_concurrency();
    options.threads = detected == 0u ? 1u : std::min(detected, 256u);
    bool output_set = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "-h" || arg == "--help") {
            help_requested = true;
            print_help();
            return true;
        }
        if (arg == "--resume") {
            options.resume = true;
            continue;
        }
        if (arg == "-s" || arg == "-e" || arg == "-t") {
            if (++i >= argc) {
                std::cerr << "[!] Missing value after " << arg << ".\n";
                return false;
            }
            const std::string value(argv[i]);
            if (arg == "-t") {
                if (!parse_thread_count(value, options.threads)) {
                    std::cerr << "[!] -t must be an integer from 1 to 256.\n";
                    return false;
                }
            } else {
                uint32_t parsed = 0u;
                if (!parse_hex32(value, parsed)) {
                    std::cerr << "[!] " << arg << " must be a hexadecimal seed32 from 0 to ffffffff.\n";
                    return false;
                }
                if (arg == "-s") {
                    options.start_seed = parsed;
                } else {
                    options.end_seed = parsed;
                }
            }
            continue;
        }
        if (!arg.empty() && arg[0] == '-') {
            std::cerr << "[!] Unknown argument: " << arg << "\n";
            return false;
        }
        if (output_set) {
            std::cerr << "[!] Only one output file may be specified.\n";
            return false;
        }
        options.output = arg;
        output_set = true;
    }

    if (options.start_seed > options.end_seed) {
        std::cerr << "[!] -s must not be greater than -e.\n";
        return false;
    }
    return true;
}

std::string format_size(uint64_t bytes) {
    static constexpr const char* kUnits[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    size_t unit = 0u;
    while (value >= 1024.0 && unit + 1u < std::size(kUnits)) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream out;
    out << std::fixed << std::setprecision(unit == 0u ? 0 : 2) << value << ' ' << kUnits[unit];
    return out.str();
}

std::string format_duration(double seconds) {
    if (!std::isfinite(seconds) || seconds < 0.0) {
        return "unknown";
    }
    const uint64_t total = static_cast<uint64_t>(seconds + 0.5);
    const uint64_t days = total / 86400u;
    const uint64_t hours = (total / 3600u) % 24u;
    const uint64_t minutes = (total / 60u) % 60u;
    const uint64_t secs = total % 60u;
    std::ostringstream out;
    if (days != 0u) out << days << "d ";
    if (days != 0u || hours != 0u) out << hours << "h ";
    if (days != 0u || hours != 0u || minutes != 0u) out << minutes << "m ";
    out << secs << 's';
    return out.str();
}

void append_hex20(std::string& out, const uint8_t x32[32]) {
    static constexpr char kHex[] = "0123456789abcdef";
    const size_t offset = out.size();
    out.resize(offset + kLineSize);
    for (size_t i = 0u; i < 20u; ++i) {
        const uint8_t byte = x32[i];
        out[offset + i * 2u] = kHex[byte >> 4u];
        out[offset + i * 2u + 1u] = kHex[byte & 0x0fu];
    }
    out[offset + 40u] = '\n';
}

void generate_curve_batch(uint64_t first_seed,
                          size_t count,
                          const std::vector<secp256k1_ge_storage>& precompute,
                          size_t row_pitch,
                          unsigned int windows,
                          CurveScratch& scratch,
                          std::string& output) {
    for (size_t i = 0u; i < count; ++i) {
        uint8_t private_key[32];
        profanity_private_bytes(static_cast<uint32_t>(first_seed + i), 0u, private_key);

        secp256k1_scalar scalar{};
        const int valid = secp256k1_scalar_set_b32_seckey(&scalar, private_key);
        secp256k1_scalar_cmov(&scalar, &SCALAR_ONE, !valid);
        secp256k1_ecmult_big(&scratch.points[i], &scalar, precompute.data(), row_pitch,
                             static_cast<int>(windows), kPrecomputeBits);
        scratch.z_values[i] = scratch.points[i].z;
    }

    secp256k1_fe_inv_all_var(static_cast<int>(count), scratch.z_inverse.data(),
                             scratch.z_values.data());
    for (size_t i = 0u; i < count; ++i) {
        secp256k1_ge affine{};
        secp256k1_ge_set_gej_zinv(&affine, &scratch.points[i], &scratch.z_inverse[i]);
        secp256k1_fe_normalize_var(&affine.x);
        uint8_t x32[32];
        secp256k1_fe_get_b32(x32, &affine.x);
        append_hex20(output, x32);
    }
}

ResultChunk generate_task(uint64_t task_id,
                          uint64_t range_start,
                          uint64_t total_count,
                          const std::vector<secp256k1_ge_storage>& precompute,
                          size_t row_pitch,
                          unsigned int windows,
                          CurveScratch& scratch) {
    ResultChunk result;
    result.task_id = task_id;
    const uint64_t task_offset = task_id * kTaskSeeds;
    result.seed_count = std::min<uint64_t>(kTaskSeeds, total_count - task_offset);
    result.data.reserve(static_cast<size_t>(result.seed_count * kLineSize));

    uint64_t done = 0u;
    while (done < result.seed_count) {
        const size_t current = static_cast<size_t>(
            std::min<uint64_t>(kCurveBatchSize, result.seed_count - done));
        generate_curve_batch(range_start + task_offset + done, current, precompute,
                             row_pitch, windows, scratch, result.data);
        done += current;
    }
    return result;
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    bool help_requested = false;
    if (!parse_options(argc, argv, options, help_requested)) {
        return 1;
    }
    if (help_requested) {
        return 0;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    const uint64_t requested_count = static_cast<uint64_t>(options.end_seed) -
                                     static_cast<uint64_t>(options.start_seed) + 1u;
    uint64_t completed_count = 0u;
    std::error_code fs_error;
    const bool output_exists = std::filesystem::exists(options.output, fs_error);
    if (fs_error) {
        std::cerr << "[!] Cannot inspect output file: " << fs_error.message() << "\n";
        return 1;
    }
    if (options.resume && output_exists) {
        const uint64_t bytes = std::filesystem::file_size(options.output, fs_error);
        if (fs_error) {
            std::cerr << "[!] Cannot inspect output file size: " << fs_error.message() << "\n";
            return 1;
        }
        if ((bytes % kLineSize) != 0u) {
            std::cerr << "[!] Partial output size is not divisible by 41 bytes; refusing unsafe resume.\n";
            return 1;
        }
        completed_count = bytes / kLineSize;
        if (completed_count > requested_count) {
            std::cerr << "[!] Partial output contains more lines than the selected seed range.\n";
            return 1;
        }
    } else if (output_exists && !options.resume) {
        std::cerr << "[!] Output already exists. Use --resume or choose another file.\n";
        return 1;
    }

    const uint64_t remaining_count = requested_count - completed_count;
    const uint64_t output_bytes = requested_count * kLineSize;
    const uint64_t remaining_bytes = remaining_count * kLineSize;

    const std::filesystem::path parent = options.output.has_parent_path()
        ? options.output.parent_path() : std::filesystem::current_path();
    const auto disk = std::filesystem::space(parent, fs_error);
    if (!fs_error && disk.available < remaining_bytes) {
        std::cerr << "[!] Not enough free space. Required: " << format_size(remaining_bytes)
                  << ", available: " << format_size(disk.available) << ".\n";
        return 1;
    }

    std::cout << "[!] Output: " << options.output << "\n"
              << "[!] Seed range: " << std::hex << std::setfill('0')
              << std::setw(8) << options.start_seed << ".." << std::setw(8) << options.end_seed
              << std::dec << " (" << requested_count << " values)\n"
              << "[!] Final text size: " << output_bytes << " bytes ("
              << format_size(output_bytes) << ")\n"
              << "[!] Worker threads: " << options.threads << "\n";
    if (completed_count != 0u) {
        std::cout << "[!] Resume point: " << completed_count << " lines; next seed "
                  << std::hex << std::setw(8) << std::setfill('0')
                  << (static_cast<uint64_t>(options.start_seed) + completed_count)
                  << std::dec << "\n";
    }

    std::cout << "[!] Building " << kPrecomputeBits << "-bit secp256k1 precompute table...\n";
    std::vector<secp256k1_ge_storage> precompute;
    size_t row_pitch = 0u;
    unsigned int windows = 0u;
    std::string precompute_error;
    if (!build_secp256k1_precompute_table_host(kPrecomputeBits, precompute, row_pitch,
                                               windows, precompute_error)) {
        std::cerr << "[!] Cannot build secp256k1 table: " << precompute_error << "\n";
        return 1;
    }

    if (completed_count != 0u) {
        std::ifstream partial(options.output, std::ios::binary);
        if (!partial.is_open()) {
            std::cerr << "[!] Cannot open partial output for resume validation.\n";
            return 1;
        }
        std::array<char, kLineSize> first_line{};
        std::array<char, kLineSize> last_line{};
        partial.read(first_line.data(), static_cast<std::streamsize>(first_line.size()));
        partial.seekg(static_cast<std::streamoff>((completed_count - 1u) * kLineSize),
                      std::ios::beg);
        partial.read(last_line.data(), static_cast<std::streamsize>(last_line.size()));
        if (!partial.good()) {
            std::cerr << "[!] Cannot read partial output endpoints for resume validation.\n";
            return 1;
        }

        CurveScratch validation_scratch;
        std::string expected_first;
        std::string expected_last;
        expected_first.reserve(kLineSize);
        expected_last.reserve(kLineSize);
        generate_curve_batch(options.start_seed, 1u, precompute, row_pitch, windows,
                             validation_scratch, expected_first);
        generate_curve_batch(static_cast<uint64_t>(options.start_seed) + completed_count - 1u,
                             1u, precompute, row_pitch, windows, validation_scratch,
                             expected_last);
        if (!std::equal(first_line.begin(), first_line.end(), expected_first.begin()) ||
            !std::equal(last_line.begin(), last_line.end(), expected_last.begin())) {
            std::cerr << "[!] Partial output does not match the selected seed range; refusing unsafe resume.\n";
            return 1;
        }
    }

    if (remaining_count == 0u) {
        std::cout << "[!] Output already contains the complete selected range.\n";
        return 0;
    }

    std::ofstream output(options.output, std::ios::binary |
        (options.resume ? std::ios::app : std::ios::trunc));
    if (!output.is_open()) {
        std::cerr << "[!] Cannot open output file: " << options.output << "\n";
        return 1;
    }

    const uint64_t generation_start = static_cast<uint64_t>(options.start_seed) + completed_count;
    const uint64_t task_count = (remaining_count + kTaskSeeds - 1u) / kTaskSeeds;
    std::atomic<uint64_t> next_task{0u};
    std::atomic<bool> failed{false};
    std::mutex error_mutex;
    std::string worker_error;

    std::mutex result_mutex;
    std::condition_variable result_ready;
    std::condition_variable result_space;
    std::map<uint64_t, ResultChunk> results;
    const size_t max_results = std::max<size_t>(2u, static_cast<size_t>(options.threads) * 2u);
    uint64_t next_write = 0u;
    unsigned int workers_remaining = options.threads;

    const auto started = std::chrono::steady_clock::now();
    std::vector<std::thread> workers;
    workers.reserve(options.threads);
    for (unsigned int i = 0u; i < options.threads; ++i) {
        workers.emplace_back([&] {
            try {
                CurveScratch scratch;
                while (!g_stop_requested.load(std::memory_order_relaxed) &&
                       !failed.load(std::memory_order_relaxed)) {
                    const uint64_t task_id = next_task.fetch_add(1u, std::memory_order_relaxed);
                    if (task_id >= task_count) {
                        break;
                    }
                    ResultChunk chunk = generate_task(task_id, generation_start, remaining_count,
                                                      precompute, row_pitch, windows, scratch);
                    std::unique_lock<std::mutex> lock(result_mutex);
                    result_space.wait(lock, [&] {
                        return failed.load(std::memory_order_relaxed) ||
                               results.size() < max_results || chunk.task_id == next_write;
                    });
                    if (failed.load(std::memory_order_relaxed)) {
                        break;
                    }
                    results.emplace(chunk.task_id, std::move(chunk));
                    lock.unlock();
                    result_ready.notify_one();
                }
            } catch (const std::exception& error) {
                {
                    std::lock_guard<std::mutex> lock(error_mutex);
                    if (worker_error.empty()) worker_error = error.what();
                }
                failed.store(true, std::memory_order_relaxed);
                result_ready.notify_all();
                result_space.notify_all();
            }
            {
                std::lock_guard<std::mutex> lock(result_mutex);
                --workers_remaining;
            }
            result_ready.notify_all();
        });
    }

    uint64_t written_this_run = 0u;
    uint64_t bytes_since_flush = 0u;
    auto last_report = started;
    while (!failed.load(std::memory_order_relaxed)) {
        ResultChunk chunk;
        {
            std::unique_lock<std::mutex> lock(result_mutex);
            result_ready.wait(lock, [&] {
                return failed.load(std::memory_order_relaxed) ||
                       results.find(next_write) != results.end() || workers_remaining == 0u;
            });
            if (failed.load(std::memory_order_relaxed)) break;
            auto it = results.find(next_write);
            if (it == results.end()) break;
            chunk = std::move(it->second);
            results.erase(it);
            ++next_write;
        }
        result_space.notify_all();

        output.write(chunk.data.data(), static_cast<std::streamsize>(chunk.data.size()));
        if (!output.good()) {
            failed.store(true, std::memory_order_relaxed);
            std::lock_guard<std::mutex> lock(error_mutex);
            worker_error = "output write failed";
            result_space.notify_all();
            break;
        }
        written_this_run += chunk.seed_count;
        bytes_since_flush += chunk.data.size();
        if (bytes_since_flush >= kFlushBytes) {
            output.flush();
            bytes_since_flush = 0u;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now - last_report >= std::chrono::seconds(5)) {
            const double elapsed = std::chrono::duration<double>(now - started).count();
            const double speed = elapsed > 0.0 ? static_cast<double>(written_this_run) / elapsed : 0.0;
            const uint64_t left = remaining_count - written_this_run;
            const double eta = speed > 0.0 ? static_cast<double>(left) / speed
                                           : std::numeric_limits<double>::infinity();
            const double percent = 100.0 * static_cast<double>(completed_count + written_this_run) /
                                   static_cast<double>(requested_count);
            std::cout << "[!] " << std::fixed << std::setprecision(2) << percent << "% | "
                      << std::setprecision(0) << speed << " points/s | ETA "
                      << format_duration(eta) << "\n";
            last_report = now;
        }
    }

    if (failed.load(std::memory_order_relaxed)) {
        g_stop_requested.store(true, std::memory_order_relaxed);
        result_space.notify_all();
        result_ready.notify_all();
    }
    for (std::thread& worker : workers) {
        worker.join();
    }
    output.flush();
    output.close();

    if (failed.load(std::memory_order_relaxed)) {
        std::lock_guard<std::mutex> lock(error_mutex);
        std::cerr << "[!] Generation failed: "
                  << (worker_error.empty() ? "unknown error" : worker_error) << "\n";
        return 1;
    }

    const auto finished = std::chrono::steady_clock::now();
    const double elapsed = std::chrono::duration<double>(finished - started).count();
    const double speed = elapsed > 0.0 ? static_cast<double>(written_this_run) / elapsed : 0.0;
    const uint64_t total_written = completed_count + written_this_run;
    if (g_stop_requested.load(std::memory_order_relaxed)) {
        std::cout << "[!] Interrupted after " << total_written
                  << " lines. Run the same command with --resume to continue.\n";
        return 130;
    }

    std::cout << "[!] Complete: " << total_written << " lines in "
              << format_duration(elapsed) << " (" << std::fixed << std::setprecision(0)
              << speed << " points/s).\n";
    return total_written == requested_count ? 0 : 1;
}
