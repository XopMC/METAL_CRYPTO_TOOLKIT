#include "ToolRunner.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cctype>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

namespace address_tools {
namespace {

constexpr size_t kBatchSize = 4096;

struct Options {
    std::filesystem::path input;
    std::filesystem::path output;
    std::filesystem::path invalid;
    unsigned int threads = 1;
};

struct WorkBatch {
    size_t id = 0;
    std::vector<std::string> lines;
};

struct ResultLine {
    std::string input;
    std::vector<uint8_t> decoded;
    bool empty = false;
    bool decoded_ok = false;
};

struct ResultBatch {
    size_t id = 0;
    std::vector<ResultLine> lines;
};

std::string trim_ascii(std::string_view value) {
    size_t begin = 0;
    size_t end = value.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return std::string(value.substr(begin, end - begin));
}

std::string hex_encode(const std::vector<uint8_t>& bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        result[i * 2] = kHex[bytes[i] >> 4];
        result[i * 2 + 1] = kHex[bytes[i] & 0x0f];
    }
    return result;
}

std::filesystem::path default_sidecar(const std::filesystem::path& input,
                                      std::string_view suffix) {
    const std::filesystem::path parent = input.parent_path();
    std::string stem = input.stem().string();
    if (stem.empty()) {
        stem = input.filename().string();
    }
    return parent / (stem + std::string(suffix));
}

bool same_path(const std::filesystem::path& lhs, const std::filesystem::path& rhs) {
    std::error_code error;
    const auto left = std::filesystem::absolute(lhs, error).lexically_normal();
    if (error) {
        return false;
    }
    const auto right = std::filesystem::absolute(rhs, error).lexically_normal();
    if (error) {
        return false;
    }
    if (left == right) {
        return true;
    }
    error.clear();
    const bool equivalent = std::filesystem::equivalent(left, right, error);
    return !error && equivalent;
}

void print_help(std::string_view tool_name, std::string_view description) {
    std::cout << tool_name << " - " << description << "\n\n"
              << "Usage:\n  " << tool_name
              << " <input.txt> [output.txt] [-t N]\n\n"
              << "Options:\n"
              << "  -t N       Worker threads, 1..256 (default: logical CPU count)\n"
              << "  -h, --help Show this help\n\n"
              << "The output contains one lowercase hexadecimal value per valid input line.\n";
}

bool parse_options(int argc,
                   char** argv,
                   std::string_view tool_name,
                   std::string_view description,
                   Options& options,
                   bool& help_requested) {
    help_requested = false;
    std::vector<std::string> positional;
    unsigned int detected = std::thread::hardware_concurrency();
    options.threads = detected == 0 ? 1 : std::min(detected, 256u);

    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        if (argument == "-h" || argument == "--help") {
            help_requested = true;
            print_help(tool_name, description);
            return true;
        }
        if (argument == "-t") {
            if (index + 1 >= argc) {
                std::cerr << "[!] Missing value after -t.\n";
                return false;
            }
            try {
                size_t parsed = 0;
                const unsigned long value = std::stoul(argv[++index], &parsed, 10);
                if (parsed != std::string(argv[index]).size() || value < 1 || value > 256) {
                    throw std::out_of_range("thread count");
                }
                options.threads = static_cast<unsigned int>(value);
            } catch (const std::exception&) {
                std::cerr << "[!] -t must be an integer from 1 to 256.\n";
                return false;
            }
            continue;
        }
        if (!argument.empty() && argument[0] == '-') {
            std::cerr << "[!] Unknown argument: " << argument << "\n";
            return false;
        }
        positional.push_back(argument);
    }

    if (positional.empty() || positional.size() > 2) {
        print_help(tool_name, description);
        return false;
    }

    options.input = positional[0];
    options.output = positional.size() == 2
                         ? std::filesystem::path(positional[1])
                         : default_sidecar(options.input, "-hex.txt");
    options.invalid = default_sidecar(options.input, "-invalid.txt");

    if (same_path(options.input, options.output)) {
        std::cerr << "[!] Input and output files must be different.\n";
        return false;
    }
    if (same_path(options.input, options.invalid)) {
        std::cerr << "[!] Input file conflicts with the invalid-line file.\n";
        return false;
    }
    if (same_path(options.output, options.invalid)) {
        std::cerr << "[!] Output file conflicts with the invalid-line file.\n";
        return false;
    }
    return true;
}

}  // namespace

int run_converter(int argc,
                  char** argv,
                  std::string_view tool_name,
                  std::string_view description,
                  Decoder decoder) {
    Options options;
    bool help_requested = false;
    if (!parse_options(argc, argv, tool_name, description, options, help_requested)) {
        return 1;
    }
    if (help_requested) {
        return 0;
    }

    std::ifstream input(options.input, std::ios::binary);
    if (!input.is_open()) {
        std::cerr << "[!] Cannot open input file: " << options.input << "\n";
        return 1;
    }
    std::ofstream output(options.output, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        std::cerr << "[!] Cannot open output file: " << options.output << "\n";
        return 1;
    }

    std::error_code remove_error;
    std::filesystem::remove(options.invalid, remove_error);

    std::mutex work_mutex;
    std::condition_variable work_ready;
    std::condition_variable work_space;
    std::deque<WorkBatch> work_queue;
    const size_t max_queued_batches = std::max<size_t>(2, options.threads * 2);
    bool producer_done = false;

    std::mutex result_mutex;
    std::condition_variable result_ready;
    std::condition_variable result_space;
    std::map<size_t, ResultBatch> results;
    const size_t max_result_batches = std::max<size_t>(2, options.threads * 2);
    size_t next_result_batch = 0;
    size_t workers_remaining = options.threads;

    std::atomic<bool> write_failed(false);
    uint64_t processed_count = 0;
    uint64_t valid_count = 0;
    uint64_t invalid_count = 0;
    uint64_t empty_count = 0;

    std::vector<std::thread> workers;
    workers.reserve(options.threads);
    for (unsigned int thread_index = 0; thread_index < options.threads; ++thread_index) {
        workers.emplace_back([&] {
            for (;;) {
                WorkBatch batch;
                {
                    std::unique_lock<std::mutex> lock(work_mutex);
                    work_ready.wait(lock, [&] {
                        return write_failed.load(std::memory_order_relaxed) || producer_done ||
                               !work_queue.empty();
                    });
                    if (write_failed.load(std::memory_order_relaxed) || work_queue.empty()) {
                        break;
                    }
                    batch = std::move(work_queue.front());
                    work_queue.pop_front();
                    work_space.notify_one();
                }

                ResultBatch converted;
                converted.id = batch.id;
                converted.lines.reserve(batch.lines.size());
                for (std::string& raw : batch.lines) {
                    ResultLine result;
                    result.input = trim_ascii(raw);
                    if (result.input.empty()) {
                        result.empty = true;
                    } else {
                        result.decoded_ok = decoder(result.input, result.decoded);
                    }
                    converted.lines.push_back(std::move(result));
                }

                bool cancelled = false;
                {
                    std::unique_lock<std::mutex> lock(result_mutex);
                    result_space.wait(lock, [&] {
                        return write_failed.load(std::memory_order_relaxed) ||
                               results.size() < max_result_batches ||
                               converted.id == next_result_batch;
                    });
                    if (write_failed.load(std::memory_order_relaxed)) {
                        cancelled = true;
                    } else {
                        results.emplace(converted.id, std::move(converted));
                    }
                }
                if (cancelled) break;
                result_ready.notify_one();
            }

            {
                std::lock_guard<std::mutex> lock(result_mutex);
                --workers_remaining;
            }
            result_ready.notify_one();
        });
    }

    std::thread writer([&] {
        std::optional<size_t> expected_length;
        std::ofstream invalid;
        auto mark_write_failed = [&] {
            write_failed.store(true, std::memory_order_relaxed);
            result_space.notify_all();
            work_space.notify_all();
            work_ready.notify_all();
        };

        for (;;) {
            ResultBatch batch;
            {
                std::unique_lock<std::mutex> lock(result_mutex);
                result_ready.wait(lock, [&] {
                    return results.find(next_result_batch) != results.end() || workers_remaining == 0;
                });
                auto it = results.find(next_result_batch);
                if (it == results.end()) {
                    break;
                }
                batch = std::move(it->second);
                results.erase(it);
            }
            result_space.notify_all();

            for (const ResultLine& line : batch.lines) {
                if (line.empty) {
                    ++empty_count;
                    continue;
                }
                ++processed_count;
                bool valid = line.decoded_ok && !line.decoded.empty();
                if (valid && expected_length.has_value() && line.decoded.size() != *expected_length) {
                    valid = false;
                }
                if (valid && !expected_length.has_value()) {
                    expected_length = line.decoded.size();
                }

                if (valid) {
                    output << hex_encode(line.decoded) << '\n';
                    ++valid_count;
                } else {
                    if (!invalid.is_open()) {
                        invalid.open(options.invalid, std::ios::binary | std::ios::trunc);
                    }
                    if (!invalid.is_open()) {
                        mark_write_failed();
                        return;
                    }
                    invalid << line.input << '\n';
                    ++invalid_count;
                }
            }
            if (!output.good() || (invalid.is_open() && !invalid.good())) {
                mark_write_failed();
                return;
            }
            {
                std::lock_guard<std::mutex> lock(result_mutex);
                ++next_result_batch;
            }
            result_space.notify_all();
        }

        output.flush();
        if (!output.good()) {
            mark_write_failed();
            return;
        }
        if (invalid.is_open()) {
            invalid.flush();
            if (!invalid.good()) {
                mark_write_failed();
                return;
            }
            invalid.close();
            if (invalid.fail()) {
                mark_write_failed();
            }
        }
    });

    size_t batch_id = 0;
    for (;;) {
        WorkBatch batch;
        batch.id = batch_id;
        batch.lines.reserve(kBatchSize);
        std::string line;
        while (batch.lines.size() < kBatchSize && std::getline(input, line)) {
            batch.lines.push_back(std::move(line));
        }
        if (batch.lines.empty()) {
            break;
        }

        {
            std::unique_lock<std::mutex> lock(work_mutex);
            work_space.wait(lock, [&] {
                return write_failed.load(std::memory_order_relaxed) ||
                       work_queue.size() < max_queued_batches;
            });
            if (write_failed.load(std::memory_order_relaxed)) {
                break;
            }
            work_queue.push_back(std::move(batch));
        }
        work_ready.notify_one();
        ++batch_id;
    }

    {
        std::lock_guard<std::mutex> lock(work_mutex);
        producer_done = true;
    }
    work_ready.notify_all();

    for (std::thread& worker : workers) {
        worker.join();
    }
    writer.join();

    output.flush();
    const bool output_flush_failed = !output.good();
    output.close();
    const bool output_close_failed = output.fail();

    if (input.bad()) {
        std::cerr << "[!] Failed while reading input file.\n";
        return 1;
    }
    if (write_failed.load(std::memory_order_relaxed) || output_flush_failed ||
        output_close_failed) {
        std::cerr << "[!] Failed while writing conversion results.\n";
        return 1;
    }

    std::cout << "Processed: " << processed_count << " | Valid: " << valid_count
              << " | Invalid: " << invalid_count << " | Empty: " << empty_count
              << " | Threads: " << options.threads << '\n';
    std::cout << "Output: " << options.output << '\n';
    if (invalid_count != 0) {
        std::cout << "Invalid lines: " << options.invalid << '\n';
    }
    return 0;
}

}  // namespace address_tools
