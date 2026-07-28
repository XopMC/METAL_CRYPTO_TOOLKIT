#include "KernelRuntime.h"
#include "Poetry.h"
#include "lib/hash/sha256.h"
#include "lib/hash/ripemd160.h"
#include "sr25519-donna-32bit/dot.h"
#include <sstream>
#include "filter.h"
#include <thread>
#include <mutex>
#include <cstdio>
#include <cstdarg>
#include <functional>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include <condition_variable>
#include <deque>
#include <stdexcept>
#include <unordered_map>
#include <atomic>
#include <cstring>

static constexpr uint8_t XP_PROFILE_RANDSTORM_PYMT = 10u;
static constexpr uint8_t XP_PROFILE_RANDSTORM_MWC32 = 11u;
static constexpr uint8_t XP_PROFILE_RANDSTORM_BYTES = 13u;
static constexpr uint8_t XP_PROFILE_RANDSTORM_V8INIT_BYTES = 14u;
static constexpr uint8_t XP_PROFILE_RANDSTORM_V8INIT_POOL32 = 15u;

static std::mutex g_founds_mutex;
static std::mutex g_save_output_mutex;
extern thread_local int DEVICE_NR;
extern bool g_save_output_with_gpu_prefix;
extern uint32_t deep;
extern bool g_crypted_input_active;
extern bool IS_HEX;
extern std::vector<std::string> passwords_list;
std::string crypted_encrypt_plaintext(const std::string& plaintext);

static thread_local int g_save_output_gpu_id = -1;
static thread_local bool g_save_output_stdout_line_start = true;
static thread_local bool g_save_output_file_line_start = true;
static std::atomic<int> g_save_cpu_postcheck_suppression_depth{ 0 };

METAL_HOST void push_save_cpu_postcheck_suppression() {
	g_save_cpu_postcheck_suppression_depth.fetch_add(1, std::memory_order_acq_rel);
}

METAL_HOST void pop_save_cpu_postcheck_suppression() {
	const int prev = g_save_cpu_postcheck_suppression_depth.fetch_sub(1, std::memory_order_acq_rel);
	if (prev <= 0) {
		g_save_cpu_postcheck_suppression_depth.store(0, std::memory_order_release);
	}
}

// save_output_set_gpu_prefix: saves output set GPU prefix.
static inline void save_output_set_gpu_prefix(const int gpu_id) {
	g_save_output_gpu_id = gpu_id;
	g_save_output_stdout_line_start = true;
	g_save_output_file_line_start = true;
}

// save_output_format_string: saves output format string.
static inline std::string save_output_format_string(const char* fmt, va_list ap) {
	if (fmt == nullptr) {
		return std::string();
	}

	va_list ap_count;
	va_copy(ap_count, ap);
	const int needed = std::vsnprintf(nullptr, 0, fmt, ap_count);
	va_end(ap_count);
	if (needed <= 0) {
		return std::string();
	}

	std::vector<char> tmp(static_cast<size_t>(needed) + 1u, '\0');
	va_list ap_write;
	va_copy(ap_write, ap);
	std::vsnprintf(tmp.data(), tmp.size(), fmt, ap_write);
	va_end(ap_write);
	return std::string(tmp.data(), static_cast<size_t>(needed));
}

// save_output_apply_gpu_prefix: saves output apply GPU prefix.
static inline std::string save_output_apply_gpu_prefix(FILE* stream, const std::string& input) {
	if (g_save_output_gpu_id < 0 || stream == nullptr || stream == stderr || input.empty()) {
		return input;
	}

	bool* line_start = (stream == stdout) ? &g_save_output_stdout_line_start : &g_save_output_file_line_start;
	const std::string prefix = "GPU " + std::to_string(g_save_output_gpu_id) + ":";

	std::string out;
	out.reserve(input.size() + prefix.size() * 2u);
	for (char ch : input) {
		if (*line_start && ch != '\n') {
			out.append(prefix);
			*line_start = false;
		}
		out.push_back(ch);
		if (ch == '\n') {
			*line_start = true;
		}
	}
	return out;
}

static int gpu_prefixed_fprintf(FILE* stream, const char* fmt, ...) {
	if (stream == nullptr) {
		return -1;
	}

	va_list ap;
	va_start(ap, fmt);
	std::string text = save_output_format_string(fmt, ap);
	va_end(ap);

	text = save_output_apply_gpu_prefix(stream, text);
	if (text.empty()) {
		return 0;
	}

	std::lock_guard<std::mutex> lock(g_save_output_mutex);
	const size_t written = std::fwrite(text.data(), 1, text.size(), stream);
	return static_cast<int>(written);
}

struct AsyncSaveTask {
	std::function<void()> fn;
};

struct AsyncSaveQueue {
	std::mutex mutex;
	std::condition_variable cv_not_empty;
	std::condition_variable cv_not_full;
	std::condition_variable cv_idle;
	std::deque<AsyncSaveTask> tasks;
	std::thread worker;
	size_t in_flight = 0;
	bool stopping = false;
	bool started = false;
	int gpu_id = -1;
};

static std::mutex g_async_save_queues_mutex;
static std::unordered_map<int, std::shared_ptr<AsyncSaveQueue>> g_async_save_queues;
static constexpr size_t MAX_PENDING_SAVE_TASKS_PER_GPU = 64u;

static void async_save_worker_loop(const std::shared_ptr<AsyncSaveQueue>& queue) {
	const int prefixed_gpu_id = g_save_output_with_gpu_prefix ? queue->gpu_id : -1;
	save_output_set_gpu_prefix(prefixed_gpu_id);

	for (;;) {
		AsyncSaveTask task;
		{
			std::unique_lock<std::mutex> lock(queue->mutex);
			queue->cv_not_empty.wait(lock, [&]() { return queue->stopping || !queue->tasks.empty(); });
			if (queue->stopping && queue->tasks.empty()) {
				break;
			}
			task = std::move(queue->tasks.front());
			queue->tasks.pop_front();
			++queue->in_flight;
			queue->cv_not_full.notify_one();
		}

		task.fn();

		{
			std::lock_guard<std::mutex> lock(queue->mutex);
			if (queue->in_flight > 0) {
				--queue->in_flight;
			}
			if (queue->tasks.empty() && queue->in_flight == 0) {
				queue->cv_idle.notify_all();
			}
		}
	}

	save_output_set_gpu_prefix(-1);
}

static std::shared_ptr<AsyncSaveQueue> get_async_save_queue_for_gpu(const int gpu_id) {
	std::lock_guard<std::mutex> map_lock(g_async_save_queues_mutex);
	auto it = g_async_save_queues.find(gpu_id);
	if (it != g_async_save_queues.end()) {
		return it->second;
	}

	auto queue = std::make_shared<AsyncSaveQueue>();
	queue->gpu_id = gpu_id;
	queue->started = true;
	queue->worker = std::thread([queue]() {
		async_save_worker_loop(queue);
	});
	g_async_save_queues.emplace(gpu_id, queue);
	return queue;
}

template <typename Fn, typename... Args>
static inline void enqueue_async_save_task_for_current_gpu(const char* family, const size_t batch_size, const bool save_mode, Fn&& fn, Args&&... args) {
	const int gpu_id = DEVICE_NR;
	auto bound = std::bind(std::forward<Fn>(fn), std::forward<Args>(args)...);
	typedef typename std::decay<decltype(bound)>::type BoundFn;
	auto bound_ptr = std::make_shared<BoundFn>(std::move(bound));

	AsyncSaveTask task;
	task.fn = [bound_ptr]() {
		(*bound_ptr)();
	};

	auto queue = get_async_save_queue_for_gpu(gpu_id);
	std::unique_lock<std::mutex> lock(queue->mutex);
	queue->cv_not_full.wait(lock, [&]() {
		return queue->stopping || queue->tasks.size() < MAX_PENDING_SAVE_TASKS_PER_GPU;
	});
	if (queue->stopping) {
		throw std::runtime_error("async save queue is stopping");
	}
	queue->tasks.push_back(std::move(task));
	lock.unlock();
	queue->cv_not_empty.notify_one();
}

static void wait_for_async_save_queue(const std::shared_ptr<AsyncSaveQueue>& queue) {
	if (!queue) {
		return;
	}

	std::unique_lock<std::mutex> lock(queue->mutex);
	queue->cv_idle.wait(lock, [&]() {
		return queue->tasks.empty() && queue->in_flight == 0;
	});
}

METAL_HOST void wait_for_current_gpu_async_save_queue() {
	const int gpu_id = DEVICE_NR;
	std::shared_ptr<AsyncSaveQueue> queue;
	{
		std::lock_guard<std::mutex> map_lock(g_async_save_queues_mutex);
		auto it = g_async_save_queues.find(gpu_id);
		if (it != g_async_save_queues.end()) {
			queue = it->second;
		}
	}
	wait_for_async_save_queue(queue);
}

METAL_HOST void flush_all_async_save_queues() {
	std::vector<std::shared_ptr<AsyncSaveQueue>> queues;
	{
		std::lock_guard<std::mutex> map_lock(g_async_save_queues_mutex);
		for (const auto& entry : g_async_save_queues) {
			queues.push_back(entry.second);
		}
	}

	for (const auto& queue : queues) {
		wait_for_async_save_queue(queue);
	}
}

METAL_HOST void shutdown_async_save_queues() {
	std::vector<std::shared_ptr<AsyncSaveQueue>> queues;
	{
		std::lock_guard<std::mutex> map_lock(g_async_save_queues_mutex);
		for (const auto& entry : g_async_save_queues) {
			queues.push_back(entry.second);
		}
	}

	for (const auto& queue : queues) {
		wait_for_async_save_queue(queue);
		{
			std::lock_guard<std::mutex> lock(queue->mutex);
			queue->stopping = true;
		}
		queue->cv_not_empty.notify_all();
		queue->cv_not_full.notify_all();
	}

	for (const auto& queue : queues) {
		if (queue && queue->worker.joinable()) {
			queue->worker.join();
		}
	}

	std::lock_guard<std::mutex> map_lock(g_async_save_queues_mutex);
	g_async_save_queues.clear();
}

static inline bool save_worker_find_in_bloom(const hash160_t& hash) {
	return find_in_bloom(hash);
}

static inline uint32_t safe_found_string_len(const char* data, uint32_t reported_len, uint32_t cap = 511) {
    if (reported_len > 0 && reported_len <= cap) return reported_len;
    uint32_t n = 0;
    while (n < cap && data[n] != '\0') ++n;
    return n;
}

static inline uint8_t endo_base_type_or_self(uint8_t type);
static inline void append_ed25519_round_tag(std::string& round, bool is_ed);
uint32_t reverseByteOrderHost(uint32_t val);

static inline bool found_hash_is_32_bytes(uint8_t coin_type) {
	switch (endo_base_type_or_self(coin_type)) {
	case 0x01:
	case 0x02:
	case 0x03:
	case 0x06:
	case 0x41:
	case 0x42:
	case 0x90:
	case 0x91:
	case 0x92:
	case 0x93:
		return false;
	default:
		return true;
	}
}

	#define fprintf gpu_prefixed_fprintf

// increment_founds: increments founds.
static inline void increment_founds(uint32_t* pFounds) {
	if (pFounds == nullptr) {
		return;
	}
	std::lock_guard<std::mutex> lock(g_founds_mutex);
	++(*pFounds);
}

static inline void increment_false_positive() {
	false_positive.fetch_add(1u, std::memory_order_relaxed);
}

static inline bool save_output_flush(FILE* file) {
	if (file == nullptr) {
		return true;
	}
	std::lock_guard<std::mutex> lock(g_save_output_mutex);
	return std::fflush(file) == 0;
}

static std::string sanitize_visible_utf8(std::string value) {
	if (value.empty()) {
		return value;
	}

	std::string safe;
	safe.reserve(value.size() * 4u);

	const unsigned char* p = reinterpret_cast<const unsigned char*>(value.data());
	size_t pos = 0;
	const size_t n = value.size();

	auto hex_append = [&](unsigned char ch) {
		char buf[7];
		std::snprintf(buf, sizeof(buf), "[0x%02X]", ch);
		safe.append(buf);
	};

	while (pos < n) {
		const unsigned char ch = p[pos];

		if (ch < 0x20 || ch == 0x7F) {
			hex_append(ch);
			++pos;
			continue;
		}
		if (ch < 0x80) {
			safe.push_back(static_cast<char>(ch));
			++pos;
			continue;
		}

		if (ch == 0xC0 || ch == 0xC1 || ch >= 0xF5) {
			hex_append(ch);
			++pos;
			continue;
		}

		const size_t need =
			(ch & 0xE0) == 0xC0 ? 2u :
			(ch & 0xF0) == 0xE0 ? 3u :
			(ch & 0xF8) == 0xF0 ? 4u : 0u;

		if (need == 0u || pos + need > n) {
			hex_append(ch);
			++pos;
			continue;
		}

		bool cont = true;
		for (size_t j = 1; j < need; ++j) {
			if ((p[pos + j] & 0xC0) != 0x80) {
				cont = false;
				break;
			}
		}
		if (!cont) {
			hex_append(ch);
			++pos;
			continue;
		}

		uint32_t cp = 0;
		if (need == 2u) cp = ((p[pos] & 0x1Fu) << 6) | (p[pos + 1] & 0x3Fu);
		else if (need == 3u) cp = ((p[pos] & 0x0Fu) << 12) | ((p[pos + 1] & 0x3Fu) << 6) | (p[pos + 2] & 0x3Fu);
		else cp = ((p[pos] & 0x07u) << 18) | ((p[pos + 1] & 0x3Fu) << 12) | ((p[pos + 2] & 0x3Fu) << 6) | (p[pos + 3] & 0x3Fu);

		if ((need == 2u && cp < 0x80u) ||
			(need == 3u && cp < 0x800u) ||
			(need == 4u && (cp < 0x10000u || cp > 0x10FFFFu)) ||
			(cp >= 0xD800u && cp <= 0xDFFFu) ||
			cp == 0xFFFDu ||
			(cp < 0x20u) || (cp >= 0x7Fu && cp <= 0x9Fu)) {
			for (size_t j = 0; j < need; ++j) {
				hex_append(p[pos + j]);
			}
			pos += need;
			continue;
		}

		safe.append(value, pos, need);
		pos += need;
	}

	return safe;
}

static inline std::string load_found_text_sanitized(const char* data, uint32_t reported_len, uint32_t cap) {
	std::string out;
	out.assign(data, safe_found_string_len(data, reported_len, cap));
	return sanitize_visible_utf8(std::move(out));
}

static inline std::string load_found_text_raw_cstr(const char* data, uint32_t cap = 511) {
	std::string out;
	out.assign(data, safe_found_string_len(data, 0, cap));
	return out;
}

static inline std::string trim_string_at_nul(std::string value) {
	const size_t nul = value.find('\0');
	if (nul != std::string::npos) {
		value.resize(nul);
	}
	return value;
}

static inline std::string build_round_suffix(const int64_t found_round, const bool is_ed) {
	std::string round = (found_round == 0) ? std::string() : ((found_round > 0 ? " +" : " -") + std::to_string(found_round > 0 ? found_round : -found_round));
	append_ed25519_round_tag(round, is_ed);
	return round;
}

METAL_HOST static inline int save_output_write_prebuilt(FILE* stream, const std::string& text) {
	if (stream == nullptr || text.empty()) {
		return 0;
	}

	std::string normalized = text;
	if (!normalized.empty() && normalized.front() == '\n') {
		normalized.erase(0, 1);
	}

	std::string prefixed = save_output_apply_gpu_prefix(stream, normalized);
	if (prefixed.empty()) {
		return 0;
	}
	if (prefixed.back() != '\n') {
		prefixed += "\n";
	}

	std::lock_guard<std::mutex> lock(g_save_output_mutex);
	const size_t written = std::fwrite(prefixed.data(), 1, prefixed.size(), stream);
	return static_cast<int>(written);
}

METAL_HOST static inline void append_hex_bytes_lower(std::string& out, const uint8_t* data, const size_t len) {
	static const char kHex[] = "0123456789abcdef";
	out.reserve(out.size() + (len * 2u));
	for (size_t idx = 0; idx < len; ++idx) {
		const uint8_t byte = data[idx];
		out.push_back(kHex[(byte >> 4) & 0x0F]);
		out.push_back(kHex[byte & 0x0F]);
	}
}

METAL_HOST static inline std::string build_hex_bytes_lower(const uint8_t* data, const size_t len) {
	std::string out;
	out.reserve(len * 2u);
	append_hex_bytes_lower(out, data, len);
	return out;
}

METAL_HOST static inline std::string build_binary_selected_text(const char* found_string, const uint32_t reported_len, const uint32_t cap = 511) {
	std::string selected = load_found_text_sanitized(found_string, reported_len, cap);
	selected = sanitize_visible_utf8(std::move(selected));
	selected += ":hex(";
	selected += build_hex_bytes_lower(reinterpret_cast<const uint8_t*>(found_string), reported_len);
	selected += ")";
	return selected;
}

METAL_HOST static inline std::string build_binary_selected_visible_text(const char* found_string, const uint32_t reported_len, const uint32_t cap = 511) {
	std::string selected = load_found_text_sanitized(found_string, reported_len, cap);
	return sanitize_visible_utf8(std::move(selected));
}

METAL_HOST static inline std::string build_crypted_source_text_from_found_bytes(const char* found_string, const uint32_t reported_len) {
	if (IS_HEX) {
		return build_hex_bytes_lower(reinterpret_cast<const uint8_t*>(found_string), reported_len);
	}
	return build_binary_selected_visible_text(found_string, reported_len);
}

METAL_HOST static inline std::string build_crypted_visible_source_text(const char* found_string, const uint32_t reported_len) {
	return build_binary_selected_visible_text(found_string, reported_len);
}

METAL_HOST static inline void append_u32_hex_lower(std::string& out, const uint32_t value) {
	static const char kHex[] = "0123456789abcdef";
	for (int shift = 28; shift >= 0; shift -= 4) {
		out.push_back(kHex[(value >> shift) & 0x0F]);
	}
}

METAL_HOST static inline std::string build_hash_payload_words(const uint32_t* words, const size_t word_count, const bool add_0x_prefix = false) {
	std::string out;
	out.reserve((add_0x_prefix ? 2u : 0u) + word_count * 8u);
	if (add_0x_prefix) {
		out += "0x";
	}
	for (size_t idx = 0; idx < word_count; ++idx) {
		append_u32_hex_lower(out, reverseByteOrderHost(words[idx]));
	}
	return out;
}

METAL_HOST static inline std::string build_key_segment_from_hex(const std::string& priv_hex, const std::string& round) {
	std::string out;
	out.reserve(priv_hex.size() + round.size());
	out += priv_hex;
	out += round;
	return out;
}

METAL_HOST static inline std::string build_key_segment(const uint8_t* priv_key, const std::string& round) {
	std::string out = build_hex_bytes_lower(priv_key, 32);
	out += round;
	return out;
}

METAL_HOST static inline std::string build_dual_key_segment(const uint8_t* priv_key, const std::string& round) {
	std::string out = build_hex_bytes_lower(priv_key, 32);
	out += round;
	out.push_back('|');
	append_hex_bytes_lower(out, priv_key + 32, 32);
	out += round;
	return out;
}

METAL_HOST static inline std::string build_dual_key_segment_from_hex(const std::string& priv_hex, const std::string& round, const std::string& extra_hex) {
	std::string out;
	out.reserve(priv_hex.size() + round.size() + 1u + extra_hex.size() + round.size());
	out += priv_hex;
	out += round;
	out.push_back('|');
	out += extra_hex;
	out += round;
	return out;
}

static inline bool save_crypted_output_enabled() {
	return g_crypted_input_active;
}

static inline std::string crypted_protect_output_text(const std::string& plain) {
	return save_crypted_output_enabled() ? crypted_encrypt_plaintext(plain) : plain;
}

static inline std::string crypted_protect_private_key_segment(const std::string& key_segment) {
	return save_crypted_output_enabled() ? crypted_encrypt_plaintext(key_segment) : key_segment;
}

METAL_HOST static inline std::string build_result_line_with_newline(const std::string& head,
	const std::string& key_segment,
	const char* type,
	const std::string& payload,
	const bool add_newline,
	const bool omit_key_segment = false) {
	std::string out;
	const size_t type_len = (type == nullptr) ? 0u : std::strlen(type);
	out.reserve(head.size() + (omit_key_segment ? 0u : key_segment.size()) + type_len + payload.size() + (add_newline ? (omit_key_segment ? 2u : 3u) : (omit_key_segment ? 1u : 2u)));
	out += head;
	if (!omit_key_segment) {
		out += key_segment;
		out.push_back(':');
	}
	if (type_len != 0u) {
		out.append(type, type_len);
	}
	out.push_back(':');
	out += payload;
	if (add_newline) {
		out.push_back('\n');
	}
	return out;
}

static inline std::string sanitize_brain_visible_text(std::string selected) {
	if (selected.empty()) {
		return selected;
	}

	std::string safe;
	safe.reserve(selected.size() * 4u);

	const unsigned char* p = reinterpret_cast<const unsigned char*>(selected.data());
	uint64_t idx = 0;
	const uint64_t n = selected.size();

	auto hex_append = [&](unsigned char ch) {
		char buf[7];
		std::snprintf(buf, sizeof(buf), "[0x%02X]", ch);
		safe.append(buf);
	};

	while (idx < n) {
		const unsigned char ch = p[idx];

		if (ch < 0x20 || ch == 0x7F) {
			hex_append(ch);
			++idx;
			continue;
		}
		if (ch < 0x80) {
			safe.push_back(static_cast<char>(ch));
			++idx;
			continue;
		}

		if (ch == 0xC0 || ch == 0xC1 || ch >= 0xF5) {
			hex_append(ch);
			++idx;
			continue;
		}

		const uint64_t need =
			(ch & 0xE0) == 0xC0 ? 2 :
			(ch & 0xF0) == 0xE0 ? 3 :
			(ch & 0xF8) == 0xF0 ? 4 : 0;

		if (need == 0 || idx + need > n) {
			hex_append(ch);
			++idx;
			continue;
		}

		bool cont = true;
		for (size_t j = 1; j < need; ++j) {
			if ((p[idx + j] & 0xC0) != 0x80) {
				cont = false;
				break;
			}
		}
		if (!cont) {
			hex_append(ch);
			++idx;
			continue;
		}

		uint32_t cp = 0;
		if (need == 2) {
			cp = ((p[idx] & 0x1Fu) << 6) | (p[idx + 1] & 0x3Fu);
		}
		else if (need == 3) {
			cp = ((p[idx] & 0x0Fu) << 12) | ((p[idx + 1] & 0x3Fu) << 6) | (p[idx + 2] & 0x3Fu);
		}
		else {
			cp = ((p[idx] & 0x07u) << 18) | ((p[idx + 1] & 0x3Fu) << 12) | ((p[idx + 2] & 0x3Fu) << 6) | (p[idx + 3] & 0x3Fu);
		}

		if ((need == 2 && cp < 0x80) ||
			(need == 3 && cp < 0x800) ||
			(need == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
			(cp >= 0xD800 && cp <= 0xDFFF) ||
			cp == 0xFFFD ||
			(cp < 0x20) || (cp >= 0x7F && cp <= 0x9F)) {
			for (size_t j = 0; j < need; ++j) {
				hex_append(p[idx + j]);
			}
			idx += need;
			continue;
		}

		safe.append(selected, static_cast<size_t>(idx), static_cast<size_t>(need));
		idx += need;
	}

	return safe;
}

static inline std::string build_brain_selected_label(const char* found_string, const uint32_t reported_len, const uint32_t iter_value) {
	std::string selected = load_found_text_sanitized(found_string, reported_len, 511);
	selected = sanitize_brain_visible_text(std::move(selected));
	selected += ":hex(";
	selected += build_hex_bytes_lower(reinterpret_cast<const uint8_t*>(found_string), reported_len);
	selected += "):ITERATION ";
	selected += std::to_string(iter_value);
	return selected;
}

static inline std::string build_mode_selected_head(const char* mode,
	const std::string& selected,
	const bool stdout_head,
	const bool add_space_after_mode_colon = false,
	const std::string& selected_open_suffix = std::string()) {
	const size_t mode_len = (mode == nullptr) ? 0u : std::strlen(mode);
	if (save_crypted_output_enabled()) {
		std::string head;
		if (stdout_head) {
			head = "\n[!] Found: ";
		}
		if (mode_len != 0u) {
			head.append(mode, mode_len);
			head.push_back(':');
			if (add_space_after_mode_colon) {
				head.push_back(' ');
			}
		}
		head += crypted_protect_output_text(selected);
		head += selected_open_suffix;
		head.push_back(':');
		return head;
	}

	std::string head;
	head.reserve(selected.size() + selected_open_suffix.size() + mode_len + (stdout_head ? 12u : 2u) + (add_space_after_mode_colon ? 1u : 0u));
	if (stdout_head) {
		head = "\n[!] Found: ";
	}
	if (mode_len != 0u) {
		head.append(mode, mode_len);
	}
	head.push_back(':');
	if (add_space_after_mode_colon) {
		head.push_back(' ');
	}
	head += selected;
	head += selected_open_suffix;
	head.push_back(':');
	return head;
}

static inline std::string build_brain_gen_selected_label(const char* found_string,
	const uint32_t reported_len,
	const uint32_t iter_value,
	const int bytes,
	const int mode,
	const int gen,
	const int skip_bytes,
	const uint64_t seed_value) {
	std::string selected = build_brain_selected_label(found_string, reported_len, iter_value);
	std::ostringstream oss;
	oss << "Byte " << bytes << ":Shift " << skip_bytes << ":Gen " << gen << ":Mode " << mode;
	oss << ":Seed " << std::hex << std::nouppercase << seed_value;
	selected += oss.str();
	return selected;
}

struct StandardKeyEmitHeads {
	std::string file_head;
	std::string stdout_default_head;
	std::string stdout_sol_head;
	std::string stdout_ton_head;
};

static inline std::string load_bip39_pass_slot(char (*foundPass)[128], uint16_t* foundPassSize, const uint64_t index) {
	if (foundPass == nullptr || foundPassSize == nullptr || foundPassSize[index] == 0) {
		return std::string();
	}
	std::string pass = load_found_text_sanitized(&foundPass[index][0], foundPassSize[index], 127);
	return sanitize_visible_utf8(std::move(pass));
}

static inline bool same_found_selected_text(char (*foundStrings)[512],
	uint32_t(*len_h)[1],
	const uint64_t lhs,
	const uint64_t rhs) {
	if (foundStrings == nullptr || len_h == nullptr || len_h[lhs][0] != len_h[rhs][0]) {
		return false;
	}
	return std::memcmp(&foundStrings[lhs][0], &foundStrings[rhs][0], len_h[lhs][0]) == 0;
}

static inline std::string resolve_bip39_pass_text(char (*foundPass)[128],
	uint16_t* foundPassSize,
	char (*foundStrings)[512],
	uint32_t(*len_h)[1],
	const uint64_t index,
	const uint64_t count) {
	std::string pass = load_bip39_pass_slot(foundPass, foundPassSize, index);
	if (!pass.empty()) {
		return pass;
	}

	if (foundPass != nullptr && foundPassSize != nullptr && foundStrings != nullptr && len_h != nullptr) {
		for (uint64_t j = index; j > 0; --j) {
			const uint64_t probe = j - 1u;
			if (foundPassSize[probe] != 0 && same_found_selected_text(foundStrings, len_h, index, probe)) {
				pass = load_bip39_pass_slot(foundPass, foundPassSize, probe);
				if (!pass.empty()) {
					return pass;
				}
			}
		}
		for (uint64_t probe = index + 1u; probe < count; ++probe) {
			if (foundPassSize[probe] != 0 && same_found_selected_text(foundStrings, len_h, index, probe)) {
				pass = load_bip39_pass_slot(foundPass, foundPassSize, probe);
				if (!pass.empty()) {
					return pass;
				}
			}
		}
	}

	if (passwords_list.size() == 1u) {
		pass = passwords_list[0];
		if (pass.size() > 128u) {
			pass.resize(128u);
		}
		return sanitize_visible_utf8(std::move(pass));
	}

	return std::string();
}

static inline std::string build_bip39_pass_derivation_prefix(char (*foundPass)[128],
	uint16_t* foundPassSize,
	char (*foundStrings)[512],
	uint32_t(*len_h)[1],
	const uint64_t index,
	const uint64_t count) {
	std::string out = "bip39_pass(";
	out += resolve_bip39_pass_text(foundPass, foundPassSize, foundStrings, len_h, index, count);
	out += "):";
	return out;
}

static inline std::string build_standard_worker_head(const std::string& prefix,
	const std::string& selected,
	const std::string& found_der,
	const std::string& selected_open_suffix = std::string()) {
	if (save_crypted_output_enabled()) {
		const bool stdout_banner = (prefix == "\n[!] Found: ");
		std::string out;
		const std::string protected_input = crypted_protect_output_text(selected);
		out.reserve(prefix.size() + protected_input.size() + selected_open_suffix.size() + found_der.size() + 2u);
		if (stdout_banner || !prefix.empty()) {
			out += prefix;
		}
		out += protected_input;
		out += selected_open_suffix;
		out.push_back(':');
		out += found_der;
		out.push_back(':');
		return out;
	}

	std::string out;
	out.reserve(prefix.size() + selected.size() + selected_open_suffix.size() + found_der.size() + 2u);
	out += prefix;
	out += selected;
	out += selected_open_suffix;
	out.push_back(':');
	out += found_der;
	out.push_back(':');
	return out;
}

static inline StandardKeyEmitHeads make_standard_key_emit_heads(const std::string& file_prefix,
	const std::string& selected,
	const std::string& found_der,
	const std::string& stdout_default_prefix,
	const std::string& stdout_sol_prefix = std::string(),
	const std::string& stdout_ton_prefix = std::string(),
	const std::string& selected_open_suffix = std::string()) {
	StandardKeyEmitHeads heads;
	heads.file_head = build_standard_worker_head(file_prefix, selected, found_der, selected_open_suffix);
	heads.stdout_default_head = build_standard_worker_head(stdout_default_prefix, selected, found_der, selected_open_suffix);
	heads.stdout_sol_head = heads.stdout_default_head;
	heads.stdout_ton_head = heads.stdout_default_head;
	return heads;
}

static inline StandardKeyEmitHeads make_standard_key_emit_heads_explicit(const std::string& file_head,
	const std::string& stdout_default_head,
	const std::string& stdout_sol_head = std::string(),
	const std::string& stdout_ton_head = std::string()) {
	StandardKeyEmitHeads heads;
	heads.file_head = file_head;
	heads.stdout_default_head = stdout_default_head;
	heads.stdout_sol_head = stdout_default_head;
	heads.stdout_ton_head = stdout_default_head;
	return heads;
}

static inline const std::string& select_standard_stdout_head(const StandardKeyEmitHeads& heads, const uint8_t coin_type) {
	return heads.stdout_default_head;
}

static inline void emit_mode_result_line(FILE* file,
	const std::string& file_head,
	const std::string& file_key_segment,
	const char* type,
	const std::string& payload,
	const std::string& stdout_head,
	const std::string& stdout_key_segment,
	const bool stdout_add_newline,
	const bool silent,
	const bool omit_key_segment = false) {
	(void)save_output_write_prebuilt(file, build_result_line_with_newline(file_head, file_key_segment, type, payload, true, omit_key_segment));
	if (!silent) {
		(void)save_output_write_prebuilt(stdout, build_result_line_with_newline(stdout_head, stdout_key_segment, type, payload, stdout_add_newline, omit_key_segment));
	}
}

static inline void emit_mode_result_line(FILE* file,
	const std::string& file_head,
	const std::string& key_segment,
	const char* type,
	const std::string& payload,
	const std::string& stdout_head,
	const bool silent,
	const bool stdout_add_newline = true,
	const bool omit_key_segment = false) {
	emit_mode_result_line(file, file_head, key_segment, type, payload, stdout_head, key_segment, stdout_add_newline, silent, omit_key_segment);
}


static inline bool save_postcheck_coin_is_ada(const uint8_t coin_type) {
	return (coin_type >= 0x10 && coin_type <= 0x19);
}

static inline bool save_postcheck_coin_is_ada_base_pair(const uint8_t coin_type) {
	return coin_type == 0x11 || coin_type == 0x18;
}

static inline size_t save_postcheck_cardano_pointer_raw_len(const uint8_t* raw) {
	const size_t max_len = 80;
	size_t off = 29;
	for (int field = 0; field < 3; ++field) {
		if (off >= max_len) {
			return 34;
		}
		for (;;) {
			const uint8_t b = raw[off++];
			if ((b & 0x80u) == 0u) {
				break;
			}
			if (off >= max_len) {
				return 34;
			}
		}
	}
	return off;
}

static inline size_t save_postcheck_cardano_byron_raw_len(const uint8_t* raw, const size_t fallback) {
	const size_t max_len = 80;
	if (raw == nullptr || raw[0] != 0x82u) {
		return fallback;
	}

	size_t off = 1;
	if (off + 2 > max_len || raw[off] != 0xd8u || raw[off + 1] != 0x18u) {
		return fallback;
	}
	off += 2;

	if (off >= max_len || (raw[off] & 0xe0u) != 0x40u) {
		return fallback;
	}
	const uint8_t add = raw[off++] & 0x1fu;
	size_t payload_len = 0;
	if (add <= 23u) {
		payload_len = add;
	}
	else if (add == 24u) {
		if (off >= max_len) return fallback;
		payload_len = raw[off++];
	}
	else if (add == 25u) {
		if (off + 2 > max_len) return fallback;
		payload_len = (static_cast<size_t>(raw[off]) << 8) | raw[off + 1];
		off += 2;
	}
	else {
		return fallback;
	}
	if (payload_len > max_len || off + payload_len > max_len) {
		return fallback;
	}
	off += payload_len;

	if (off >= max_len || (raw[off] & 0xe0u) != 0x00u) {
		return fallback;
	}
	const uint8_t crc_add = raw[off++] & 0x1fu;
	if (crc_add <= 23u) {
		return off;
	}
	if (crc_add == 24u && off + 1 <= max_len) {
		return off + 1;
	}
	if (crc_add == 25u && off + 2 <= max_len) {
		return off + 2;
	}
	if (crc_add == 26u && off + 4 <= max_len) {
		return off + 4;
	}
	return fallback;
}

static inline size_t save_postcheck_ada_raw_len(const uint8_t coin_type, const uint8_t* raw) {
	switch (coin_type) {
	case 0x10: return save_postcheck_cardano_byron_raw_len(raw, 43);
	case 0x11: return 57;
	case 0x12: return 29;
	case 0x13: return save_postcheck_cardano_byron_raw_len(raw, 76);
	case 0x14: return 29;
	case 0x15: return save_postcheck_cardano_pointer_raw_len(raw);
	case 0x16: return 57;
	case 0x17: return save_postcheck_cardano_byron_raw_len(raw, 43);
	case 0x18: return 57;
	case 0x19: return save_postcheck_cardano_byron_raw_len(raw, 76);
	default: return 32;
	}
}

static inline bool save_cpu_postcheck_and_count(uint32_t* pFounds, const uint32_t(*foundHash160)[20], const uint64_t index, const uint8_t coin_type) {
	if (g_save_cpu_postcheck_suppression_depth.load(std::memory_order_acquire) <= 0 && (useBloomCPU || useXorCPU)) {
		hash160_t to_check{};
		const uint8_t* raw = reinterpret_cast<const uint8_t*>(&foundHash160[index]);
		const uint8_t base_type = endo_base_type_or_self(coin_type);
		if (save_postcheck_coin_is_ada(base_type)) {
			uint8_t ada_hash[32] = { 0 };
			sha256(const_cast<uint8_t*>(raw), save_postcheck_ada_raw_len(base_type, raw), ada_hash);
			memcpy(&to_check.ul, ada_hash, 32);
		}
		else if (base_type == 0x07) {
			uint8_t p2wsh_rmd[20] = { 0 };
			ripemd160_32(const_cast<uint8_t*>(raw), p2wsh_rmd);
			memcpy(&to_check.uc, p2wsh_rmd, 20);
		}
		else {
			memcpy(&to_check.ul, raw, 32);
		}
		if (!save_worker_find_in_bloom(to_check)) {
			increment_false_positive();
			return false;
		}
	}
	increment_founds(pFounds);
	return true;
}

static inline bool save_metal_check(const metalError_t st, const char* stage, const char* op) {
	if (st == metalSuccess) {
		return true;
	}
	::fprintf(stderr, "\n[!] SaveFunc Metal error at stage '%s' for %s: %s (%s)\n",
		stage, op, metalGetErrorName(st), metalGetErrorString(st));
	return false;
}

static inline bool save_load_results_count(const char* stage, unsigned long long& resultsCountHost) {
	return save_metal_check(metalReadStateValue(&resultsCountHost, d_resultsCount, sizeof(resultsCountHost), 0, metalMemcpyDeviceToHost), stage, "metalReadStateValue(d_resultsCount)");
}

static inline bool save_store_results_count_zero(const char* stage) {
	const unsigned long long zero = 0ull;
	return save_metal_check(metalWriteStateValue(d_resultsCount, &zero, sizeof(zero), 0, metalMemcpyHostToDevice), stage, "metalWriteStateValue(d_resultsCount=0)");
}

static inline void save_clear_results_count_best_effort(const char* stage) {
	(void)save_store_results_count_zero(stage);
}

#define SAVE_METAL_OR_RETURN(stage, expr) do { if (!save_metal_check((expr), (stage), #expr)) return; } while (0)
#define SAVE_METAL_OR_GOTO(stage, expr, label) do { if (!save_metal_check((expr), (stage), #expr)) goto label; } while (0)

// Local helpers for scalar_mult_mod_n_256 keep this translation unit self-contained.
static inline int cmp_be(const uint8_t* x, const uint8_t* y, size_t n) {
	for (size_t i = 0; i < n; ++i) { if (x[i] != y[i]) return (x[i] < y[i]) ? -1 : 1; }
	return 0;
}
// sub_be: subtracts be.
static inline void sub_be(const uint8_t* x, const uint8_t* y, uint8_t* out, size_t n) {
	int b = 0; for (size_t i = n; i-- > 0;) { int t = (int)x[i] - (int)y[i] - b; if (t < 0) { t += 256; b = 1; } else b = 0; out[i] = (uint8_t)t; }
}
// add_be: adds be.
static inline void add_be(const uint8_t* x, const uint8_t* y, uint8_t* out, size_t n) {
	int c = 0; for (size_t i = n; i-- > 0;) { int t = (int)x[i] + (int)y[i] + c; out[i] = (uint8_t)(t & 0xFF); c = t >> 8; }
}

// SECP256K1 endomorphism: decode result tags and reconstruct the canonical private key.
// Tag format is defined in KernelRuntime.h:
// type = ENDO_TAG_BASE + ENDO_GROUP_STRIDE * group + variant.
static const uint8_t SECP256K1_N[32] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
	0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};
static const uint8_t SECP256K1_LAMBDA[32] = {
	0x53,0x63,0xAD,0x4C,0xC0,0x5C,0x30,0xE0,0xA5,0x26,0x1C,0x02,0x88,0x12,0x64,0x5A,
	0x12,0x2E,0x22,0xEA,0x20,0x81,0x66,0x78,0xDF,0x02,0x96,0x7C,0x1B,0x23,0xBD,0x72
};
static const uint8_t SECP256K1_LAMBDA2[32] = {
	0xAC,0x9C,0x52,0xB3,0x3F,0xA3,0xAD,0x48,0x58,0xA6,0x05,0x9F,0x6D,0x6C,0x42,0x98,
	0xD4,0xE4,0x4B,0x54,0x91,0x04,0x33,0xB1,0xF8,0xC0,0x06,0x2D,0xD3,0x1E,0x8C,0xC0
};
// r = k * mult mod n. For each bit of k (MSB first): r=2*r; if(bit) r+=mult; r%=n
// Uses 33-byte buffer for additions to avoid overflow (2*max(r) + mult can need 257 bits)
static void scalar_mult_mod_n_256(const uint8_t k_be[32], const uint8_t mult_be[32], uint8_t out_be[32]) {
	uint8_t r[33] = {0}, t[33];
	uint8_t n_pad[33]; memcpy(n_pad, SECP256K1_N, 32); n_pad[32] = 0;
	uint8_t mult_pad[33]; memcpy(mult_pad, mult_be, 32); mult_pad[32] = 0;
	for (int bi = 0; bi < 256; bi++) {
		int by = bi / 8, br = 7 - (bi % 8);
		int set = (k_be[by] >> br) & 1;
		add_be(r, r, t, 33);
		memcpy(r, t, 33);
		if (set) {
			add_be(r, mult_pad, t, 33);
			memcpy(r, t, 33);
		}
		while (cmp_be(r, n_pad, 33) >= 0) {
			sub_be(r, n_pad, t, 33);
			memcpy(r, t, 33);
		}
	}
	memcpy(out_be, r, 32);
}

// Returns true when a 32-byte big-endian scalar is zero.
static inline bool is_zero_be32(const uint8_t* x) {
	for (int i = 0; i < 32; ++i) {
		if (x[i] != 0) return false;
	}
	return true;
}

// Computes out = (n - in) mod n for secp256k1 order n.
static inline void negate_mod_n_256(const uint8_t in_be[32], uint8_t out_be[32]) {
	if (is_zero_be32(in_be)) {
		memset(out_be, 0, 32);
		return;
	}
	sub_be(SECP256K1_N, in_be, out_be, 32);
}

// Decodes encoded endomorphism result tag into display type and key transform metadata.
static inline bool decode_endo_tag(uint8_t type, uint8_t& base_type, uint8_t& lambda_sel, bool& negate) {
	if (type < ENDO_TAG_BASE) return false;
	const uint8_t code = (uint8_t)(type - ENDO_TAG_BASE);
	const uint8_t group = (uint8_t)(code / ENDO_GROUP_STRIDE);
	const uint8_t variant = (uint8_t)(code % ENDO_GROUP_STRIDE);
	if (group > ENDO_GROUP_P2WSH) return false;
	if (variant > ENDO_VARIANT_ENDO2_NEG) return false;

	switch (group) {
	case ENDO_GROUP_COMPRESSED: base_type = 0x02; break;
	case ENDO_GROUP_SEGWIT: base_type = 0x03; break;
	case ENDO_GROUP_UNCOMPRESSED: base_type = 0x01; break;
	case ENDO_GROUP_ETH: base_type = 0x06; break;
	case ENDO_GROUP_TAPROOT: base_type = 0x04; break;
	case ENDO_GROUP_XPOINT: base_type = 0x05; break;
	case ENDO_GROUP_P2WSH: base_type = 0x07; break;
	default: return false;
	}

	lambda_sel = 0;
	negate = false;
	switch (variant) {
	case ENDO_VARIANT_BASE_POS:
		break;
	case ENDO_VARIANT_BASE_NEG:
		negate = true;
		break;
	case ENDO_VARIANT_ENDO1_POS:
		lambda_sel = 1;
		break;
	case ENDO_VARIANT_ENDO1_NEG:
		lambda_sel = 1;
		negate = true;
		break;
	case ENDO_VARIANT_ENDO2_POS:
		lambda_sel = 2;
		break;
	case ENDO_VARIANT_ENDO2_NEG:
		lambda_sel = 2;
		negate = true;
		break;
	default:
		return false;
	}
	return true;
}

// Resolves encoded endomorphism tag to its base output type, or returns original type.
static inline uint8_t endo_base_type_or_self(uint8_t type) {
	uint8_t base_type = type;
	uint8_t lambda_sel = 0;
	bool negate = false;
	if (decode_endo_tag(type, base_type, lambda_sel, negate)) {
		return base_type;
	}
	return type;
}

// Reconstructs canonical private key for endomorphism-derived hit variants.
static void fix_endo_key(const uint8_t key_in[32], uint8_t key_out[32], uint8_t endo_type) {
	uint8_t base_type = 0;
	uint8_t lambda_sel = 0;
	bool negate = false;
	if (!decode_endo_tag(endo_type, base_type, lambda_sel, negate)) {
		// Legacy compatibility: older builds used 0xC2 for endo2.
		if (endo_type == 0xC2) {
			scalar_mult_mod_n_256(key_in, SECP256K1_LAMBDA2, key_out);
			return;
		}
		memcpy(key_out, key_in, 32);
		return;
	}

	uint8_t tmp[32];
	if (lambda_sel == 1) scalar_mult_mod_n_256(key_in, SECP256K1_LAMBDA, tmp);
	else if (lambda_sel == 2) scalar_mult_mod_n_256(key_in, SECP256K1_LAMBDA2, tmp);
	else memcpy(tmp, key_in, 32);

	if (negate) negate_mod_n_256(tmp, key_out);
	else memcpy(key_out, tmp, 32);
}

static inline const char* byte_to_coin(uint8_t coin, bool& ed)
{
	switch (coin)
	{
		// BTC, ETH, Secp256k1 PubKey
	case 0x01: return "UNCOMPRESSED";
	case 0x02: return "COMPRESSED";
	case 0x03: return "SEGWIT";
	case 0x04: return "TAPROOT";
	case 0x05: return "XPOINT";
	case 0x06: return "ETH";
	case 0x07: return "P2WSH";
		// Cardano
	case 0x10: ed = true; return "ADA(Byron Icarus)";
	case 0x11: ed = true; return "ADA(Shelley Base)";
	case 0x12: ed = true; return "ADA(Shelley Enterprise)";
	case 0x13: ed = true; return "ADA(Byron Daedalus)";
	case 0x14: ed = true; return "ADA(Shelley Reward)";
	case 0x15: ed = true; return "ADA(Shelley Pointer)";
	case 0x16: ed = true; return "ADA(Shelley Exodus)";
	case 0x17: ed = true; return "ADA(Byron Ledger)";
	case 0x18: ed = true; return "ADA(Shelley Ledger)";
	case 0x19: ed = true; return "ADA(Byron Legacy)";
		// Aptos
	case 0x20: ed = true; return "APTOS(Legacy ed25519)";
	case 0x21: ed = true; return "APTOS(Generalized ed25519)";
	case 0x22: return "APTOS(Generalized secp256k1)";
		// Polkadot
	case 0x30: ed = true; return "DOT(ed25519)";
	case 0x31: ed = true; return "DOT(sr25519)";
		// Exodus (ed25519)
	case 0x40: ed = true; return "ED25519(EXODUS)";
		// Filecoin
	case 0x41: return "FIL(f1)";
	case 0x42: return "FIL(f4)";
		// IOTA
	case 0x50: return "IOTA(secp256k1)";
	case 0x51: ed = true; return "IOTA(ed25519)";
		// ICP
	case 0x52: ed = true; return "ICP(ed25519)";
	case 0x53: return "ICP(secp256k1)";
		// Solana
	case 0x60: ed = true; return "SOLANA";
		// Sui
	case 0x70: return "SUI(secp256k1)";
	case 0x71: ed = true; return "SUI(ed25519)";
		// TON
	case 0x80: ed = true; return "TON(v1r1)";
	case 0x81: ed = true; return "TON(v1r2)";
	case 0x82: ed = true; return "TON(v1r3)";
	case 0x83: ed = true; return "TON(v2r1)";
	case 0x84: ed = true; return "TON(v2r2)";
	case 0x85: ed = true; return "TON(v3r1)";
	case 0x86: ed = true; return "TON(v3r2)";
	case 0x87: ed = true; return "TON(v4r1)";
	case 0x88: ed = true; return "TON(v4r2)";
	case 0x89: ed = true; return "TON(v5r1)";
	case 0x8a: ed = true; return "TON(hv1)";
	case 0x8b: ed = true; return "TON(hv2)";
	case 0x8c: ed = true; return "TON(hv3)";
		// XRP
	case 0x90: return "XRP(secp256k1)";
	case 0x91: ed = true; return "XRP(ed25519)";
		//XTZ
	case 0x92: return "XTZ(secp256k1)"; //XTZ2
	case 0x93: ed = true; return "XTZ(ed25519)"; //XTZ1
	default:   return "UNKNOWN";
	}
}


static bool Silent = false;
static bool BIP39_Pass = false;
bool STOP_THREAD = false;

std::atomic<uint64_t> false_positive{0};

// Host helper: setSilentMode.
METAL_HOST void setSilentMode()
{

	Silent = true;
}

// Host helper: setPassMode.
METAL_HOST void setPassMode()
{

	BIP39_Pass = true;
}

// append_ed25519_round_tag: appends ed 25519 round tag.
static inline void append_ed25519_round_tag(std::string& round, bool is_ed)
{
	if (!is_ed) {
		return;
	}
	if (is_ed25519_scalar) {
		round += " (ed25519 scalar)";
	}
	else if (is_ed25519_hash) {
		round += " (ed25519 hash)";
	}
}

// reverseByteOrderHost: reverses byte order host.
uint32_t reverseByteOrderHost(uint32_t val) {
	return ((val & 0xFF) << 24) |
		((val & 0xFF00) << 8) |
		((val & 0xFF0000) >> 8) |
		((val & 0xFF000000) >> 24);
}

const char* const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string encodeBase58_d(const uint8_t* bytes, size_t length) {
	if (!bytes || length == 0) return std::string();

	size_t zeros = 0;
	while (zeros < length && bytes[zeros] == 0) zeros++;


	std::vector<uint8_t> b58;
	b58.reserve((length - zeros) * 138 / 100 + 1);

	for (size_t i = zeros; i < length; ++i) {
		uint32_t carry = bytes[i];
		for (size_t j = 0; j < b58.size(); ++j) {
			uint32_t x = (uint32_t)b58[j] * 256u + carry;
			b58[j] = (uint8_t)(x % 58u);
			carry = (uint32_t)(x / 58u);
		}
		while (carry > 0) {
			b58.push_back((uint8_t)(carry % 58u));
			carry /= 58u;
		}
	}

	std::string out;
	out.reserve(zeros + b58.size());
	out.append(zeros, '1');

	for (size_t i = 0; i < b58.size(); ++i) {
		out.push_back(ALPHABET[b58[b58.size() - 1 - i]]);
	}

	return out;

}

const char* const RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

// encodeBase58_d_XRP: encodes Base58 d XRP.
std::string encodeBase58_d_XRP(const uint8_t* bytes, size_t length) {
	if (!bytes || length == 0) return std::string();

	size_t zeros = 0;
	while (zeros < length && bytes[zeros] == 0) zeros++;

	std::vector<uint8_t> b58;
	b58.reserve((length - zeros) * 138 / 100 + 1);

	for (size_t i = zeros; i < length; ++i) {
		uint32_t carry = bytes[i];
		for (size_t j = 0; j < b58.size(); ++j) {
			uint32_t x = (uint32_t)b58[j] * 256u + carry;
			b58[j] = (uint8_t)(x % 58u);
			carry = (uint32_t)(x / 58u);
		}
		while (carry > 0) {
			b58.push_back((uint8_t)(carry % 58u));
			carry /= 58u;
		}
	}

	std::string out;
	out.reserve(zeros + b58.size());
	out.append(zeros, RIPPLE_ALPHABET[0]);
	for (size_t i = 0; i < b58.size(); ++i) {
		out.push_back(RIPPLE_ALPHABET[b58[b58.size() - 1 - i]]);
	}
	return out;
}

std::string hash160ToBase58_d(const uint8_t hash160[20], uint8_t prefix) {
	uint8_t extended[25];
	extended[0] = prefix;
	memcpy(&extended[1], hash160, 20);

	uint8_t hash[32];
	sha256(extended, 21, hash);
	sha256(hash, 32, hash);

	memcpy(&extended[21], hash, 4);
	return encodeBase58_d(extended, 25);
}

std::string hash160ToXRP(const uint8_t hash160[20], uint8_t prefix) {
	uint8_t extended[25];
	extended[0] = prefix;
	memcpy(&extended[1], hash160, 20);

	uint8_t hash[32];
	sha256(extended, 21, hash);
	sha256(hash, 32, hash);

	memcpy(&extended[21], hash, 4);
	return encodeBase58_d_XRP(extended, 25);
}

uint32_t bech32_polymod_step_d(uint32_t pre) {
	uint8_t b = pre >> 25;
	return ((pre & 0x1FFFFFF) << 5) ^
		(-((b >> 0) & 1) & 0x3b6a57b2UL) ^
		(-((b >> 1) & 1) & 0x26508e6dUL) ^
		(-((b >> 2) & 1) & 0x1ea119faUL) ^
		(-((b >> 3) & 1) & 0x3d4233ddUL) ^
		(-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t charset_rev[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
			-1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
			1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
			-1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
			1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

// bech32_encode: encodes the related data for Bech32.
int bech32_encode(char* output, const char* hrp, const uint8_t* data, size_t data_len, bool bech32m = false) {
	uint32_t chk = 1;
	size_t i = 0;
	while (hrp[i] != 0) {
		int ch = hrp[i];
		if (ch < 33 || ch > 126) {
			return 0;
		}

		if (ch >= 'A' && ch <= 'Z') return 0;
		chk = bech32_polymod_step_d(chk) ^ (ch >> 5);
		++i;
	}
	chk = bech32_polymod_step_d(chk);
	while (*hrp != 0) {
		chk = bech32_polymod_step_d(chk) ^ (*hrp & 0x1f);
		*(output++) = *(hrp++);
	}
	*(output++) = '1';
	for (i = 0; i < data_len; ++i) {
		if (*data >> 5) return 0;
		chk = bech32_polymod_step_d(chk) ^ (*data);
		*(output++) = charset[*(data++)];
	}
	for (i = 0; i < 6; ++i) {
		chk = bech32_polymod_step_d(chk);
	}
	chk ^= (bech32m ? 0x2bc830a3u : 1u);
	for (i = 0; i < 6; ++i) {
		*(output++) = charset[(chk >> ((5 - i) * 5)) & 0x1f];
	}
	*output = 0;
	return 1;
}

// convert_bits: converts bits.
static int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad) {
	uint32_t val = 0;
	int bits = 0;
	uint32_t maxv = (((uint32_t)1) << outbits) - 1;
	while (inlen--) {
		val = (val << inbits) | *(in++);
		bits += inbits;
		while (bits >= outbits) {
			bits -= outbits;
			out[(*outlen)++] = (val >> bits) & maxv;
		}
	}
	if (pad) {
		if (bits) {
			out[(*outlen)++] = (val << (outbits - bits)) & maxv;
		}
	}
	else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
		return 0;
	}
	return 1;
}

// segwit_addr_encode: encodes the related data for segwit addr.
int segwit_addr_encode(char* output, const char* hrp, uint16_t witver, const uint8_t* witprog, size_t witprog_len) {
	uint8_t data[65] = { 0 };
	size_t datalen = 0;
	if (witver > 16) return 0;
	if (witver == 0 && witprog_len != 20 && witprog_len != 32) return 0;
	if (witprog_len < 2 || witprog_len > 40) return 0;
	data[0] = witver;
	convert_bits(data + 1, &datalen, 5, witprog, witprog_len, 8, 1);
	++datalen;
	bool use_bech32m = witver != 0;
	return bech32_encode(output, hrp, data, datalen, use_bech32m);
}

int cardano_shelley_addr_encode(char* output, const char* hrp,
	const uint8_t* addr_bytes, size_t addr_len)
{
	uint8_t data[256];
	size_t datalen = 0;

	if (!convert_bits(data, &datalen, 5, addr_bytes, addr_len, 8, 1))
		return 0;

	return bech32_encode(output, hrp, data, datalen, /*bech32m=*/false);
}
int iota_bech32(char* out, const char* hrp, const uint8_t* raw_addr, uint8_t version)
{
	uint8_t data5[80];
	size_t  data5_len = 0;

	uint8_t data_prepared[33];
	memcpy(&data_prepared[1], raw_addr, 32);
	data_prepared[0] = version;

	convert_bits(data5, &data5_len, 5, data_prepared, 33, 8, 1);
	return bech32_encode(out, hrp, data5, data5_len, /*bech32m=*/false);

}

// bech32_decode_nocheck_d: decodes nocheck d for Bech32.
int bech32_decode_nocheck_d(uint8_t* data, size_t* data_len, const char* input)
{

	uint8_t acc = 0;
	uint8_t acc_len = 8;
	size_t out_len = 0;

	size_t input_len = strlen(input);
	for (int i = 0; i < input_len; i++) {

		if (input[i] & 0x80)
			return false;

		int8_t c = charset_rev[tolower(input[i])];
		if (c < 0)
			return false;

		if (acc_len >= 5) {
			acc |= c << (acc_len - 5);
			acc_len -= 5;
		}
		else {
			int shift = 5 - acc_len;
			data[out_len++] = acc | (c >> shift);
			acc_len = 8 - shift;
			acc = c << acc_len;
		}

	}

	data[out_len++] = acc;
	*data_len = out_len;

	return true;

}

const uint16_t CRC16_POLY = 0x1021;
const uint16_t CRC_INIT = 0x0000;
uint16_t crc16(const std::vector<uint8_t>& data) {
	uint16_t crc = CRC_INIT;
	for (uint8_t byte : data) {
		crc ^= static_cast<uint16_t>(byte) << 8;
		for (int i = 0; i < 8; ++i) {
			if (crc & 0x8000) {
				crc = (crc << 1) ^ CRC16_POLY;
			}
			else {
				crc <<= 1;
			}
		}
	}
	return crc & 0xFFFF;
}

const std::string BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// base64_encode: encodes the related data for Base64.
std::string base64_encode(const std::vector<uint8_t>& input) {
	std::string encoded;
	encoded.reserve(((input.size() + 2) / 3) * 4);
	int i = 0;
	int j = 0;
	uint8_t char_array_3[3];
	uint8_t char_array_4[4];

	for (uint8_t byte : input) {
		char_array_3[i++] = byte;
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; i < 4; i++) {
				encoded.push_back(BASE64_CHARS[char_array_4[i]]);
			}
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 3; j++) {
			char_array_3[j] = '\0';
		}

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

		for (j = 0; j < i + 1; j++) {
			encoded.push_back(BASE64_CHARS[char_array_4[j]]);
		}

		while (i++ < 3) {
			encoded.push_back('=');
		}
	}

	return encoded;
}

const uint8_t BOUNCEABLE_TAG = 0x11;
const uint8_t NON_BOUNCEABLE_TAG = 0x51;
const uint8_t TEST_FLAG = 0x80;

// generate_ton_address: generates TON address.
std::string generate_ton_address(const uint8_t* hash, bool is_testnet = false, bool is_bounceable = false, int8_t workchain = 0) {
	std::vector<uint8_t> address_data;
	address_data.reserve(36);

	address_data.push_back(is_bounceable ? BOUNCEABLE_TAG : NON_BOUNCEABLE_TAG);
	if (is_testnet) {
		address_data[0] |= TEST_FLAG;
	}

	address_data.push_back(workchain);
	address_data.insert(address_data.end(), hash, hash + 32);

	uint16_t checksum = crc16(address_data);
	address_data.push_back(static_cast<uint8_t>(checksum >> 8));
	address_data.push_back(static_cast<uint8_t>(checksum & 0xFF));

	return base64_encode(address_data);
}

static inline bool ss58_prefix_bytes(const int prefix, std::vector<uint8_t>& out) {
	if (prefix < 0 || prefix > 16383) {
		return false;
	}
	if (prefix < 64) {
		out.push_back(static_cast<uint8_t>(prefix));
		return true;
	}
	out.push_back(static_cast<uint8_t>(((prefix & 0x00fc) >> 2) | 0x40));
	out.push_back(static_cast<uint8_t>((prefix >> 8) | ((prefix & 0x0003) << 6)));
	return true;
}

// ss58Address: encodes raw 32-byte Substrate account id with an explicit SS58 prefix.
std::string ss58Address(const uint8_t pubKey[32], const int prefix) {
	std::vector<uint8_t> data;
	data.reserve(36);
	if (!ss58_prefix_bytes(prefix, data)) {
		data.push_back(0x00);
	}
	data.insert(data.end(), pubKey, pubKey + 32);

	const char* prefixStr = "SS58PRE";
	std::vector<uint8_t> checksumInput;
	checksumInput.reserve(std::strlen(prefixStr) + data.size());
	checksumInput.insert(checksumInput.end(), prefixStr, prefixStr + std::strlen(prefixStr));
	checksumInput.insert(checksumInput.end(), data.begin(), data.end());

	uint8_t hash[64] = { 0 };
	blake2b(checksumInput.data(), checksumInput.size(), hash, 64);

	data.push_back(hash[0]);
	data.push_back(hash[1]);

	return encodeBase58_d(data.data(), data.size());
}

static inline bool is_ada_dot_coin(const uint8_t coin_type) {
	return (coin_type >= 0x10 && coin_type <= 0x19) || coin_type == 0x30 || coin_type == 0x31;
}

static inline size_t cardano_pointer_raw_len(const uint8_t* raw) {
	const size_t max_len = 80;
	size_t off = 29;
	for (int field = 0; field < 3; ++field) {
		if (off >= max_len) {
			return 34;
		}
		for (;;) {
			const uint8_t b = raw[off++];
			if ((b & 0x80u) == 0u) {
				break;
			}
			if (off >= max_len) {
				return 34;
			}
		}
	}
	return off;
}

static inline std::string ada_or_dot_address(const uint8_t coin_type, const uint8_t* raw) {
	if (coin_type == 0x30 || coin_type == 0x31) {
		return build_hex_bytes_lower(raw, 32);
	}
	if (coin_type == 0x10) {
		return encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 43));
	}
	if (coin_type == 0x17) {
		return encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 43));
	}
	if (coin_type == 0x13 || coin_type == 0x19) {
		return encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 76));
	}

	char output[160] = { 0 };
	if (coin_type == 0x11 || coin_type == 0x18) {
		cardano_shelley_addr_encode(output, "addr", raw, 57);
		return std::string(output);
	}
	if (coin_type == 0x16) {
		cardano_shelley_addr_encode(output, "addr", raw, 57);
		return std::string(output);
	}
	if (coin_type == 0x12) {
		cardano_shelley_addr_encode(output, "addr", raw, 29);
		return std::string(output);
	}
	if (coin_type == 0x14) {
		cardano_shelley_addr_encode(output, "stake", raw, 29);
		return std::string(output);
	}
	if (coin_type == 0x15) {
		cardano_shelley_addr_encode(output, "addr", raw, cardano_pointer_raw_len(raw));
		return std::string(output);
	}
	return std::string();
}

static inline std::string build_key_segment_ada_dot(const uint8_t* priv_key, const uint8_t coin_type, const std::string& round) {
	std::string key_round = round;
	if (save_postcheck_coin_is_ada(coin_type) && coin_type != 0x16 && is_ed25519_scalar) {
		const char* scalar_tag = " (ed25519 scalar)";
		const size_t scalar_tag_len = strlen(scalar_tag);
		if (key_round.size() >= scalar_tag_len && key_round.compare(key_round.size() - scalar_tag_len, scalar_tag_len, scalar_tag) == 0) {
			key_round.erase(key_round.size() - scalar_tag_len);
			key_round += " (ed25519 seed)";
		}
	}
	if (save_postcheck_coin_is_ada_base_pair(coin_type)) {
		return build_dual_key_segment(priv_key, key_round);
	}
	return build_key_segment(priv_key, key_round);
}

static inline std::string derivation_path_or_empty(const std::vector<std::string>& Der_list, const uint32_t idx) {
	return (idx < Der_list.size()) ? Der_list[idx] : std::string();
}

static inline std::string build_derivation_segment_ada_pair(const std::vector<std::string>& Der_list, const uint32_t first_path, const uint32_t* foundDerivation2, const uint64_t found_index, const uint8_t coin_type) {
	std::string out = derivation_path_or_empty(Der_list, first_path);
	if (save_postcheck_coin_is_ada_base_pair(coin_type) && foundDerivation2 != nullptr) {
		std::string second = derivation_path_or_empty(Der_list, foundDerivation2[found_index]);
		if (!second.empty()) {
			out.push_back('|');
			out += second;
		}
	}
	return out;
}

static inline uint32_t* copy_found_derivation2_or_null(const size_t count) {
	uint32_t* dev_foundDerivations2 = nullptr;
	if (metalReadStateValue(&dev_foundDerivations2, d_foundDerivations2, sizeof(dev_foundDerivations2)) != metalSuccess || dev_foundDerivations2 == nullptr) {
		return nullptr;
	}
	uint32_t* foundDerivation2 = new uint32_t[count];
	metalMemcpy(foundDerivation2, dev_foundDerivations2, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemset(dev_foundDerivations2, 0, count * sizeof(uint32_t));
	return foundDerivation2;
}

static inline bool emit_ada_dot_result(FILE* file,
	const std::string& file_head,
	const std::string& stdout_head,
	const uint8_t* priv_key,
	const uint32_t* found_hash160,
	const uint8_t coin_type,
	const char* type,
	const std::string& round,
	const bool save_mode,
	const bool preserve_key_in_crypted = false) {
	if (!is_ada_dot_coin(coin_type)) {
		return false;
	}

	const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
	const std::string raw_key_segment = build_key_segment_ada_dot(priv_key, coin_type, round);
	const bool omit_key_segment = save_crypted_output_enabled() && !preserve_key_in_crypted;
	const std::string key_segment = (save_crypted_output_enabled() && preserve_key_in_crypted)
		? crypted_protect_private_key_segment(raw_key_segment)
		: raw_key_segment;

	if (save_mode && (coin_type == 0x30 || coin_type == 0x31)) {
		const char* curve = (coin_type == 0x31) ? "sr25519" : "ed25519";
		const struct { const char* label; int prefix; } aliases[] = {
			{ "PolkaDOT", 0 },
			{ "KUSAMA", 2 },
			{ "SUBTRATE", 42 }
		};
		for (const auto& alias : aliases) {
			const std::string ss58 = ss58Address(raw, alias.prefix);
			std::string alias_type = alias.label;
			alias_type += "(";
			alias_type += curve;
			alias_type += ")";
			emit_mode_result_line(file, file_head, key_segment, alias_type.c_str(), ss58, stdout_head, Silent, true, omit_key_segment);
		}
		return true;
	}

	const std::string addr = ada_or_dot_address(coin_type, raw);
	emit_mode_result_line(file, file_head, key_segment, type, addr, stdout_head, Silent, true, omit_key_segment);
	return true;
}

static unsigned char* hexing_host(unsigned char* buf, size_t buf_sz, unsigned char* hexed, size_t hexed_sz) {
	static const char hex_chars[] = "0123456789abcdef";
	for (size_t i = 0; i < buf_sz; ++i) {
		hexed[2 * i] = hex_chars[(buf[i] >> 4) & 0xF];
		hexed[2 * i + 1] = hex_chars[buf[i] & 0xF];
	}
	return hexed;
}

static unsigned char* hexing_host_end(unsigned char* buf, size_t buf_sz, unsigned char* hexed, size_t hexed_sz) {
	static const char hex_chars[] = "0123456789abcdef";
	for (size_t i = 0; i < buf_sz; ++i) {
		hexed[2 * i] = hex_chars[(buf[i] >> 4) & 0xF];
		hexed[2 * i + 1] = hex_chars[buf[i] & 0xF];
	}
	hexed[buf_sz * 2] = '\0';
	return hexed;
}


//blake2b-160 && blake2b-256
#define ROR64_BLAKE(x,n) (((x)>>(n))|((x)<<(64-(n))))

static const uint64_t IV[8] = {
  0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL
};

static const uint8_t SIGMA[12][16] = {
 {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
 {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
 {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
 {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
 {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
 {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
 {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
 {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
 {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
 {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
 {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
 {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}
};

static inline uint64_t ld64(const uint8_t* p) {
	return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
		((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void G(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d, uint64_t x, uint64_t y) {
	*a = *a + *b + x; *d = ROR64_BLAKE(*d ^ *a, 32);
	*c = *c + *d;   *b = ROR64_BLAKE(*b ^ *c, 24);
	*a = *a + *b + y; *d = ROR64_BLAKE(*d ^ *a, 16);
	*c = *c + *d;   *b = ROR64_BLAKE(*b ^ *c, 63);
}

static void compress(uint64_t h[8], const uint8_t block[128], uint64_t t0, uint64_t t1, int last) {
	uint64_t m[16], v[16];
	for (int i = 0; i < 16; i++) m[i] = ld64(block + 8 * i);
	for (int i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = IV[i]; }
	v[12] ^= t0; v[13] ^= t1; if (last) v[14] = ~v[14];
	for (int r = 0; r < 12; r++) {
		const uint8_t* s = SIGMA[r];
		G(&v[0], &v[4], &v[8], &v[12], m[s[0]], m[s[1]]);
		G(&v[1], &v[5], &v[9], &v[13], m[s[2]], m[s[3]]);
		G(&v[2], &v[6], &v[10], &v[14], m[s[4]], m[s[5]]);
		G(&v[3], &v[7], &v[11], &v[15], m[s[6]], m[s[7]]);
		G(&v[0], &v[5], &v[10], &v[15], m[s[8]], m[s[9]]);
		G(&v[1], &v[6], &v[11], &v[12], m[s[10]], m[s[11]]);
		G(&v[2], &v[7], &v[8], &v[13], m[s[12]], m[s[13]]);
		G(&v[3], &v[4], &v[9], &v[14], m[s[14]], m[s[15]]);
	}
	for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

void blake2b_160(const uint8_t* in, size_t inlen, uint8_t out[20]) {
	uint64_t h[8], t0 = 0, t1 = 0; uint8_t buf[128]; size_t bl = 0;
	uint64_t p0 = (uint64_t)20 | ((uint64_t)1 << 16) | ((uint64_t)1 << 24);
	for (int i = 0; i < 8; i++) h[i] = IV[i];
	h[0] ^= p0;

	while (inlen) {
		size_t take = 128 - bl; if (take > inlen) take = inlen;
		memcpy(buf + bl, in, take); bl += take; in += take; inlen -= take;
		if (bl == 128) {
			t0 += 128; if (t0 < 128) t1++;
			compress(h, buf, t0, t1, 0);
			bl = 0;
		}
	}
	t0 += bl; if (t0 < bl) t1++;
	if (bl < 128) memset(buf + bl, 0, 128 - bl);
	compress(h, buf, t0, t1, 1);

	for (int i = 0; i < 20; i++) {
		out[i] = (uint8_t)(h[i >> 3] >> (8 * (i & 7)));
	}
}

void blake2b_256(const uint8_t* in, size_t inlen, uint8_t out[32]) {
	uint64_t h[8], t0 = 0, t1 = 0;
	uint8_t buf[128];
	size_t bl = 0;

	uint64_t p0 = (uint64_t)32 | ((uint64_t)1 << 16) | ((uint64_t)1 << 24);

	for (int i = 0; i < 8; i++) h[i] = IV[i];
	h[0] ^= p0;

	while (inlen) {
		size_t take = 128 - bl;
		if (take > inlen) take = inlen;
		memcpy(buf + bl, in, take);
		bl += take; in += take; inlen -= take;

		if (bl == 128) {
			t0 += 128; if (t0 < 128) t1++;
			compress(h, buf, t0, t1, 0);
			bl = 0;
		}
	}

	t0 += bl; if (t0 < bl) t1++;
	if (bl < 128) memset(buf + bl, 0, 128 - bl);
	compress(h, buf, t0, t1, 1);

	for (int i = 0; i < 32; i++) {
		out[i] = (uint8_t)(h[i >> 3] >> (8 * (i & 7)));
	}
}

void blake2b_4(const uint8_t* in, size_t inlen, uint8_t out[4]) {

	extern void compress(uint64_t h[8], const uint8_t block[128], uint64_t t0, uint64_t t1, int last);
	extern const uint64_t IV[8];

	uint64_t h[8], t0 = 0, t1 = 0;
	uint8_t buf[128]; size_t bl = 0;

	uint64_t p0 = (uint64_t)4 | ((uint64_t)1 << 16) | ((uint64_t)1 << 24);
	for (int i = 0; i < 8; i++) h[i] = IV[i];
	h[0] ^= p0;

	while (inlen) {
		size_t take = 128 - bl; if (take > inlen) take = inlen;
		memcpy(buf + bl, in, take); bl += take; in += take; inlen -= take;
		if (bl == 128) { t0 += 128; if (t0 < 128) t1++; compress(h, buf, t0, t1, 0); bl = 0; }
	}
	t0 += bl; if (t0 < bl) t1++;
	if (bl < 128) memset(buf + bl, 0, 128 - bl);
	compress(h, buf, t0, t1, 1);

	uint64_t w = h[0];
	out[0] = (uint8_t)(w);
	out[1] = (uint8_t)(w >> 8);
	out[2] = (uint8_t)(w >> 16);
	out[3] = (uint8_t)(w >> 24);
}


/* ===================== Base32 ===================== */

static const char B32_ALPH[] = "abcdefghijklmnopqrstuvwxyz234567";

// base32_lower_encode: encodes the related data for Base32 lower.
size_t base32_lower_encode(const uint8_t* in, size_t inlen, char* out) {
	size_t outlen = 0;
	uint32_t buffer = 0;
	int bits = 0;

	for (size_t i = 0; i < inlen; i++) {
		buffer = (buffer << 8) | in[i];
		bits += 8;
		while (bits >= 5) {
			int idx = (buffer >> (bits - 5)) & 0x1F;
			out[outlen++] = B32_ALPH[idx];
			bits -= 5;
		}
	}
	if (bits > 0) {
		int idx = (buffer << (5 - bits)) & 0x1F;
		out[outlen++] = B32_ALPH[idx];
	}
	return outlen;
}

char* filecoin_from_payload(const uint8_t payload20[20], const char* network, char* out) {

	if (network[0] == 'f' && network[1] == '4') {
		/* f4 (delegated, namespace=10/EVM):
		   checksum = BLAKE2b-4( 0x04 || 0x0A || payload20 ) */



		uint8_t buf[1 + 1 + 20];
		buf[0] = 0x04;
		buf[1] = 0x0A;
		memcpy(buf + 2, payload20, 20);
		uint8_t checksum[4];
		blake2b_4(buf, sizeof(buf), checksum);

		uint8_t data[24];
		memcpy(data, payload20, 20);
		memcpy(data + 20, checksum, 4);

		char b32[40];
		size_t n = base32_lower_encode(data, 24, b32);
		if (n != 39) return NULL;
		b32[n] = '\0';

		out[0] = 'f'; out[1] = '4'; out[2] = '1'; out[3] = '0'; out[4] = 'f';
		memcpy(out + 5, b32, 39);
		out[44] = '\0';
		return out;

		//f410f2oekwcmo2pueydmaq53eic2i62crtbeyuzx2gmy
		//f4102oekwcmo2pueydmaq53eic2i62crtbeyuzx2gmy
	}

	// f1 (SECP256K1 pubkey-hash): checksum = BLAKE2b-4( 0x01 || payload20 )
	uint8_t buf[1 + 20];
	buf[0] = 0x01;
	memcpy(buf + 1, payload20, 20);
	uint8_t checksum[4];
	blake2b_4(buf, sizeof(buf), checksum);

	uint8_t data[24];
	memcpy(data, payload20, 20);
	memcpy(data + 20, checksum, 4);

	char b32[40];
	size_t n = base32_lower_encode(data, 24, b32);
	if (n != 39) return NULL;
	b32[n] = '\0';

	out[0] = network[0];
	out[1] = network[1];
	memcpy(out + 2, b32, 39);
	out[41] = '\0';
	return out;
}



//TEZOS
static const uint8_t PREFIX_TZ1[3] = { 0x06, 0xA1, 0x9F };
static const uint8_t PREFIX_TZ2[3] = { 0x06, 0xA1, 0xA1 };

std::string tz_from_pkhash(const uint8_t prefix[3], const uint8_t pk_hash[20]) {
	uint8_t payload[3 + 20];
	memcpy(payload, prefix, 3);
	memcpy(payload + 3, pk_hash, 20);

	uint8_t d1[32], d2[32];
	sha256(payload, sizeof(payload), d1);
	sha256(d1, 32, d2);

	uint8_t finalbuf[3 + 20 + 4];
	memcpy(finalbuf, payload, 3 + 20);
	memcpy(finalbuf + 3 + 20, d2, 4);



	return encodeBase58_d(finalbuf, sizeof(finalbuf));
}


static inline void emit_standard_key_result(FILE* file,
	const StandardKeyEmitHeads& heads,
	const unsigned char* found_priv_key,
	const uint32_t* found_hash160,
	const uint8_t coin_type,
	const int64_t round_value,
	const bool save) {
	bool is_ed = false;
	const char* type = byte_to_coin(coin_type, is_ed);
	const std::string round = build_round_suffix(round_value, is_ed);
	const std::string key_segment = build_key_segment(found_priv_key, round);
	const bool omit_key_segment = save_crypted_output_enabled();

	if (emit_ada_dot_result(file, heads.file_head, heads.stdout_default_head, found_priv_key, found_hash160, coin_type, type, round, save)) {
		return;
	}

	auto emit_nosave = [&](const std::string& payload, const bool stdout_add_newline = true) {
		emit_mode_result_line(file, heads.file_head, key_segment, type, payload, heads.stdout_default_head, Silent, stdout_add_newline, omit_key_segment);
	};

	if (!save) {
		if (found_hash_is_32_bytes(coin_type)) {
			emit_nosave(build_hash_payload_words(found_hash160, 8));
		}
		else {
			emit_nosave(build_hash_payload_words(found_hash160, 5), false);
		}
		return;
	}

	const std::string& stdout_head = select_standard_stdout_head(heads, coin_type);
	auto emit_save = [&](const char* emit_type, const std::string& payload, const bool stdout_add_newline = true) {
		emit_mode_result_line(file, heads.file_head, key_segment, emit_type, payload, stdout_head, Silent, stdout_add_newline, omit_key_segment);
	};
	auto emit_default = [&](const char* emit_type, const std::string& payload, const bool stdout_add_newline = true) {
		emit_mode_result_line(file, heads.file_head, key_segment, emit_type, payload, heads.stdout_default_head, Silent, stdout_add_newline, omit_key_segment);
	};

	if (coin_type == 0x02) {
		const std::string addr = hash160ToBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 0x00);
		char output[86] = { 0 };
		segwit_addr_encode(output, "bc", 0, reinterpret_cast<const uint8_t*>(found_hash160), 20);
		emit_default(type, addr);
		emit_default("P2WPKH", output);
		return;
	}
	if (coin_type == 0x01) {
		emit_default(type, hash160ToBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 0x00));
		return;
	}
	if (coin_type == 0x03) {
		emit_default(type, hash160ToBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 0x05));
		return;
	}
	if (coin_type == 0x04) {
		char output[86] = { 0 };
		segwit_addr_encode(output, "bc", 1, reinterpret_cast<const uint8_t*>(found_hash160), 32);
		emit_default(type, output);
		return;
	}
	if (endo_base_type_or_self(coin_type) == 0x07) {
		char output[86] = { 0 };
		segwit_addr_encode(output, "bc", 0, reinterpret_cast<const uint8_t*>(found_hash160), 32);
		emit_default(type, output);
		return;
	}
	if (coin_type == 0x05) {
		// Legacy compatibility: standard save paths historically stored only 20-byte XPOINT payload here.
		emit_default(type, build_hash_payload_words(found_hash160, 5));
		return;
	}
	if (coin_type == 0x60) {
		emit_save(type, encodeBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 32));
		return;
	}
	if (coin_type == 0x30 || coin_type == 0x31) {
		emit_save(type, ss58Address(reinterpret_cast<const uint8_t*>(found_hash160), 0));
		return;
	}
	if (coin_type >= 0x80 && coin_type <= 0x8c) {
		emit_save(type, generate_ton_address(reinterpret_cast<const uint8_t*>(found_hash160)));
		return;
	}
	if (coin_type == 0x06) {
		emit_default(type, build_hash_payload_words(found_hash160, 5, true));
		return;
	}
	if ((coin_type >= 0x20 && coin_type <= 0x22) || (coin_type >= 0x70 && coin_type <= 0x71) || coin_type == 0x52 || coin_type == 0x53) {
		emit_default(type, build_hash_payload_words(found_hash160, 8, true));
		return;
	}
	if (coin_type == 0x90 || coin_type == 0x91) {
		emit_default(type, hash160ToXRP(reinterpret_cast<const uint8_t*>(found_hash160), 0x00));
		return;
	}
	if (coin_type == 0x50 || coin_type == 0x51) {
		char output[86] = { 0 };
		uint8_t version = (coin_type == 50) ? 0x01 : 0x00;
		iota_bech32(output, "iota", reinterpret_cast<const uint8_t*>(found_hash160), version);
		emit_default(type, output);
		return;
	}
	if (coin_type >= 0x10 && coin_type <= 0x13) {
		if (coin_type == 0x10) {
			const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
			emit_default(type, encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 43)));
		}
		else if (coin_type == 0x13) {
			const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
			emit_default(type, encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 76)));
		}
		else {
			char output[128] = { 0 };
			cardano_shelley_addr_encode(output, "addr", reinterpret_cast<const uint8_t*>(found_hash160), (coin_type == 0x11) ? 57 : 29);
			emit_default(type, output);
		}
		return;
	}
	if (coin_type == 0x41 || coin_type == 0x42) {
		char addr[64] = { 0 };
		filecoin_from_payload(reinterpret_cast<const uint8_t*>(found_hash160), (coin_type == 0x41) ? "f1" : "f4", &addr[0]);
		emit_default(type, addr);
		return;
	}
	if (coin_type == 0x92 || coin_type == 0x93) {
		std::string addr = (coin_type == 0x92)
			? tz_from_pkhash(PREFIX_TZ2, reinterpret_cast<const uint8_t*>(found_hash160))
			: tz_from_pkhash(PREFIX_TZ1, reinterpret_cast<const uint8_t*>(found_hash160));
		emit_default(type, addr);
		return;
	}

	if (found_hash_is_32_bytes(coin_type)) {
		emit_default(type, build_hash_payload_words(found_hash160, 8));
	}
	else {
		emit_default(type, build_hash_payload_words(found_hash160, 5));
	}
}

static inline void emit_byte_result(FILE* file,
	const StandardKeyEmitHeads& heads,
	const std::string& selected,
	const unsigned char* found_priv_key,
	const uint32_t* found_hash160,
	const uint8_t coin_type,
	const int64_t round_value,
	const bool save,
	const uint32_t found_derivation) {
	if (!(save && coin_type >= 0x10 && coin_type <= 0x13)) {
		emit_standard_key_result(file, heads, found_priv_key, found_hash160, coin_type, round_value, save);
		return;
	}

	bool is_ed = false;
	const char* type = byte_to_coin(coin_type, is_ed);
	const std::string round = build_round_suffix(round_value, is_ed);
	const std::string key_segment = build_key_segment(found_priv_key, round);

	if (emit_ada_dot_result(file, heads.file_head, heads.stdout_default_head, found_priv_key, found_hash160, coin_type, type, round, save)) {
		return;
	}

	if (coin_type == 0x10) {
		const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
		const std::string addr = encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 43));
		const std::string file_head = selected + ":";
		const std::string stdout_head = "\n[!] Found: " + selected + ":";
		emit_mode_result_line(file, file_head, key_segment, type, addr, stdout_head, Silent);
		return;
	}

	if (coin_type == 0x13) {
		const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
		const std::string addr = encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 76));
		const std::string daedalus_der = (found_derivation < 0x80000000u)
			? ("/0'/" + std::to_string(found_derivation))
			: ("/1'/" + std::to_string(found_derivation - 0x80000000u));
		const std::string file_head = selected + ":" + daedalus_der + ":";
		const std::string stdout_head = "\n[!] Found: " + selected + ":" + daedalus_der + ":";
		emit_mode_result_line(file, file_head, key_segment, type, addr, stdout_head, Silent);
		return;
	}

	emit_standard_key_result(file, heads, found_priv_key, found_hash160, coin_type, round_value, save);
}

// hex_nibble_uc: converts nibble uc.
static inline int hex_nibble_uc(unsigned char c) {
	if (c >= '0' && c <= '9') return (int)(c - '0');
	if (c >= 'a' && c <= 'f') return (int)(c - 'a') + 10;
	if (c >= 'A' && c <= 'F') return (int)(c - 'A') + 10;
	return -1;
}

static inline bool
unhex_strict(const unsigned char* str, size_t str_sz,
	unsigned char* unhexed, size_t unhexed_sz)
{
	if (str_sz & 1) return false;

	size_t i, j;
	for (i = 0, j = 0; i + 1 < str_sz && j < unhexed_sz; i += 2, ++j) {
		int hi = hex_nibble_uc(str[i + 0]);
		int lo = hex_nibble_uc(str[i + 1]);
		if ((hi | lo) < 0) return false;
		unhexed[j] = (unsigned char)((hi << 4) | lo);
	}

	return true;
}

//Armory Easy16
static constexpr char EASY16_ALPH[16] = {
	'a','s','d','f','g','h','j','k','w','e','r','t','u','i','o','n'
};

// easy16_encode_raw: encodes raw for easy 16.
static inline std::string easy16_encode_raw(const uint8_t* data, size_t len) {
	std::string out;
	out.resize(len * 2);
	size_t p = 0;
	for (size_t i = 0; i < len; ++i) {
		uint8_t b = data[i];
		out[p++] = EASY16_ALPH[b >> 4];
		out[p++] = EASY16_ALPH[b & 0x0F];
	}
	return out;
}

static inline std::string group4_with_spaces(const std::string& s) {
	std::string out;
	out.reserve(s.size() + s.size() / 4);

	for (size_t i = 0; i < s.size(); ++i) {
		out.push_back(s[i]);
		if (((i + 1) % 4) == 0 && (i + 1) != s.size()) out.push_back(' ');
	}
	return out;
}

// armory_easy16_encode: encodes the related data for armory easy 16.
static inline std::string armory_easy16_encode(const uint8_t data64[64]) {
	std::string out;
	out.reserve(4 * (36 + 8 + 1));

	for (int line = 0; line < 4; ++line) {
		const uint8_t* block16 = data64 + line * 16;

		uint8_t cs32[32];
		sha256((uint8_t*)block16, 16, cs32);
		sha256(cs32, 32, cs32);

		uint8_t payload18[18];
		std::memcpy(payload18, block16, 16);
		payload18[16] = cs32[0];
		payload18[17] = cs32[1];

		std::string e16 = easy16_encode_raw(payload18, 18);
		std::string pretty = group4_with_spaces(e16);

		out += pretty;
		if (line != 3) out.push_back('\n');
	}
	return out;
}

static inline void emit_brain_like_result(FILE* file,
	const std::string& selected,
	const unsigned char* found_priv_key,
	const uint32_t* found_hash160,
	const uint8_t coin_type,
	const int64_t round_value,
	const bool save,
	const std::string& selected_open_suffix = std::string()) {
	bool is_ed = false;
	const char* type = byte_to_coin(coin_type, is_ed);
	const std::string round = build_round_suffix(round_value, is_ed);
	const std::string key_hex = build_hex_bytes_lower(found_priv_key, 32);
	const std::string key_segment = build_key_segment_from_hex(key_hex, round);
	const bool omit_key_segment = save_crypted_output_enabled();
	const std::string file_head = build_mode_selected_head("Brain", selected, false, false, selected_open_suffix);
	const std::string stdout_head = build_mode_selected_head("Brain", selected, true, false, selected_open_suffix);

	if (emit_ada_dot_result(file, file_head, stdout_head, found_priv_key, found_hash160, coin_type, type, round, save)) {
		return;
	}

	auto emit_default = [&](const char* emit_type, const std::string& payload, const bool stdout_add_newline = true) {
		emit_mode_result_line(file, file_head, key_segment, emit_type, payload, stdout_head, Silent, stdout_add_newline, omit_key_segment);
	};
	auto emit_with_custom_key_stdout = [&](const std::string& file_key_segment, const std::string& stdout_key_segment, const char* emit_type, const std::string& payload, const bool stdout_add_newline = true) {
		emit_mode_result_line(file, file_head, file_key_segment, emit_type, payload, stdout_head, stdout_key_segment, stdout_add_newline, Silent, omit_key_segment);
	};

	if (!save) {
		if (coin_type >= 0x10 && coin_type <= 0x13) {
			if (coin_type == 0x10) {
				emit_default(type, build_hex_bytes_lower(reinterpret_cast<const uint8_t*>(found_hash160), 43));
			}
			else if (coin_type == 0x11) {
				const std::string sk_hex = build_hex_bytes_lower(found_priv_key + 32, 32);
				const std::string dual_key_segment = build_dual_key_segment_from_hex(key_hex, round, sk_hex);
				emit_with_custom_key_stdout(dual_key_segment, dual_key_segment, type, build_hex_bytes_lower(reinterpret_cast<const uint8_t*>(found_hash160), 57));
			}
			else if (coin_type == 0x13) {
				const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
				emit_default(type, build_hex_bytes_lower(raw, save_postcheck_cardano_byron_raw_len(raw, 76)));
			}
			else {
				emit_default(type, build_hex_bytes_lower(reinterpret_cast<const uint8_t*>(found_hash160), 29));
			}
			return;
		}

		if (found_hash_is_32_bytes(coin_type)) {
			emit_default(type, build_hash_payload_words(found_hash160, 8));
		}
		else {
			emit_default(type, build_hash_payload_words(found_hash160, 5), false);
		}
		return;
	}

	if (coin_type == 0x02) {
		const std::string addr = hash160ToBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 0x00);
		char output[86] = { 0 };
		segwit_addr_encode(output, "bc", 0, reinterpret_cast<const uint8_t*>(found_hash160), 20);
		emit_default(type, addr);
		emit_default("P2WPKH", output);
		return;
	}
	if (coin_type == 0x01) {
		emit_default(type, hash160ToBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 0x00));
		return;
	}
	if (coin_type == 0x03) {
		emit_default(type, hash160ToBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 0x05));
		return;
	}
	if (coin_type == 0x04) {
		char output[86] = { 0 };
		segwit_addr_encode(output, "bc", 1, reinterpret_cast<const uint8_t*>(found_hash160), 32);
		emit_default(type, output);
		return;
	}
	if (endo_base_type_or_self(coin_type) == 0x07) {
		char output[86] = { 0 };
		segwit_addr_encode(output, "bc", 0, reinterpret_cast<const uint8_t*>(found_hash160), 32);
		emit_default(type, output);
		return;
	}
	if (coin_type == 0x05) {
		// Legacy compatibility: brain save paths historically stored only 20-byte XPOINT payload here.
		emit_default(type, build_hash_payload_words(found_hash160, 5));
		return;
	}
	if (coin_type == 0x60) {
		emit_default(type, encodeBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 32));
		return;
	}
	if (coin_type == 0x30 || coin_type == 0x31) {
		emit_default(type, ss58Address(reinterpret_cast<const uint8_t*>(found_hash160), 0));
		return;
	}
	if (coin_type >= 0x80 && coin_type <= 0x8c) {
		emit_default(type, generate_ton_address(reinterpret_cast<const uint8_t*>(found_hash160)));
		return;
	}
	if (coin_type == 0x06) {
		emit_default(type, build_hash_payload_words(found_hash160, 5, true));
		return;
	}
	if ((coin_type >= 0x20 && coin_type <= 0x22) || (coin_type >= 0x70 && coin_type <= 0x71) || coin_type == 0x52 || coin_type == 0x53) {
		emit_default(type, build_hash_payload_words(found_hash160, 8, true));
		return;
	}
	if (coin_type == 0x90 || coin_type == 0x91) {
		emit_default(type, hash160ToXRP(reinterpret_cast<const uint8_t*>(found_hash160), 0x00));
		return;
	}
	if (coin_type == 0x50 || coin_type == 0x51) {
		char output[86] = { 0 };
		uint8_t version = 0x00;
		if (coin_type == 50) {
			version = 0x01;
		}
		iota_bech32(output, "iota", reinterpret_cast<const uint8_t*>(found_hash160), version);
		emit_default(type, output);
		return;
	}
	if (coin_type >= 0x10 && coin_type <= 0x13) {
		if (coin_type == 0x10) {
			const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
			const std::string byron_base58 = encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 43));
			emit_with_custom_key_stdout(key_segment, key_segment, type, byron_base58);
		}
		else if (coin_type == 0x11) {
			char output[128] = { 0 };
			cardano_shelley_addr_encode(output, "addr", reinterpret_cast<const uint8_t*>(found_hash160), 57);
			const std::string sk_hex = build_hex_bytes_lower(found_priv_key + 32, 32);
			const std::string dual_key_segment = build_dual_key_segment_from_hex(key_hex, round, sk_hex);
			emit_with_custom_key_stdout(dual_key_segment, dual_key_segment, type, output);
		}
		else if (coin_type == 0x13) {
			const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
			emit_default(type, encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 76)));
		}
		else {
			char output[128] = { 0 };
			cardano_shelley_addr_encode(output, "addr", reinterpret_cast<const uint8_t*>(found_hash160), 29);
			emit_default(type, output);
		}
		return;
	}
	if (coin_type == 0x41 || coin_type == 0x42) {
		char addr[64] = { 0 };
		if (coin_type == 0x41) {
			filecoin_from_payload(reinterpret_cast<const uint8_t*>(found_hash160), "f1", &addr[0]);
		}
		else {
			filecoin_from_payload(reinterpret_cast<const uint8_t*>(found_hash160), "f4", &addr[0]);
		}
		emit_default(type, addr);
		return;
	}
	if (coin_type == 0x92 || coin_type == 0x93) {
		std::string addr;
		if (coin_type == 0x92) {
			addr = tz_from_pkhash(PREFIX_TZ2, reinterpret_cast<const uint8_t*>(found_hash160));
		}
		else {
			addr = tz_from_pkhash(PREFIX_TZ1, reinterpret_cast<const uint8_t*>(found_hash160));
		}
		emit_default(type, addr);
		return;
	}

	if (found_hash_is_32_bytes(coin_type)) {
		emit_default(type, build_hash_payload_words(found_hash160, 8));
	}
	else {
		emit_default(type, build_hash_payload_words(found_hash160, 5));
	}
}

struct PrivEmitHeads {
	std::string file_head;
	std::string stdout_default_head;
	std::string stdout_raw32_save_head;
	std::string bare_file_head;
	std::string bare_stdout_head;
};

static inline PrivEmitHeads make_priv_emit_heads(const std::string& file_head,
	const std::string& stdout_default_head,
	const std::string& stdout_raw32_save_head = std::string(),
	const std::string& bare_file_head = std::string(),
	const std::string& bare_stdout_head = std::string()) {
	PrivEmitHeads heads;
	heads.file_head = file_head;
	heads.stdout_default_head = stdout_default_head;
	heads.stdout_raw32_save_head = stdout_raw32_save_head.empty() ? stdout_default_head : stdout_raw32_save_head;
	heads.bare_file_head = bare_file_head.empty() ? file_head : bare_file_head;
	heads.bare_stdout_head = bare_stdout_head.empty() ? stdout_default_head : bare_stdout_head;
	return heads;
}

static inline void emit_priv_worker_result(FILE* file,
	const PrivEmitHeads& heads,
	const unsigned char* found_priv_key,
	const uint32_t* found_hash160,
	const uint8_t coin_type,
	const int64_t round_value,
	const bool save,
	const bool support_cardano,
	const size_t save_fallback_words) {
	const uint8_t base_type = endo_base_type_or_self(coin_type);
	bool is_ed = false;
	const char* type = byte_to_coin(base_type, is_ed);
	unsigned char key_to_hex[32];
	fix_endo_key((uint8_t*)found_priv_key, key_to_hex, coin_type);
	const std::string round = build_round_suffix(round_value, is_ed);
	const std::string key_hex = build_hex_bytes_lower(key_to_hex, 32);
	const std::string key_segment = build_key_segment_from_hex(key_hex, round);
	const std::string output_key_segment = crypted_protect_private_key_segment(key_segment);

	if (emit_ada_dot_result(file, heads.file_head, heads.stdout_default_head, found_priv_key, found_hash160, base_type, type, round, save, true)) {
		return;
	}

	auto emit_default = [&](const char* emit_type, const std::string& payload, const bool stdout_add_newline = true) {
		emit_mode_result_line(file, heads.file_head, output_key_segment, emit_type, payload, heads.stdout_default_head, Silent, stdout_add_newline);
	};
	auto emit_raw32_save = [&](const char* emit_type, const std::string& payload, const bool stdout_add_newline = true) {
		emit_mode_result_line(file, heads.file_head, output_key_segment, emit_type, payload, heads.stdout_raw32_save_head, Silent, stdout_add_newline);
	};
	auto emit_bare = [&](const char* emit_type, const std::string& payload, const bool stdout_add_newline = true) {
		emit_mode_result_line(file, heads.bare_file_head, output_key_segment, emit_type, payload, heads.bare_stdout_head, Silent, stdout_add_newline);
	};
	auto emit_custom_default_key = [&](const std::string& custom_key_segment, const char* emit_type, const std::string& payload, const bool stdout_add_newline = true) {
		const std::string output_custom_key_segment = crypted_protect_private_key_segment(custom_key_segment);
		emit_mode_result_line(file, heads.file_head, output_custom_key_segment, emit_type, payload, heads.stdout_default_head, output_custom_key_segment, stdout_add_newline, Silent);
	};

	if (!save) {
		if (support_cardano && coin_type >= 0x10 && coin_type <= 0x13) {
			if (coin_type == 0x10) {
				emit_default(type, build_hex_bytes_lower(reinterpret_cast<const uint8_t*>(found_hash160), 43));
			}
			else if (coin_type == 0x11) {
				const std::string sk_hex = build_hex_bytes_lower(found_priv_key + 32, 32);
				const std::string dual_key_segment = build_dual_key_segment_from_hex(key_hex, round, sk_hex);
				emit_custom_default_key(dual_key_segment, type, build_hex_bytes_lower(reinterpret_cast<const uint8_t*>(found_hash160), 57));
			}
			else if (coin_type == 0x13) {
				const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
				emit_default(type, build_hex_bytes_lower(raw, save_postcheck_cardano_byron_raw_len(raw, 76)));
			}
			else {
				emit_default(type, build_hex_bytes_lower(reinterpret_cast<const uint8_t*>(found_hash160), 29));
			}
			return;
		}

		if (found_hash_is_32_bytes(coin_type)) {
			emit_default(type, build_hash_payload_words(found_hash160, 8));
		}
		else {
			emit_default(type, build_hash_payload_words(found_hash160, 5), false);
		}
		return;
	}

	if (base_type == 0x02) {
		const std::string addr = hash160ToBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 0x00);
		char output[86] = { 0 };
		segwit_addr_encode(output, "bc", 0, reinterpret_cast<const uint8_t*>(found_hash160), 20);
		emit_default(type, addr);
		emit_default("P2WPKH", output);
		return;
	}
	if (base_type == 0x01) {
		emit_default(type, hash160ToBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 0x00));
		return;
	}
	if (coin_type == 0x03) {
		emit_default(type, hash160ToBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 0x05));
		return;
	}
	if (coin_type == 0x60) {
		emit_default(type, encodeBase58_d(reinterpret_cast<const uint8_t*>(found_hash160), 32));
		return;
	}
	if (coin_type == 0x30 || coin_type == 0x31) {
		emit_default(type, ss58Address(reinterpret_cast<const uint8_t*>(found_hash160), 0));
		return;
	}
	if (coin_type >= 0x80 && coin_type <= 0x8c) {
		emit_default(type, generate_ton_address(reinterpret_cast<const uint8_t*>(found_hash160)));
		return;
	}
	if (coin_type == 0x06) {
		emit_default(type, build_hash_payload_words(found_hash160, 5, true));
		return;
	}
	if ((coin_type >= 0x20 && coin_type <= 0x22) || (coin_type >= 0x70 && coin_type <= 0x71) || coin_type == 0x52 || coin_type == 0x53) {
		emit_raw32_save(type, build_hash_payload_words(found_hash160, 8, true));
		return;
	}
	if (coin_type == 0x90 || coin_type == 0x91) {
		emit_bare(type, hash160ToXRP(reinterpret_cast<const uint8_t*>(found_hash160), 0x00));
		return;
	}
	if (coin_type == 0x04) {
		char output[86] = { 0 };
		segwit_addr_encode(output, "bc", 1, reinterpret_cast<const uint8_t*>(found_hash160), 32);
		emit_default(type, output);
		return;
	}
	if (base_type == 0x07) {
		char output[86] = { 0 };
		segwit_addr_encode(output, "bc", 0, reinterpret_cast<const uint8_t*>(found_hash160), 32);
		emit_default(type, output);
		return;
	}
	if (coin_type == 0x50 || coin_type == 0x51) {
		char output[86] = { 0 };
		const uint8_t version = (coin_type == 50) ? 0x01 : 0x00;
		iota_bech32(output, "iota", reinterpret_cast<const uint8_t*>(found_hash160), version);
		emit_default(type, output);
		return;
	}
	if (support_cardano && coin_type >= 0x10 && coin_type <= 0x13) {
		if (coin_type == 0x10) {
			const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
			emit_default(type, encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 43)));
		}
		else if (coin_type == 0x11) {
			char output[128] = { 0 };
			cardano_shelley_addr_encode(output, "addr", reinterpret_cast<const uint8_t*>(found_hash160), 57);
			const std::string sk_hex = build_hex_bytes_lower(found_priv_key + 32, 32);
			const std::string dual_key_segment = build_dual_key_segment_from_hex(key_hex, round, sk_hex);
			emit_custom_default_key(dual_key_segment, type, output);
		}
		else if (coin_type == 0x13) {
			const uint8_t* raw = reinterpret_cast<const uint8_t*>(found_hash160);
			emit_default(type, encodeBase58_d(raw, save_postcheck_cardano_byron_raw_len(raw, 76)));
		}
		else {
			char output[128] = { 0 };
			cardano_shelley_addr_encode(output, "addr", reinterpret_cast<const uint8_t*>(found_hash160), 29);
			emit_default(type, output);
		}
		return;
	}
	if (coin_type == 0x41 || coin_type == 0x42) {
		char addr[64] = { 0 };
		filecoin_from_payload(reinterpret_cast<const uint8_t*>(found_hash160), (coin_type == 0x41) ? "f1" : "f4", &addr[0]);
		emit_default(type, addr);
		return;
	}
	if (coin_type == 0x92 || coin_type == 0x93) {
		const std::string addr = (coin_type == 0x92)
			? tz_from_pkhash(PREFIX_TZ2, reinterpret_cast<const uint8_t*>(found_hash160))
			: tz_from_pkhash(PREFIX_TZ1, reinterpret_cast<const uint8_t*>(found_hash160));
		emit_default(type, addr);
		return;
	}

	emit_default(type, build_hash_payload_words(found_hash160, save_fallback_words));
}


//Old mnemonic save func.

static std::string build_old_derivation_label(uint32_t slot)
{
	const uint32_t old_deep = (deep == 0) ? 20u : deep;
	if (slot < old_deep) {
		return "m/0/" + std::to_string(slot);
	}
	return "m/1/" + std::to_string(slot - old_deep);
}

static void SaveResultOld_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1], int64_t* rounds,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::string selected;

		string hexed;
		hexed.resize((len_h[i][0] * 2));
		hexing_host((uint8_t*)&foundStrings[i], len_h[i][0], (uint8_t*)hexed.data(), (len_h[i][0] * 2));

		uint32_t swaped_seed[512 / 4];
		memcpy(swaped_seed, foundStrings[i], len_h[i][0]);
		for (int n = 0; n < len_h[i][0] / 4; n++)
		{
			swaped_seed[n] = reverseByteOrderHost(swaped_seed[n]);

		}
		string recovered_mnemonic;
		recovered_mnemonic.resize(512 * 2);
		int word_count = (len_h[i][0] / 4) * 3;
		seed_to_mnemonic_phrase(swaped_seed, word_count, wordsOLD, word_lengths, (char*)recovered_mnemonic.data());
		recovered_mnemonic.resize(strlen(recovered_mnemonic.c_str()));

		if (save_crypted_output_enabled()) {
			selected = recovered_mnemonic;
		}
		else {
			selected = recovered_mnemonic + ":seed(" + hexed + ")";
		}

		std::string found_der = "";
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		found_der = build_old_derivation_label(foundDerivation[i]);
		if (save_postcheck_coin_is_ada_base_pair(coin_type[i]) && foundDerivation2 != nullptr) {
			found_der += "|" + build_old_derivation_label(foundDerivation2[i]);
		}
		std::string round = build_round_suffix(rounds[i], is_ed);


		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] len_h;
	delete[] rounds;
	STOP_THREAD = false;
}

// Host helper: SaveResultOld.
METAL_HOST void SaveResultOld(FILE* file, uint32_t& Founds, bool save) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));

	save_clear_results_count_best_effort(__func__);



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("old", count, save, SaveResultOld_Worker, file, &Founds, save, foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, len_h, rounds, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}

static void SaveResultOldSeed_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1], int64_t* rounds,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::string selected;

		std::string selected_new;
		selected_new.assign(&foundStrings[i][0], len_h[i][0]);

		selected_new = sanitize_visible_utf8(std::move(selected_new));



		uint32_t swaped_seed[512 / 4];
		bool is_hex = unhex_strict((uint8_t*)foundStrings[i], len_h[i][0], (uint8_t*)swaped_seed, len_h[i][0] / 2);


		for (int n = 0; n < len_h[i][0] / 4; n++)
		{
			swaped_seed[n] = reverseByteOrderHost(swaped_seed[n]);

		}
		string recovered_mnemonic;
		if (len_h[i][0] % 8 == 0 && is_hex)
		{
			recovered_mnemonic.resize(512 * 2);
			int word_count = (len_h[i][0] / 8) * 3;
			seed_to_mnemonic_phrase(swaped_seed, word_count, wordsOLD, word_lengths, (char*)recovered_mnemonic.data());
			recovered_mnemonic.resize(strlen(recovered_mnemonic.c_str()));
		}
		else
		{

			recovered_mnemonic = "NULL";
			recovered_mnemonic.resize(4);
		}

		if (save_crypted_output_enabled()) {
			selected = build_crypted_source_text_from_found_bytes(&foundStrings[i][0], len_h[i][0]);
		}
		else {
			selected = recovered_mnemonic + ":seed(" + selected_new + ")";
		}

		std::string found_der = "";
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		found_der = build_old_derivation_label(foundDerivation[i]);
		if (save_postcheck_coin_is_ada_base_pair(coin_type[i]) && foundDerivation2 != nullptr) {
			found_der += "|" + build_old_derivation_label(foundDerivation2[i]);
		}
		std::string round = build_round_suffix(rounds[i], is_ed);

		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] len_h;
	delete[] rounds;
	STOP_THREAD = false;
}

// Host helper: SaveResultOldSeed.
METAL_HOST void SaveResultOldSeed(FILE* file, uint32_t& Founds, bool save) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));

	save_clear_results_count_best_effort(__func__);



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("old_seed", count, save, SaveResultOldSeed_Worker, file, &Founds, save, foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, len_h, rounds, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}


//Mnemonic save func.
static void SaveResult_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	std::vector<std::string> Der_list,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1],
	char (*foundPass)[128], uint16_t* foundPassSize, int64_t* rounds,
	unsigned long long count) {


	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::string selected = load_found_text_sanitized(&foundStrings[i][0], len_h[i][0], 511);

		std::string found_der = "";
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);


		if (BIP39_Pass) {
			found_der = build_bip39_pass_derivation_prefix(foundPass, foundPassSize, foundStrings, len_h, i, count);
		}
		found_der += build_derivation_segment_ada_pair(Der_list, foundDerivation[i], foundDerivation2, i, coin_type[i]);

		std::string round = build_round_suffix(rounds[i], is_ed);



		char privkey_hexed[65] = { 0 };
		hexing_host_end((uint8_t*)foundPrvKeys[i], 32, (uint8_t*)privkey_hexed, 32 * 2);
		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}


	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] foundPass;
	delete[] len_h;
	delete[] rounds;
	STOP_THREAD = false;
}

// Host helper: SaveResult.
METAL_HOST void SaveResult(FILE* file, uint32_t& Founds, bool save, std::vector<std::string> Der_list)
{
	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	SAVE_METAL_OR_RETURN("save.snapshot.count.mnemonic", metalReadStateValue(&resultsCountHost, d_resultsCount, sizeof(resultsCountHost), 0, metalMemcpyDeviceToHost));

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort("save.clear_device.count.mnemonic");
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	char (*foundPass)[128];
	uint16_t* foundPassSize;
	if (BIP39_Pass)
	{
		foundPass = new char[count][128];
		foundPassSize = new uint16_t[count];
	}
	else
	{
		foundPass = nullptr;
		foundPassSize = nullptr;
	}
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	char (*dev_pass)[128] = nullptr;
	uint16_t* dev_passSize = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;

	SAVE_METAL_OR_GOTO("save.snapshot.symbols.mnemonic", metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.mnemonic", metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.mnemonic", metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.mnemonic", metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.mnemonic", metalReadStateValue(&dev_type, d_type, sizeof(dev_type)), fail);
	if (BIP39_Pass) {
		SAVE_METAL_OR_GOTO("save.snapshot.symbols.mnemonic", metalReadStateValue(&dev_pass, d_pass, sizeof(dev_pass)), fail);
		SAVE_METAL_OR_GOTO("save.snapshot.symbols.mnemonic", metalReadStateValue(&dev_passSize, d_pass_size, sizeof(dev_passSize)), fail);
	}
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.mnemonic", metalReadStateValue(&dev_len, d_len, sizeof(dev_len)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.mnemonic", metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds)), fail);

	SAVE_METAL_OR_GOTO("save.snapshot.copy.mnemonic", metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost), fail);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.mnemonic", metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.mnemonic", metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.mnemonic", metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.mnemonic", metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost), fail);
	if (BIP39_Pass) {
		SAVE_METAL_OR_GOTO("save.snapshot.copy.mnemonic", metalMemcpy(foundPass, dev_pass, count * 128 * sizeof(char), metalMemcpyDeviceToHost), fail);
		SAVE_METAL_OR_GOTO("save.snapshot.copy.mnemonic", metalMemcpy(foundPassSize, dev_passSize, count * sizeof(uint16_t), metalMemcpyDeviceToHost), fail);
	}
	SAVE_METAL_OR_GOTO("save.snapshot.copy.mnemonic", metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.mnemonic", metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost), fail);

	SAVE_METAL_OR_GOTO("save.clear_device.mnemonic", metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.mnemonic", metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.mnemonic", metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.mnemonic", metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.mnemonic", metalMemset(dev_type, 0, count * sizeof(uint8_t)), fail);
	if (BIP39_Pass) {
		SAVE_METAL_OR_GOTO("save.clear_device.mnemonic", metalMemset(dev_pass, 0, count * 128 * sizeof(char)), fail);
		SAVE_METAL_OR_GOTO("save.clear_device.mnemonic", metalMemset(dev_passSize, 0, count * sizeof(uint16_t)), fail);
	}
	SAVE_METAL_OR_GOTO("save.clear_device.mnemonic", metalMemset(dev_len, 0, count * sizeof(uint32_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.mnemonic", metalMemset(dev_rounds, 0, count * sizeof(int64_t)), fail);


	save_clear_results_count_best_effort("save.clear_device.count.mnemonic");


	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("mnemonic", count, save,
			SaveResult_Worker, file, &Founds, save,
			std::move(Der_list),
			foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160,
			coin_type, len_h, foundPass, foundPassSize, rounds,
			count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

	return;

fail:
	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] foundPass;
	delete[] foundPassSize;
	delete[] len_h;
	delete[] rounds;
}



//Priv save func.
static void SaveResultPRIV_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type, int64_t* rounds,
	unsigned long long count) {
	const PrivEmitHeads heads = make_priv_emit_heads("", "\n[!] Found: ");

	for (uint64_t i = 0; i < count; i++) {

		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}
		emit_priv_worker_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save, true, 8);
	}
	if (save) {
		save_output_flush(file);
	}


	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] rounds;
	STOP_THREAD = false;
}

// Host helper: SaveResultPRIV.
METAL_HOST void SaveResultPRIV(FILE* file, uint32_t& Founds, bool save, const vector<string>& Der_list) {
	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	SAVE_METAL_OR_RETURN("save.snapshot.count.priv", metalReadStateValue(&resultsCountHost, d_resultsCount, sizeof(resultsCountHost), 0, metalMemcpyDeviceToHost));

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort("save.clear_device.count.priv");
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	int64_t* rounds = new int64_t[count];

	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	int64_t* dev_rounds = nullptr;

	SAVE_METAL_OR_GOTO("save.snapshot.symbols.priv", metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.priv", metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.priv", metalReadStateValue(&dev_type, d_type, sizeof(dev_type)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.priv", metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds)), fail);

	SAVE_METAL_OR_GOTO("save.snapshot.copy.priv", metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.priv", metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.priv", metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.priv", metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost), fail);

	SAVE_METAL_OR_GOTO("save.clear_device.priv", metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.priv", metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.priv", metalMemset(dev_type, 0, count * sizeof(uint8_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.priv", metalMemset(dev_rounds, 0, count * sizeof(int64_t)), fail);

	save_clear_results_count_best_effort("save.clear_device.count.priv");



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("priv", count, save, SaveResultPRIV_Worker, file, &Founds, save, foundPrvKeys, foundHash160, coin_type, rounds, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

	return;

fail:
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] rounds;
}

static bool decode_poetry_key_descriptor(const unsigned char* encoded,
	size_t encoded_len,
	std::string& phrase) {
	if (encoded_len != 38u) return false;
	const unsigned char* private_key = encoded + 6u;
	const uint32_t word_count = encoded[4];
	if (word_count < 3u || word_count > POETRY_MAX_WORDS || word_count % 3u != 0u) {
		return false;
	}

	const uint32_t group_count = word_count / 3u;
	const uint32_t overflow_mask = encoded[5];
	if ((overflow_mask >> group_count) != 0u) return false;

	constexpr uint64_t dictionary_size = POETRY_WORD_COUNT;
	constexpr uint64_t dictionary_square = dictionary_size * dictionary_size;
	constexpr uint64_t dictionary_cube = dictionary_square * dictionary_size;
	const uint32_t key_offset = 32u - group_count * 4u;

	std::string decoded;
	for (uint32_t group = 0u; group < group_count; ++group) {
		const unsigned char* block_bytes = private_key + key_offset + group * 4u;
		const uint32_t block = (static_cast<uint32_t>(block_bytes[0]) << 24u) |
			(static_cast<uint32_t>(block_bytes[1]) << 16u) |
			(static_cast<uint32_t>(block_bytes[2]) << 8u) |
			static_cast<uint32_t>(block_bytes[3]);
		const uint64_t full_block = static_cast<uint64_t>(block) +
			(((overflow_mask >> group) & 1u) != 0u ? (uint64_t{1} << 32u) : 0u);
		if (full_block >= dictionary_cube) return false;

		const uint32_t first = static_cast<uint32_t>(full_block % dictionary_size);
		const uint32_t second = static_cast<uint32_t>(
			(first + (full_block / dictionary_size) % dictionary_size) % dictionary_size);
		const uint32_t third = static_cast<uint32_t>(
			(second + (full_block / dictionary_square) % dictionary_size) % dictionary_size);
		const uint32_t ids[3] = { first, second, third };
		for (uint32_t id : ids) {
			if (id >= POETRY_WORD_COUNT || wordsOLD[id] == nullptr) return false;
			if (!decoded.empty()) decoded.push_back(' ');
			decoded.append(wordsOLD[id]);
		}
	}
	phrase.swap(decoded);
	return !phrase.empty();
}

static void SaveResultPoetry_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char (*foundStrings)[512],
	uint32_t(*len_h)[1],
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	int64_t* rounds,
	unsigned long long count) {
	for (uint64_t i = 0; i < count; ++i) {
		const unsigned char* encoded = reinterpret_cast<const unsigned char*>(foundStrings[i]);
		const size_t encoded_len = static_cast<size_t>(len_h[i][0]);
		std::string phrase;
		if (encoded_len >= 4u && encoded[0] == 0u && encoded[1] == 'P' &&
			encoded[2] == 'O' && encoded[3] == 'K') {
			if (!decode_poetry_key_descriptor(encoded, encoded_len, phrase)) {
				gpu_prefixed_fprintf(stderr, "[!] Invalid Poetry key descriptor [!]\n");
				continue;
			}
		}
		else {
			phrase.assign(foundStrings[i], encoded_len);
		}
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}
		const PrivEmitHeads heads = make_priv_emit_heads(
			phrase + ":",
			"\n[!] Found: " + phrase + ":");
		emit_priv_worker_result(file, heads, foundPrvKeys[i], foundHash160[i],
			coin_type[i], rounds[i], save, true, 8);
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] len_h;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] rounds;
	STOP_THREAD = false;
}

METAL_HOST void SaveResultPoetry(FILE* file, uint32_t& Founds, bool save,
	const vector<string>& Der_list) {
	(void)Der_list;
	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	SAVE_METAL_OR_RETURN("save.snapshot.count.poetry",
		metalReadStateValue(&resultsCountHost, d_resultsCount, sizeof(resultsCountHost),
			0, metalMemcpyDeviceToHost));

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort("save.clear_device.count.poetry");
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) count = MAX_FOUNDS;

	char (*foundStrings)[512] = new char[count][512];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	int64_t* rounds = new int64_t[count];

	char (*dev_foundStrings)[512] = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	int64_t* dev_rounds = nullptr;

	SAVE_METAL_OR_GOTO("save.snapshot.symbols.poetry", metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings)), fail_poetry);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.poetry", metalReadStateValue(&dev_len, d_len, sizeof(dev_len)), fail_poetry);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.poetry", metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys)), fail_poetry);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.poetry", metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160)), fail_poetry);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.poetry", metalReadStateValue(&dev_type, d_type, sizeof(dev_type)), fail_poetry);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.poetry", metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds)), fail_poetry);

	SAVE_METAL_OR_GOTO("save.snapshot.copy.poetry", metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost), fail_poetry);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.poetry", metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost), fail_poetry);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.poetry", metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost), fail_poetry);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.poetry", metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost), fail_poetry);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.poetry", metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost), fail_poetry);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.poetry", metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost), fail_poetry);

	SAVE_METAL_OR_GOTO("save.clear_device.poetry", metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char)), fail_poetry);
	SAVE_METAL_OR_GOTO("save.clear_device.poetry", metalMemset(dev_len, 0, count * sizeof(uint32_t)), fail_poetry);
	SAVE_METAL_OR_GOTO("save.clear_device.poetry", metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t)), fail_poetry);
	SAVE_METAL_OR_GOTO("save.clear_device.poetry", metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t)), fail_poetry);
	SAVE_METAL_OR_GOTO("save.clear_device.poetry", metalMemset(dev_type, 0, count * sizeof(uint8_t)), fail_poetry);
	SAVE_METAL_OR_GOTO("save.clear_device.poetry", metalMemset(dev_rounds, 0, count * sizeof(int64_t)), fail_poetry);

	save_clear_results_count_best_effort("save.clear_device.count.poetry");
	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("poetry", count, save,
			SaveResultPoetry_Worker, file, &Founds, save, foundStrings, len_h,
			foundPrvKeys, foundHash160, coin_type, rounds, count);
	}

	if (FULL) flush_all_async_save_queues();
	return;

fail_poetry:
	delete[] foundStrings;
	delete[] len_h;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] rounds;
}

static std::string build_profanity_prefix(const ProfanityVerifiedResult& result) {
	char head[96];
	std::snprintf(head, sizeof(head),
		"SEED %08x:OFFSET %016llx:ROUND %016llx:PRIV:",
		result.seed32,
		static_cast<unsigned long long>(result.lane_id),
		static_cast<unsigned long long>(result.round));

	std::string out(head);
	append_hex_bytes_lower(out, result.priv, 32);
	return out;
}

static void append_profanity_line(std::vector<std::string>& lines,
	const std::string& prefix,
	const char* type,
	const std::string& payload) {
	std::string out;
	const size_t type_len = (type == nullptr) ? 0u : std::strlen(type);
	out.reserve(prefix.size() + type_len + payload.size() + 2u);
	out += prefix;
	out.push_back(':');
	if (type_len != 0u) {
		out.append(type, type_len);
	}
	out.push_back(':');
	out += payload;
	lines.push_back(std::move(out));
}

static std::vector<std::string> build_profanity_payloads(const ProfanityVerifiedResult& result, const bool save) {
	std::vector<std::string> lines;
	lines.reserve(2);

	const uint8_t type_code = result.type;
	const uint8_t* payload = result.payload;
	const uint32_t* payload_words = reinterpret_cast<const uint32_t*>(payload);
	bool is_ed = false;
	const char* type = byte_to_coin(type_code, is_ed);
	const std::string prefix = build_profanity_prefix(result);

	if (type_code == 0x02) {
		if (save) {
			append_profanity_line(lines, prefix, type, hash160ToBase58_d(payload, 0x00));
			char output[86] = { 0 };
			segwit_addr_encode(output, "bc", 0, payload, 20);
			append_profanity_line(lines, prefix, "P2WPKH", output);
		}
		else {
			append_profanity_line(lines, prefix, type, build_hash_payload_words(payload_words, 5));
		}
		return lines;
	}
	if (type_code == 0x01) {
		append_profanity_line(lines, prefix, type, save ? hash160ToBase58_d(payload, 0x00) : build_hash_payload_words(payload_words, 5));
		return lines;
	}
	if (type_code == 0x03) {
		append_profanity_line(lines, prefix, type, save ? hash160ToBase58_d(payload, 0x05) : build_hash_payload_words(payload_words, 5));
		return lines;
	}
	if (type_code == 0x04) {
		if (save) {
			char output[86] = { 0 };
			segwit_addr_encode(output, "bc", 1, payload, 32);
			append_profanity_line(lines, prefix, type, output);
		}
		else {
			append_profanity_line(lines, prefix, type, build_hash_payload_words(payload_words, 8));
		}
		return lines;
	}
	if (type_code == 0x07) {
		if (save) {
			char output[86] = { 0 };
			segwit_addr_encode(output, "bc", 0, payload, 32);
			append_profanity_line(lines, prefix, type, output);
		}
		else {
			append_profanity_line(lines, prefix, type, build_hash_payload_words(payload_words, 8));
		}
		return lines;
	}
	if (type_code == 0x05) {
		append_profanity_line(lines, prefix, type, build_hex_bytes_lower((result.payload_len == 32u) ? payload : result.x32, 32));
		return lines;
	}
	if (type_code == 0x06) {
		append_profanity_line(lines, prefix, type, build_hash_payload_words(payload_words, 5, save));
		return lines;
	}

	if (result.payload_len == 32u || found_hash_is_32_bytes(type_code)) {
		append_profanity_line(lines, prefix, type, build_hash_payload_words(payload_words, 8));
	}
	else {
		append_profanity_line(lines, prefix, type, build_hash_payload_words(payload_words, 5));
	}
	return lines;
}

static inline bool save_profanity_cpu_postcheck_and_count(uint32_t* pFounds, const ProfanityVerifiedResult& result) {
	if (useBloomCPU || useXorCPU) {
		hash160_t to_check{};
		if (endo_base_type_or_self(result.type) == 0x07u && result.payload_len == 32u) {
			uint8_t p2wsh_rmd[20] = { 0 };
			ripemd160_32(const_cast<uint8_t*>(result.payload), p2wsh_rmd);
			std::memcpy(to_check.uc, p2wsh_rmd, 20);
		}
		else {
			size_t n = static_cast<size_t>(result.payload_len);
			if (n > sizeof(to_check.uc)) {
				n = sizeof(to_check.uc);
			}
			if (n > 0u) {
				std::memcpy(to_check.uc, result.payload, n);
			}
		}
		if (!save_worker_find_in_bloom(to_check)) {
			increment_false_positive();
			return false;
		}
	}
	increment_founds(pFounds);
	return true;
}

static void SaveResultProfanity_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	bool cpu_postcheck,
	ProfanityVerifiedResult* results,
	unsigned long long count) {
	bool wrote_file = false;
	for (unsigned long long i = 0; i < count; ++i) {
		if (cpu_postcheck) {
			if (!save_profanity_cpu_postcheck_and_count(pFounds, results[i])) {
				continue;
			}
		}
		else {
			increment_founds(pFounds);
		}

		const std::vector<std::string> payloads = build_profanity_payloads(results[i], save);
		for (const std::string& payload : payloads) {
			if (save && file != nullptr) {
				std::lock_guard<std::mutex> lock(g_save_output_mutex);
				std::fwrite(payload.data(), 1, payload.size(), file);
				std::fwrite("\n", 1, 1, file);
				wrote_file = true;
			}
			if (!Silent) {
				(void)save_output_write_prebuilt(stdout, std::string("[!] Found: ") + payload);
			}
		}
	}
	if (wrote_file && file != nullptr) {
		std::lock_guard<std::mutex> lock(g_save_output_mutex);
		std::fflush(file);
	}

	delete[] results;
	STOP_THREAD = false;
}

static void SaveResultProfanityImpl(FILE* file, uint32_t& Founds, bool save, const ProfanityVerifiedResult* results, unsigned long long count, bool cpu_postcheck) {
	if (results == nullptr || count == 0ull) {
		return;
	}
	if (count > static_cast<unsigned long long>(MAX_FOUNDS)) {
		count = static_cast<unsigned long long>(MAX_FOUNDS);
	}

	STOP_THREAD = true;
	ProfanityVerifiedResult* owned = new ProfanityVerifiedResult[static_cast<size_t>(count)];
	std::memcpy(owned, results, static_cast<size_t>(count) * sizeof(ProfanityVerifiedResult));
	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("profanity", static_cast<size_t>(count), save,
			SaveResultProfanity_Worker, file, &Founds, save, cpu_postcheck, owned, count);
	}

	if (FULL) {
		flush_all_async_save_queues();
	}
}

METAL_HOST void SaveResultProfanity(FILE* file, uint32_t& Founds, bool save, const ProfanityVerifiedResult* results, unsigned long long count) {
	SaveResultProfanityImpl(file, Founds, save, results, count, true);
}

METAL_HOST void SaveResultProfanityRecovery(FILE* file, uint32_t& Founds, bool save, const ProfanityRecoveryVerifiedResult* results, unsigned long long count) {
	SaveResultProfanityImpl(file, Founds, save, results, count, false);
}

static inline std::string wallet_result_target_label(const std::vector<std::string>& labels, uint32_t index) {
	if (index < labels.size()) {
		return sanitize_visible_utf8(labels[index]);
	}
	return std::string("target#") + std::to_string(index);
}

static inline std::string wallet_result_password_label(const WalletModeResult& r) {
	const size_t n = std::min<size_t>(r.password_len, WALLET_MAX_PASSWORD_LEN);
	bool printable = true;
	for (size_t i = 0; i < n; ++i) {
		const uint8_t c = r.password[i];
		if (c < 0x20u || c > 0x7eu || c == ':' || c == '\r' || c == '\n') {
			printable = false;
			break;
		}
	}
	if (printable) {
		return std::string(reinterpret_cast<const char*>(r.password), n);
	}
	return std::string("hex(") + build_hex_bytes_lower(r.password, n) + ")";
}

static inline void wallet_append_found_line(FILE* file, uint32_t& Founds, bool save, const std::string& line) {
	increment_founds(&Founds);
	if (save && file != nullptr) {
		(void)save_output_write_prebuilt(file, line + "\n");
	}
	if (!Silent) {
		(void)save_output_write_prebuilt(stdout, std::string("\n[!] Found: ") + line + "\n");
	}
	save_output_flush(file);
}

static inline std::string wallet_payload_hex(const WalletModeResult& r) {
	return build_hex_bytes_lower(r.payload, std::min<size_t>(r.payload_len, WALLETDAT_MAX_PUBKEY_LEN));
}

static inline const char* wallet_browser_profile_name(uint8_t profile) {
	switch (profile) {
	case BROWSERVAULT_PROFILE_METAMASK_AES_GCM: return "metamask-browser-passworder";
	case BROWSERVAULT_PROFILE_PHANTOM_SECRETBOX_PBKDF2: return "phantom-secretbox-pbkdf2";
	case BROWSERVAULT_PROFILE_PHANTOM_SECRETBOX_SCRYPT: return "phantom-secretbox-scrypt";
	case BROWSERVAULT_PROFILE_ATOMIC_CRYPTOJS_AES: return "atomic-cryptojs-aes";
	case BROWSERVAULT_PROFILE_STELLAR_AES_GCM: return "stellar-pbkdf2-aes-gcm";
	case BROWSERVAULT_PROFILE_BISQ_SCRYPT_AES: return "bisq-scrypt-aes";
	case BROWSERVAULT_PROFILE_MULTIBIT_HD_SCRYPT_AES: return "multibit-hd-scrypt-aes";
	case BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_MD5_AES: return "multibit-classic-md5-aes";
	case BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_SCRYPT_AES: return "multibit-classic-scrypt-aes";
	case BROWSERVAULT_PROFILE_DOGECHAIN_PBKDF2_AES_CBC: return "dogechain-sha256b64-pbkdf2-aes-cbc";
	case BROWSERVAULT_PROFILE_BLOCKCHAIN_V2_PBKDF2_AES_CBC: return "blockchain-pbkdf2-sha1-aes-cbc";
	case BROWSERVAULT_PROFILE_ETHPRESALE_PBKDF2_AES_CBC: return "ethpresale-pbkdf2-aes-cbc";
	case BROWSERVAULT_PROFILE_BIP38_NON_EC: return "bip38-non-ec-scrypt-aes";
	case BROWSERVAULT_PROFILE_BIP38_EC: return "bip38-ec-multiply-scrypt-aes";
	case BROWSERVAULT_PROFILE_ANDROID_BACKUP_PBKDF2_SHA1_AES_CBC: return "android-backup-pbkdf2-sha1-aes-cbc";
	case BROWSERVAULT_PROFILE_SUBSTRATE_SCRYPT_PKCS8: return "substrate-v3-scrypt-pkcs8";
	case BROWSERVAULT_PROFILE_SUBSTRATE_LEGACY_PKCS8: return "substrate-v2-legacy-pkcs8";
	case BROWSERVAULT_PROFILE_COPAY_SJCL_AES_CCM: return "copay-sjcl-pbkdf2-aes-ccm";
	default: return "unknown";
	}
}

static inline const char* wallet_browser_result_prefix(uint8_t profile) {
	switch (profile) {
	case BROWSERVAULT_PROFILE_STELLAR_AES_GCM: return "STELLARWALLET";
	case BROWSERVAULT_PROFILE_BISQ_SCRYPT_AES: return "BISQWALLET";
	case BROWSERVAULT_PROFILE_MULTIBIT_HD_SCRYPT_AES: return "MULTIBITWALLET";
	case BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_MD5_AES: return "MULTIBITWALLET";
	case BROWSERVAULT_PROFILE_MULTIBIT_CLASSIC_SCRYPT_AES: return "MULTIBITWALLET";
	case BROWSERVAULT_PROFILE_DOGECHAIN_PBKDF2_AES_CBC: return "DOGECHAINWALLET";
	case BROWSERVAULT_PROFILE_BLOCKCHAIN_V2_PBKDF2_AES_CBC: return "BLOCKCHAINWALLET";
	case BROWSERVAULT_PROFILE_ETHPRESALE_PBKDF2_AES_CBC: return "ETHPRESALE";
	case BROWSERVAULT_PROFILE_BIP38_NON_EC: return "BIP38";
	case BROWSERVAULT_PROFILE_BIP38_EC: return "BIP38";
	case BROWSERVAULT_PROFILE_ANDROID_BACKUP_PBKDF2_SHA1_AES_CBC: return "ANDROIDWALLET";
	case BROWSERVAULT_PROFILE_SUBSTRATE_SCRYPT_PKCS8: return "SUBSTRATEWALLET";
	case BROWSERVAULT_PROFILE_SUBSTRATE_LEGACY_PKCS8: return "SUBSTRATEWALLET";
	case BROWSERVAULT_PROFILE_COPAY_SJCL_AES_CCM: return "COPAYWALLET";
	default: return "BROWSERVAULT";
	}
}

static inline const char* wallet_electrum_type_name(uint8_t type) {
	switch (type) {
	case ELECTRUMWALLET_TARGET_BIE1: return "BIE1";
	case ELECTRUMWALLET_TARGET_FIELD_V1: return "FIELD";
	case ELECTRUMWALLET_TARGET_PLAINTEXT: return "PLAINTEXT";
	default: return "UNKNOWN";
	}
}

METAL_HOST void SaveResultKeystore(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files) {
	if (results == nullptr) return;
	for (unsigned long long i = 0; i < count; ++i) {
		const WalletModeResult& r = results[i];
		const std::string target = wallet_result_target_label(target_files, r.target_index);
		const std::string pass = wallet_result_password_label(r);
		std::string line = "KEYSTORE:" + target + ":PASSWORD:" + pass;
		if (r.type == WALLET_KEYSTORE_RESULT_MAC_ONLY) {
			line += ":VAULT:" + wallet_payload_hex(r) + ":PROFILE:web3-secret-storage-mac";
		}
		else {
			line += ":PRIV:" + build_hex_bytes_lower(r.priv, 32u) + ":ETH:0x" + build_hex_bytes_lower(r.payload, 20u);
		}
		wallet_append_found_line(file, Founds, save, line);
	}
}

METAL_HOST void SaveResultWalletDat(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files) {
	if (results == nullptr) return;
	for (unsigned long long i = 0; i < count; ++i) {
		const WalletModeResult& r = results[i];
		const std::string target = wallet_result_target_label(target_files, r.target_index);
		const std::string pass = wallet_result_password_label(r);
		std::string line = "WALLETDAT:" + target + ":PASSWORD:" + pass;
		if (r.type == WALLET_DAT_RESULT_MKEY_ONLY) {
			line += ":MKEY:" + wallet_payload_hex(r) + ":PROFILE:bitcoin-core-mkey-only";
		}
		else {
			line += ":PRIV:" + build_hex_bytes_lower(r.priv, 32u) + ":PUBKEY:" + wallet_payload_hex(r);
		}
		wallet_append_found_line(file, Founds, save, line);
	}
}

METAL_HOST void SaveResultWalletJS(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& profiles) {
	if (results == nullptr) return;
	for (unsigned long long i = 0; i < count; ++i) {
		const WalletModeResult& r = results[i];
		bool is_ed = false;
		const char* type = byte_to_coin(r.type, is_ed);
		const std::string profile = wallet_result_target_label(profiles, r.target_index);
		std::string payload = wallet_payload_hex(r);
		if (r.type == 0x06u && r.payload_len == 20u) payload = "0x" + payload;
		if (save && endo_base_type_or_self(r.type) == 0x07u && r.payload_len == 32u) {
			char output[86] = { 0 };
			segwit_addr_encode(output, "bc", 0, r.payload, 32);
			payload = output;
		}
		const std::string line = "WALLETJS:" + profile + ":SOURCE:" + wallet_result_password_label(r) +
			":PRIV:" + build_hex_bytes_lower(r.priv, 32u) + ":" + type + ":" + payload;
		wallet_append_found_line(file, Founds, save, line);
	}
}

METAL_HOST void SaveResultBrowserVault(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files) {
	if (results == nullptr) return;
	for (unsigned long long i = 0; i < count; ++i) {
		const WalletModeResult& r = results[i];
		if (r.mode == WALLET_MODE_ETHPRESALE || r.type == BROWSERVAULT_PROFILE_ETHPRESALE_PBKDF2_AES_CBC) {
			const std::string line = std::string("ETHPRESALE:") + wallet_result_target_label(target_files, r.target_index) +
				":PASSWORD:" + wallet_result_password_label(r) +
				":PRIV:" + build_hex_bytes_lower(r.priv, 32u) +
				":ETH:0x" + build_hex_bytes_lower(r.payload, 20u);
			wallet_append_found_line(file, Founds, save, line);
			continue;
		}
		if (r.mode == WALLET_MODE_BIP38) {
			bool is_ed = false;
			const char* type = byte_to_coin(r.type, is_ed);
			const uint8_t profile = r.reserved[0] != 0u ? r.reserved[0] : BROWSERVAULT_PROFILE_BIP38_NON_EC;
			const std::string line = std::string("BIP38:") + wallet_result_target_label(target_files, r.target_index) +
				":PASSWORD:" + wallet_result_password_label(r) +
				":PRIV:" + build_hex_bytes_lower(r.priv, 32u) +
				":" + type + ":" + build_hex_bytes_lower(r.payload, 20u) +
				":PROFILE:" + wallet_browser_profile_name(profile);
			wallet_append_found_line(file, Founds, save, line);
			continue;
		}
		const std::string line = std::string(wallet_browser_result_prefix(r.type)) + ":" + wallet_result_target_label(target_files, r.target_index) +
			":PASSWORD:" + wallet_result_password_label(r) +
			":VAULT:" + wallet_payload_hex(r) +
			":PROFILE:" + wallet_browser_profile_name(r.type);
		wallet_append_found_line(file, Founds, save, line);
	}
}

METAL_HOST void SaveResultExodusSeco(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files) {
	if (results == nullptr) return;
	for (unsigned long long i = 0; i < count; ++i) {
		const WalletModeResult& r = results[i];
		const std::string line = "EXODUSSECO:" + wallet_result_target_label(target_files, r.target_index) +
			":PASSWORD:" + wallet_result_password_label(r) +
			":VAULT:" + wallet_payload_hex(r) +
			":PROFILE:seco-v0-scrypt-aes";
		wallet_append_found_line(file, Founds, save, line);
	}
}

METAL_HOST void SaveResultElectrumWallet(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files) {
	if (results == nullptr) return;
	for (unsigned long long i = 0; i < count; ++i) {
		const WalletModeResult& r = results[i];
		const std::string line = "ELECTRUMWALLET:" + wallet_result_target_label(target_files, r.target_index) +
			":PASSWORD:" + wallet_result_password_label(r) +
			":TYPE:" + wallet_electrum_type_name(r.type) +
			":DETAIL:" + wallet_payload_hex(r);
		wallet_append_found_line(file, Founds, save, line);
	}
}

METAL_HOST void SaveResultBitcoinJWallet(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files) {
	if (results == nullptr) return;
	for (unsigned long long i = 0; i < count; ++i) {
		const WalletModeResult& r = results[i];
		const char* prefix = (r.mode == WALLET_MODE_ANDROIDWALLET) ? "ANDROIDWALLET" : "BITCOINJWALLET";
		const std::string line = std::string(prefix) + ":" + wallet_result_target_label(target_files, r.target_index) +
			":PASSWORD:" + wallet_result_password_label(r) +
			":PRIV:" + build_hex_bytes_lower(r.priv, 32u) +
			":PUBKEY:" + wallet_payload_hex(r);
		wallet_append_found_line(file, Founds, save, line);
	}
}

METAL_HOST void SaveResultArmoryWallet(FILE* file, uint32_t& Founds, bool save, const WalletModeResult* results, unsigned long long count, const std::vector<std::string>& target_files) {
	if (results == nullptr) return;
	for (unsigned long long i = 0; i < count; ++i) {
		const WalletModeResult& r = results[i];
		const std::string line = "ARMORYWALLET:" + wallet_result_target_label(target_files, r.target_index) +
			":PASSWORD:" + wallet_result_password_label(r) +
			":PRIV:" + build_hex_bytes_lower(r.priv, 32u) +
			":PUBKEY:" + wallet_payload_hex(r);
		wallet_append_found_line(file, Founds, save, line);
	}
}

static inline const char* xp_profile_kind_name(uint8_t kind) {
	switch (kind) {
	case XP_PROFILE_OPENSSL: return "openssl";
	case XP_PROFILE_CGR_STATE: return "cgr-state";
	case XP_PROFILE_CGR_BRIDGE: return "cgr-bridge";
	case XP_PROFILE_SSLEAY_STIR: return "ssleay-stir";
	case XP_PROFILE_CGR_XOR: return "cgr-xor";
	case XP_PROFILE_CGR_CHAIN: return "cgr-chain";
	case XP_PROFILE_CGR_CHAIN_BRIDGE: return "cgr-chain-bridge";
	case XP_PROFILE_RAW32: return "raw32";
	case XP_PROFILE_RANDSTORM_JSBN: return "randstorm";
	case XP_PROFILE_RANDSTORM_PYMT: return "randstorm-pymt";
	case XP_PROFILE_RANDSTORM_MWC32: return "randstorm-mwc32";
	case XP_PROFILE_RANDSTORM_V8INIT: return "randstorm-v8init";
	case XP_PROFILE_RANDSTORM_BYTES: return "randstorm-bytes";
	case XP_PROFILE_RANDSTORM_CRYPTO1_JSBN: return "randstorm-crypto1-jsbn";
	case XP_PROFILE_RANDSTORM_V8INIT_BYTES: return "randstorm-v8init-bytes";
	case XP_PROFILE_RANDSTORM_V8INIT_POOL32: return "randstorm-v8init-pool32";
	case XP_PROFILE_PHPCOINADDRESS: return "phpcoinaddress";
	case XP_PROFILE_BLUEWALLET_ISAAC: return "bluewallet-isaac";
	case XP_PROFILE_TIME_LCG_DIRECT: return "time-lcg-direct";
	case XP_PROFILE_JAVA_LCG_DIRECT: return "java-lcg-direct";
	case XP_PROFILE_SHA256_DIRECT: return "sha256-direct";
	case XP_PROFILE_PID_HASH_DIRECT: return "pid-hash-direct";
	case XP_PROFILE_LOWBITS_DIRECT: return "lowbits-direct";
	case XP_PROFILE_TIME_MT: return "time-mt";
	default: return "unknown";
	}
}

static inline const char* xp_phpcoinaddress_variant_name(uint8_t variant) {
	switch (variant) {
	case 0u: return "php521";
	case 1u: return "php710";
	case 2u: return "phplegacy";
	default: return "unknown";
	}
}

static inline const char* xp_bluewallet_isaac_variant_name(uint8_t variant) {
	switch (variant) {
	case 0u: return "v0-cap255";
	case 1u: return "v2-cap256";
	default: return "unknown";
	}
}

static inline const char* xp_time_lcg_direct_variant_name(uint8_t variant) {
	switch (variant) {
	case 0u: return "glibc";
	case 1u: return "msvc";
	case 2u: return "borland";
	case 3u: return "dual-xor";
	case 4u: return "glibc-xor-pid";
	default: return "unknown";
	}
}

static inline const char* xp_java_lcg_direct_variant_name(uint8_t variant) {
	switch (variant) {
	case 0u: return "nextbytes";
	default: return "unknown";
	}
}

static inline const char* xp_sha256_direct_variant_name(uint8_t variant) {
	switch (variant) {
	case 0u: return "decimal";
	case 1u: return "hex";
	case 2u: return "phone10";
	case 3u: return "short-ascii";
	case 4u: return "be64";
	case 5u: return "be64d";
	default: return "unknown";
	}
}

static inline const char* xp_pid_hash_direct_variant_name(uint8_t variant) {
	switch (variant) {
	case 0u: return "sha256d-pid-be4";
	default: return "unknown";
	}
}

static inline const char* xp_lowbits_direct_variant_name(uint8_t variant) {
	switch (variant) {
	case 0u: return "be64";
	default: return "unknown";
	}
}

static inline const char* xp_time_mt_variant_name(uint8_t variant) {
	switch (variant) {
	case 0u: return "mt19937-u32-le-limbs";
	default: return "unknown";
	}
}

static inline const char* xp_randstorm_result_profile_name(uint8_t profile) {
	static const char* engines[] = {
		"v8-2011", "v8-2015", "spidermonkey-lcg48", "jsc-weakrandom",
		"v8-classic-mwc", "v8-alt-mwc", "v8-mwc1616", "lcg32"
	};
	static const char* groups[] = {
		"jsbn", "raw32", "jsbn-lohi", "raw32-lohi",
		"pool32", "pool32-lohi", "raw32-drop1", "raw32-drop1-lohi"
	};
	static thread_local char name[80];
	const uint32_t engine = profile % 8u;
	const uint32_t group = profile / 8u;
	if (engine >= 8u || group >= 8u) return "unknown";
	std::snprintf(name, sizeof(name), "%s-%s", engines[engine], groups[group]);
	return name;
}

static inline const char* xp_randstorm_bytes_result_profile_name(uint8_t profile) {
	static const char* engines[] = {
		"v8-2011", "v8-2015", "spidermonkey-lcg48", "jsc-weakrandom",
		"v8-classic-mwc", "v8-alt-mwc", "v8-mwc1616", "lcg32"
	};
	static thread_local char name[80];
	const uint32_t engine = profile % 8u;
	const uint32_t group = profile / 8u;
	if (engine >= 8u || group >= 2u) return "unknown";
	std::snprintf(name, sizeof(name), "%s-%s", engines[engine], group == 0u ? "byte8" : "low8-byte8");
	return name;
}

static inline const char* xp_randstorm_crypto1_jsbn_result_profile_name(uint8_t profile) {
	static const char* engines[] = {
		"v8-2011", "v8-2015", "spidermonkey-lcg48", "jsc-weakrandom",
		"v8-classic-mwc", "v8-alt-mwc", "v8-mwc1616", "lcg32"
	};
	static thread_local char name[96];
	const uint32_t engine = profile % 8u;
	if (engine >= 8u) return "unknown";
	std::snprintf(name, sizeof(name), "%s-randombytes1-jsbn", engines[engine]);
	return name;
}

static inline const char* xp_randstorm_mwc32_result_profile_name(uint8_t profile) {
	static const char* engines[] = {
		"v8-2011-state0", "v8-classic-mwc-state0", "v8-alt-mwc-state0", "v8-mwc1616-state0"
	};
	static const char* groups[] = {
		"jsbn", "raw32", "jsbn-lohi", "raw32-lohi",
		"pool32", "pool32-lohi", "raw32-drop1", "raw32-drop1-lohi",
		"byte8", "low8-byte8"
	};
	static thread_local char name[96];
	const uint32_t engine = profile % 4u;
	const uint32_t group = profile / 4u;
	if (engine >= 4u || group >= 10u) return "unknown";
	std::snprintf(name, sizeof(name), "%s-%s", engines[engine], groups[group]);
	return name;
}

static inline const char* xp_randstorm_v8init_result_profile_name(uint8_t profile) {
	static const char* engines[] = {
		"msvc-rand-v8-classic", "msvc-rand-v8-2011",
		"ansi-rand-v8-classic", "ansi-rand-v8-2011",
		"lrand48-v8-classic", "lrand48-v8-2011",
		"glibc-random-v8-classic", "glibc-random-v8-2011",
		"msvc-rand-v8-2015", "ansi-rand-v8-2015",
		"lrand48-v8-2015", "glibc-random-v8-2015",
		"msvc-rand-v8-alt-mwc", "ansi-rand-v8-alt-mwc",
		"lrand48-v8-alt-mwc", "glibc-random-v8-alt-mwc",
		"msvc-rand-v8-mwc1616", "ansi-rand-v8-mwc1616",
		"lrand48-v8-mwc1616", "glibc-random-v8-mwc1616"
	};
	static thread_local char name[96];
	const uint32_t engine = profile % 20u;
	const uint32_t group = profile / 20u;
	if (engine >= 20u || group >= 2u) return "unknown";
	if (group == 0u) {
		std::snprintf(name, sizeof(name), "%s", engines[engine]);
	}
	else {
		std::snprintf(name, sizeof(name), "%s-lohi", engines[engine]);
	}
	return name;
}

static inline const char* xp_randstorm_v8init_bytes_result_profile_name(uint8_t profile) {
	static const char* engines[] = {
		"msvc-rand-v8-classic", "msvc-rand-v8-2011",
		"ansi-rand-v8-classic", "ansi-rand-v8-2011",
		"lrand48-v8-classic", "lrand48-v8-2011",
		"glibc-random-v8-classic", "glibc-random-v8-2011",
		"msvc-rand-v8-2015", "ansi-rand-v8-2015",
		"lrand48-v8-2015", "glibc-random-v8-2015",
		"msvc-rand-v8-alt-mwc", "ansi-rand-v8-alt-mwc",
		"lrand48-v8-alt-mwc", "glibc-random-v8-alt-mwc",
		"msvc-rand-v8-mwc1616", "ansi-rand-v8-mwc1616",
		"lrand48-v8-mwc1616", "glibc-random-v8-mwc1616"
	};
	static thread_local char name[112];
	const uint32_t engine = profile % 20u;
	const uint32_t group = profile / 20u;
	if (engine >= 20u || group >= 2u) return "unknown";
	std::snprintf(name, sizeof(name), "%s-%s", engines[engine], group == 0u ? "byte8" : "low8-byte8");
	return name;
}

METAL_HOST void SaveResultXP(FILE* file, uint32_t& Founds, bool save, const XpReplayResult* results, unsigned long long count) {
	if (results == nullptr) return;
	for (unsigned long long i = 0; i < count; ++i) {
		const XpReplayResult& r = results[i];
		bool is_ed = false;
		const char* type = byte_to_coin(r.type, is_ed);
		std::string prefix = std::string("XP:PROFILE:") + xp_profile_kind_name(r.profile_kind);
		if (r.profile_kind == XP_PROFILE_OPENSSL) {
			char pid_buf[9];
			std::snprintf(pid_buf, sizeof(pid_buf), "%08x", r.pid);
			prefix += ":ARCH:" + std::string(xp_openssl_arch_name(r.reserved[0])) +
				":PATH:" + std::string(xp_openssl_path_name(r.path_id)) +
				":PID:" + std::string(pid_buf) +
				":KEY:" + std::to_string(r.key_index);
		}
		else if (r.profile_kind == XP_PROFILE_RANDSTORM_JSBN) {
			char state_buf[17];
			char time0_buf[9];
			char time1_buf[9];
			std::snprintf(state_buf, sizeof(state_buf), "%016llx", static_cast<unsigned long long>(r.source_state));
			std::snprintf(time0_buf, sizeof(time0_buf), "%08x", r.seed_time0);
			std::snprintf(time1_buf, sizeof(time1_buf), "%08x", r.seed_time1);
			prefix += ":ENGINE:" + std::string(xp_randstorm_result_profile_name(r.path_id)) +
				":STATE:" + std::string(state_buf) +
				":TIME0:" + std::string(time0_buf) +
				":TIME1:" + std::string(time1_buf) +
				":KEY:" + std::to_string(r.key_index);
			if (r.line_index != 0xffffffffu) {
				prefix += ":MILEAGE:" + std::to_string(r.line_index);
			}
			if (r.reserved[1] == 1u) {
				prefix += ":VAR:add1";
			}
		}
		else if (r.profile_kind == XP_PROFILE_RANDSTORM_BYTES) {
			char state_buf[17];
			std::snprintf(state_buf, sizeof(state_buf), "%016llx", static_cast<unsigned long long>(r.source_state));
			prefix += ":ENGINE:" + std::string(xp_randstorm_bytes_result_profile_name(r.path_id)) +
				":STATE:" + std::string(state_buf) +
				":KEY:" + std::to_string(r.key_index);
			if (r.line_index != 0xffffffffu) {
				prefix += ":MILEAGE:" + std::to_string(r.line_index);
			}
		}
		else if (r.profile_kind == XP_PROFILE_RANDSTORM_CRYPTO1_JSBN) {
			char state_buf[17];
			std::snprintf(state_buf, sizeof(state_buf), "%016llx", static_cast<unsigned long long>(r.source_state));
			prefix += ":ENGINE:" + std::string(xp_randstorm_crypto1_jsbn_result_profile_name(r.path_id)) +
				":STATE:" + std::string(state_buf) +
				":KEY:" + std::to_string(r.key_index);
			if (r.line_index != 0xffffffffu) {
				prefix += ":MILEAGE:" + std::to_string(r.line_index);
			}
		}
		else if (r.profile_kind == XP_PROFILE_RANDSTORM_PYMT) {
			char state_buf[17];
			std::snprintf(state_buf, sizeof(state_buf), "%016llx", static_cast<unsigned long long>(r.source_state));
			prefix += ":ENGINE:python-mt-randint8" +
				std::string(":SEED:") + std::string(state_buf) +
				":KEY:" + std::to_string(r.key_index);
		}
		else if (r.profile_kind == XP_PROFILE_PHPCOINADDRESS) {
			char seed_buf[17];
			std::snprintf(seed_buf, sizeof(seed_buf), "%016llx", static_cast<unsigned long long>(r.source_state));
			prefix += ":VARIANT:" + std::string(xp_phpcoinaddress_variant_name(r.path_id)) +
				":SEED:" + std::string(seed_buf) +
				":KEY:" + std::to_string(r.key_index);
		}
		else if (r.profile_kind == XP_PROFILE_BLUEWALLET_ISAAC) {
			char seed_buf[9];
			std::snprintf(seed_buf, sizeof(seed_buf), "%08x", static_cast<uint32_t>(r.source_state));
			prefix += ":VARIANT:" + std::string(xp_bluewallet_isaac_variant_name(r.path_id)) +
				":SEED:" + std::string(seed_buf) +
				":KEY:" + std::to_string(r.key_index);
		}
		else if (r.profile_kind == XP_PROFILE_TIME_LCG_DIRECT) {
			char seed_buf[9];
			std::snprintf(seed_buf, sizeof(seed_buf), "%08x", static_cast<uint32_t>(r.source_state));
			prefix += ":VARIANT:" + std::string(xp_time_lcg_direct_variant_name(r.path_id));
			if (r.path_id == 4u) {
				char time_buf[9];
				char pid_buf[9];
				std::snprintf(time_buf, sizeof(time_buf), "%08x", r.seed_time0);
				std::snprintf(pid_buf, sizeof(pid_buf), "%08x", r.seed_time1);
				prefix += ":TIME:" + std::string(time_buf) +
					":PID:" + std::string(pid_buf);
			}
			prefix += ":SEED:" + std::string(seed_buf) +
				":KEY:" + std::to_string(r.key_index);
		}
		else if (r.profile_kind == XP_PROFILE_JAVA_LCG_DIRECT) {
			char seed_buf[13];
			std::snprintf(seed_buf, sizeof(seed_buf), "%012llx", static_cast<unsigned long long>(r.source_state));
			prefix += ":VARIANT:" + std::string(xp_java_lcg_direct_variant_name(r.path_id)) +
				":SEED:" + std::string(seed_buf) +
				":KEY:" + std::to_string(r.key_index);
		}
		else if (r.profile_kind == XP_PROFILE_SHA256_DIRECT) {
			char input_buf[17];
			std::snprintf(input_buf, sizeof(input_buf), "%016llx", static_cast<unsigned long long>(r.source_state));
			prefix += ":VARIANT:" + std::string(xp_sha256_direct_variant_name(r.path_id)) +
				":INPUT:" + std::string(input_buf) +
				":KEY:" + std::to_string(r.key_index);
		}
		else if (r.profile_kind == XP_PROFILE_PID_HASH_DIRECT) {
			char pid_buf[9];
			std::snprintf(pid_buf, sizeof(pid_buf), "%08x", r.pid);
			prefix += ":VARIANT:" + std::string(xp_pid_hash_direct_variant_name(r.path_id)) +
				":PID:" + std::string(pid_buf) +
				":KEY:" + std::to_string(r.key_index);
		}
		else if (r.profile_kind == XP_PROFILE_LOWBITS_DIRECT) {
			char value_buf[17];
			std::snprintf(value_buf, sizeof(value_buf), "%016llx", static_cast<unsigned long long>(r.source_state));
			prefix += ":VARIANT:" + std::string(xp_lowbits_direct_variant_name(r.path_id)) +
				":VALUE:" + std::string(value_buf) +
				":KEY:" + std::to_string(r.key_index);
		}
		else if (r.profile_kind == XP_PROFILE_TIME_MT) {
			char seed_buf[9];
			std::snprintf(seed_buf, sizeof(seed_buf), "%08x", static_cast<uint32_t>(r.source_state));
			prefix += ":VARIANT:" + std::string(xp_time_mt_variant_name(r.path_id)) +
				":SEED:" + std::string(seed_buf) +
				":KEY:" + std::to_string(r.key_index);
		}
		else if (r.profile_kind == XP_PROFILE_RANDSTORM_MWC32) {
			char state_buf[9];
			char time0_buf[9];
			char time1_buf[9];
			std::snprintf(state_buf, sizeof(state_buf), "%08x", static_cast<uint32_t>(r.source_state));
			std::snprintf(time0_buf, sizeof(time0_buf), "%08x", r.seed_time0);
			std::snprintf(time1_buf, sizeof(time1_buf), "%08x", r.seed_time1);
			prefix += ":ENGINE:" + std::string(xp_randstorm_mwc32_result_profile_name(r.path_id)) +
				":STATE0:" + std::string(state_buf) +
				":TIME0:" + std::string(time0_buf) +
				":TIME1:" + std::string(time1_buf) +
				":KEY:" + std::to_string(r.key_index);
			if (r.line_index != 0xffffffffu) {
				prefix += ":MILEAGE:" + std::to_string(r.line_index);
			}
			if (r.reserved[1] == 1u) {
				prefix += ":VAR:add1";
			}
		}
		else if (r.profile_kind == XP_PROFILE_RANDSTORM_V8INIT) {
			char seed_buf[17];
			char time0_buf[9];
			char time1_buf[9];
			std::snprintf(seed_buf, sizeof(seed_buf), "%016llx", static_cast<unsigned long long>(r.source_state));
			std::snprintf(time0_buf, sizeof(time0_buf), "%08x", r.seed_time0);
			std::snprintf(time1_buf, sizeof(time1_buf), "%08x", r.seed_time1);
			prefix += ":ENGINE:" + std::string(xp_randstorm_v8init_result_profile_name(r.path_id)) +
				":SEED:" + std::string(seed_buf) +
				":TIME0:" + std::string(time0_buf) +
				":TIME1:" + std::string(time1_buf) +
				":KEY:" + std::to_string(r.key_index);
			if (r.line_index != 0xffffffffu) {
				prefix += ":MILEAGE:" + std::to_string(r.line_index);
			}
		}
		else if (r.profile_kind == XP_PROFILE_RANDSTORM_V8INIT_BYTES) {
			char seed_buf[17];
			std::snprintf(seed_buf, sizeof(seed_buf), "%016llx", static_cast<unsigned long long>(r.source_state));
			prefix += ":ENGINE:" + std::string(xp_randstorm_v8init_bytes_result_profile_name(r.path_id)) +
				":SEED:" + std::string(seed_buf) +
				":KEY:" + std::to_string(r.key_index);
			if (r.line_index != 0xffffffffu) {
				prefix += ":MILEAGE:" + std::to_string(r.line_index);
			}
		}
		else if (r.profile_kind == XP_PROFILE_RANDSTORM_V8INIT_POOL32) {
			char seed_buf[17];
			std::snprintf(seed_buf, sizeof(seed_buf), "%016llx", static_cast<unsigned long long>(r.source_state));
			prefix += ":ENGINE:" + std::string(xp_randstorm_v8init_result_profile_name(r.path_id)) + "-pool32" +
				":SEED:" + std::string(seed_buf) +
				":KEY:" + std::to_string(r.key_index);
			if (r.line_index != 0xffffffffu) {
				prefix += ":MILEAGE:" + std::to_string(r.line_index);
			}
		}
		else {
			prefix += ":LINE:" + std::to_string(r.line_index);
		}
		std::string payload = build_hex_bytes_lower(r.payload, std::min<size_t>(r.payload_len, XP_REPLAY_PAYLOAD_MAX));
		if (r.type == 0x06u && r.payload_len == 20u) payload = "0x" + payload;
		if (save && endo_base_type_or_self(r.type) == 0x07u && r.payload_len == 32u) {
			char output[86] = { 0 };
			segwit_addr_encode(output, "bc", 0, r.payload, 32);
			payload = output;
		}
		const std::string line = prefix + ":PRIV:" + build_hex_bytes_lower(r.priv, 32u) + ":" + type + ":" + payload;
		wallet_append_found_line(file, Founds, save, line);
	}
}


//Hmac save sunc.
static void SaveResultHmac_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	std::vector<std::string> Der_list,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type, int64_t* rounds,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}
		std::string found_der = "";
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		found_der = build_derivation_segment_ada_pair(Der_list, foundDerivation[i], foundDerivation2, i, coin_type[i]);

		std::string round = build_round_suffix(rounds[i], is_ed);

		const std::string selected = load_found_text_raw_cstr(&foundStrings[i][0], 511);
		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("hmac:", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}


	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] rounds;
	STOP_THREAD = false;
}

// Host helper: SaveResultHmac.
METAL_HOST void SaveResultHmac(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list)
{
	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	int64_t* rounds = new int64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	int64_t* dev_rounds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));

	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));

	save_clear_results_count_best_effort(__func__);



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("hmac", count, save, SaveResultHmac_Worker, file, &Founds, save, std::move(Der_list), foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, rounds, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}
}


//Seed save func.
static void SaveResultSeed_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	std::vector<std::string> Der_list,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1], int64_t* rounds,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::string selected = save_crypted_output_enabled()
			? build_crypted_source_text_from_found_bytes(&foundStrings[i][0], len_h[i][0])
			: build_binary_selected_text(&foundStrings[i][0], len_h[i][0]);
		std::string found_der = "";
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		found_der = build_derivation_segment_ada_pair(Der_list, foundDerivation[i], foundDerivation2, i, coin_type[i]);
		std::string round = build_round_suffix(rounds[i], is_ed);

		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("seed:", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] rounds;
	delete[] len_h;
	STOP_THREAD = false;
}

// Host helper: SaveResultSeed.
METAL_HOST void SaveResultSeed(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));

	save_clear_results_count_best_effort(__func__);


	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("seed", count, save, SaveResultSeed_Worker, file, &Founds, save, std::move(Der_list), foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, len_h, rounds, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}


//Bip32 passphrase save func.
static void SaveResultBip32_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	std::vector<std::string> Der_list,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1],
	uint32_t(*iter_h)[1], int64_t* rounds,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::string selected;
		std::string selected_open_suffix;
		if (save_crypted_output_enabled()) {
			selected = build_crypted_visible_source_text(&foundStrings[i][0], len_h[i][0]);
			selected_open_suffix = ":ITERATION ";
			selected_open_suffix += std::to_string(iter_h[i][0]);
		}
		else {
			selected = build_binary_selected_text(&foundStrings[i][0], len_h[i][0]);
			selected += ":ITERATION ";
			selected += std::to_string(iter_h[i][0]);
		}
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		std::string found_der = "";
		found_der = build_derivation_segment_ada_pair(Der_list, foundDerivation[i], foundDerivation2, i, coin_type[i]);

		std::string round = build_round_suffix(rounds[i], is_ed);

		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("Bip32 passphrase:", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ", selected_open_suffix);
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] len_h;
	delete[] iter_h;
	delete[] coin_type;
	delete[] rounds;
	STOP_THREAD = false;
}

// Host helper: SaveResultBip32.
METAL_HOST void SaveResultBip32(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	uint32_t(*iter_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	uint32_t(*dev_iter)[1] = nullptr;
	int64_t* dev_rounds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_iter, d_iter, sizeof(dev_iter));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));

	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(iter_h, dev_iter, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_iter, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));

	save_clear_results_count_best_effort(__func__);




	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("bip32", count, save, SaveResultBip32_Worker, file, &Founds, save, std::move(Der_list), foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, len_h, iter_h, rounds, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}


//Brain save func.
static void SaveResultBrain_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char          (*foundStrings)[512],
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1],
	uint32_t(*iter_h)[1], int64_t* rounds,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		const bool crypted_output = save_crypted_output_enabled();
		const std::string selected = crypted_output
			? build_crypted_source_text_from_found_bytes(&foundStrings[i][0], len_h[i][0])
			: build_brain_selected_label(&foundStrings[i][0], len_h[i][0], iter_h[i][0]);
		std::string selected_open_suffix;
		if (crypted_output) {
			selected_open_suffix = ":ITERATION ";
			selected_open_suffix += std::to_string(iter_h[i][0]);
		}
		try {
			emit_brain_like_result(file, selected, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save, selected_open_suffix);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] len_h;
	delete[] iter_h;
	delete[] coin_type;
	delete[] rounds;
	STOP_THREAD = false;
}

// Host helper: SaveResultBrain.
METAL_HOST void SaveResultBrain(FILE* file, uint32_t& Founds, bool save, const vector<string>& Der_list) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	uint32_t(*iter_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	uint32_t(*dev_iter)[1] = nullptr;
	int64_t* dev_rounds = nullptr;

	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_iter, d_iter, sizeof(dev_iter));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));

	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(iter_h, dev_iter, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_iter, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));

	save_clear_results_count_best_effort(__func__);





	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("brain", count, save, SaveResultBrain_Worker, file, &Founds, save, foundStrings, foundPrvKeys, foundHash160, coin_type, len_h, iter_h, rounds, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}


static void SaveResultBrainGen_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char          (*foundStrings)[512],
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1],
	uint32_t(*iter_h)[1], int64_t* rounds, uint64_t* seeds,
	unsigned long long count, int bytes, int mode, int gen, int skipBytes) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		const std::string selected = build_brain_gen_selected_label(&foundStrings[i][0], len_h[i][0], iter_h[i][0], bytes, mode, gen, skipBytes, seeds[i]);
		try {
			emit_brain_like_result(file, selected, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] len_h;
	delete[] iter_h;
	delete[] coin_type;
	delete[] rounds;
	STOP_THREAD = false;
}

// Host helper: SaveResultBrainGen.
METAL_HOST void SaveResultBrainGen(FILE* file, uint32_t& Founds, bool save, const vector<string>& Der_list, int bytes, int mode, int gen, int skipBytes) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	uint32_t(*iter_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];
	uint64_t* seeds = new uint64_t[count];


	char          (*dev_foundStrings)[512] = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	uint32_t(*dev_iter)[1] = nullptr;
	int64_t* dev_rounds = nullptr;
	uint64_t* dev_seeds = nullptr;


	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_iter, d_iter, sizeof(dev_iter));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));
	metalReadStateValue(&dev_seeds, d_seed, sizeof(dev_seeds));


	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(iter_h, dev_iter, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);
	metalMemcpy(seeds, dev_seeds, count * sizeof(uint64_t), metalMemcpyDeviceToHost);


	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_iter, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));
	metalMemset(dev_seeds, 0, count * sizeof(uint64_t));


	save_clear_results_count_best_effort(__func__);





	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("brain_gen", count, save, SaveResultBrainGen_Worker, file, &Founds, save, foundStrings, foundPrvKeys, foundHash160, coin_type, len_h, iter_h, rounds, seeds, count, bytes, mode, gen, skipBytes
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}


// Byte-mode save worker.
static void SaveResultByte_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	std::vector<std::string> Der_list,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	char (*foundPass)[128], uint16_t* foundPassSize,
	uint32_t(*len_h)[1], int64_t* rounds,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}
		std::string found_der = "";
		if (BIP39_Pass) {
			found_der = build_bip39_pass_derivation_prefix(foundPass, foundPassSize, foundStrings, len_h, i, count);
		}
		found_der += build_derivation_segment_ada_pair(Der_list, foundDerivation[i], foundDerivation2, i, coin_type[i]);

		std::string selected;
		selected = load_found_text_sanitized(&foundStrings[i][0], len_h[i][0], 511);

		selected = sanitize_visible_utf8(std::move(selected));
		if (!save_crypted_output_enabled()) {
			string hexed;
			hexed.resize((len_h[i][0] * 2));

			hexing_host((uint8_t*)&foundStrings[i], len_h[i][0], (uint8_t*)hexed.data(), (len_h[i][0] * 2));
			selected += ":hex(";
			selected.append(hexed);
			selected += ")";
		}
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		std::string round = build_round_suffix(rounds[i], is_ed);

		const StandardKeyEmitHeads heads = make_standard_key_emit_heads_explicit(
			build_standard_worker_head("", selected, found_der),
			build_standard_worker_head("\n[!] Found: ", selected, found_der),
			"\n[!] Found: " + selected + ": " + found_der + ":",
			"\n[!] Found: " + selected + ": " + found_der + ":");
		try {
			emit_byte_result(file, heads, selected, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save, foundDerivation[i]);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}


	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] len_h;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] foundPass;
	delete[] rounds;
	STOP_THREAD = false;
}

// Host helper: SaveResultByte.
METAL_HOST void SaveResultByte(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list)
{
	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	char (*foundPass)[128];
	uint16_t* foundPassSize;
	if (BIP39_Pass) {
		foundPass = new char[count][128];
		foundPassSize = new uint16_t[count];
	}
	else
	{
		foundPass = nullptr;
		foundPassSize = nullptr;
	}

	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	char (*dev_pass)[128] = nullptr;
	uint16_t* dev_passSize = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	if (BIP39_Pass) {
		metalReadStateValue(&dev_pass, d_pass, sizeof(dev_pass));
		metalReadStateValue(&dev_passSize, d_pass_size, sizeof(dev_passSize));
	}
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));

	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	if (BIP39_Pass) {
		metalMemcpy(foundPass, dev_pass, count * 128 * sizeof(char), metalMemcpyDeviceToHost);
		metalMemcpy(foundPassSize, dev_passSize, count * sizeof(uint16_t), metalMemcpyDeviceToHost);
	}
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	if (BIP39_Pass) {
		metalMemset(dev_pass, 0, count * 128 * sizeof(char));
		metalMemset(dev_passSize, 0, count * sizeof(uint16_t));
	}
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));

	save_clear_results_count_best_effort(__func__);



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("byte", count, save, SaveResultByte_Worker, file, &Founds, save, std::move(Der_list), foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, foundPass, foundPassSize, len_h, rounds, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}


//Hmac PRNG save func.
static void SaveResultHmacGen_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	std::vector<std::string> Der_list,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type, int64_t* rounds, uint64_t* seeds,
	unsigned long long count, int bytes, int mode, int gen, int skipBytes) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}
		std::string found_der = "";
		std::ostringstream oss;
		string derivat = build_derivation_segment_ada_pair(Der_list, foundDerivation[i], foundDerivation2, i, coin_type[i]);
		oss << "Byte " << bytes << ":Shift " << skipBytes << ":Gen " << gen << ":Mode " << mode;
		uint64_t seed = seeds[i];
		oss << ":Seed " << std::hex << std::nouppercase << seed << ":" << derivat;
		found_der += oss.str();
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		std::string round = build_round_suffix(rounds[i], is_ed);

		const std::string selected = load_found_text_raw_cstr(&foundStrings[i][0], 511);
		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("hmac:", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}



	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] rounds;
	STOP_THREAD = false;
}

// Host helper: SaveResultHmacGen.
METAL_HOST void SaveResultHmacGen(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list, int bytes, int mode, int gen, int skipBytes) {


	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	int64_t* rounds = new int64_t[count];
	uint64_t* seeds = new uint64_t[count];


	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	int64_t* dev_rounds = nullptr;
	uint64_t* dev_seeds = nullptr;


	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));
	metalReadStateValue(&dev_seeds, d_seed, sizeof(dev_seeds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);
	metalMemcpy(seeds, dev_seeds, count * sizeof(uint64_t), metalMemcpyDeviceToHost);


	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));
	metalMemset(dev_seeds, 0, count * sizeof(uint64_t));


	save_clear_results_count_best_effort(__func__);




	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("hmac_gen", count, save, SaveResultHmacGen_Worker, file, &Founds, save, std::move(Der_list), foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, rounds, seeds, count, bytes, mode, gen, skipBytes
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}


//Seed PRNG save func.
static void SaveResultSeedGen_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	std::vector<std::string> Der_list,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1], int64_t* rounds, uint64_t* seeds,
	unsigned long long count, int bytes, int mode, int gen, int skipBytes) {
	for (int i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}
		std::string found_der = "";
		std::ostringstream oss;
		string derivat = build_derivation_segment_ada_pair(Der_list, foundDerivation[i], foundDerivation2, i, coin_type[i]);
		oss << "Byte " << bytes << ":Shift " << skipBytes << ":Gen " << gen << ":Mode " << mode;
		uint64_t seed = seeds[i];
		oss << ":Seed " << std::hex << std::nouppercase << seed << ":" << derivat;
		found_der += oss.str();
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);

		std::string round = build_round_suffix(rounds[i], is_ed);

		const std::string selected = build_binary_selected_text(&foundStrings[i][0], len_h[i][0]);
		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("seed:", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}


	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] len_h;
	delete[] rounds;
	delete[] seeds;
	STOP_THREAD = false;
}

// Host helper: SaveResultSeedGen.
METAL_HOST void SaveResultSeedGen(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list, int bytes, int mode, int gen, int skipBytes) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];
	uint64_t* seeds = new uint64_t[count];


	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;
	uint64_t* dev_seeds = nullptr;


	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));
	metalReadStateValue(&dev_seeds, d_seed, sizeof(dev_seeds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);
	metalMemcpy(seeds, dev_seeds, count * sizeof(uint64_t), metalMemcpyDeviceToHost);


	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));
	metalMemset(dev_seeds, 0, count * sizeof(uint64_t));


	save_clear_results_count_best_effort(__func__);




	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("seed_gen", count, save, SaveResultSeedGen_Worker, file, &Founds, save, std::move(Der_list), foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, len_h, rounds, seeds, count, bytes, mode, gen, skipBytes
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}


//Mnemonic PRNG save func.
static void SaveResultGen_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	std::vector<std::string> Der_list,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1],
	char (*foundPass)[128], uint16_t* foundPassSize, int64_t* rounds, uint64_t* seeds,
	unsigned long long count, int bytes, int mode, int gen, int skipBytes) {

	for (uint64_t i = 0; i < count; i++) {


		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}
		std::string found_der = "";
		if (BIP39_Pass) {
			found_der = build_bip39_pass_derivation_prefix(foundPass, foundPassSize, foundStrings, len_h, i, count);
		}
		string derivat = build_derivation_segment_ada_pair(Der_list, foundDerivation[i], foundDerivation2, i, coin_type[i]);
		std::ostringstream oss;
		oss << "Byte " << bytes << ":Shift " << skipBytes << ":Gen " << gen << ":Mode " << mode ;
		uint64_t seed = seeds[i];
		oss << ":Seed " << std::hex << std::nouppercase << seed <<":" << derivat;
		found_der += oss.str();
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		std::string round = build_round_suffix(rounds[i], is_ed);

		std::string selected;
		selected = load_found_text_sanitized(&foundStrings[i][0], len_h[i][0], 511);

		const StandardKeyEmitHeads heads = make_standard_key_emit_heads_explicit(
			build_standard_worker_head("", selected, found_der),
			build_standard_worker_head("\n[!] Found: ", selected, found_der),
			build_standard_worker_head("\n[!] Found: ", selected, found_der),
			build_standard_worker_head("\n[!] Found: ", selected, found_der));
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}



	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] len_h;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] foundPass;
	delete[] foundPassSize;
	delete[] rounds;
	delete[] seeds;
	STOP_THREAD = false;
}

// Host helper: SaveResultGen.
METAL_HOST void SaveResultGen(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list, int bytes, int mode, int gen, int skipBytes) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	char (*foundPass)[128] = new char[count][128]();
	uint16_t* foundPassSize = new uint16_t[count]();
	int64_t* rounds = new int64_t[count];
	uint64_t* seeds = new uint64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	char (*dev_pass)[128] = nullptr;
	uint16_t* dev_passSize = nullptr;
	int64_t* dev_rounds = nullptr;
	uint64_t* dev_seeds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	if (BIP39_Pass) {
		metalReadStateValue(&dev_pass, d_pass, sizeof(dev_pass));
		metalReadStateValue(&dev_passSize, d_pass_size, sizeof(dev_passSize));
	}
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));
	metalReadStateValue(&dev_seeds, d_seed, sizeof(dev_seeds));

	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	if (BIP39_Pass) {
		metalMemcpy(foundPass, dev_pass, count * 128 * sizeof(char), metalMemcpyDeviceToHost);
		metalMemcpy(foundPassSize, dev_passSize, count * sizeof(uint16_t), metalMemcpyDeviceToHost);
	}
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);
	metalMemcpy(seeds, dev_seeds, count * sizeof(uint64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	if (BIP39_Pass) {
		metalMemset(dev_pass, 0, count * 128 * sizeof(char));
		metalMemset(dev_passSize, 0, count * sizeof(uint16_t));
	}
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));
	metalMemset(dev_seeds, 0, count * sizeof(uint64_t));

	save_clear_results_count_best_effort(__func__);

	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("mnemonic_gen", count, save,
			SaveResultGen_Worker, file, &Founds, save,
			std::move(Der_list),
			foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160,
			coin_type, len_h, foundPass, foundPassSize, rounds, seeds,
			count, bytes, mode, gen, skipBytes
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}
}

//PRIV PRNG save func.
static void SaveResultPRIVGen_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type, int64_t* rounds, uint64_t* seeds,
	unsigned long long count, int bytes, int mode, int gen, int skipBytes) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::ostringstream oss;
		oss << "Byte " << bytes << ":Shift " << skipBytes << ":Gen " << gen << ":Mode " << mode;
		const uint64_t seed = seeds[i];
		oss << ":Seed " << std::hex << std::nouppercase << seed;
		const std::string found_der = oss.str();
		const PrivEmitHeads heads = make_priv_emit_heads(
			"priv:" + found_der + ":",
			"\n[!] Found: priv:" + found_der + ":",
			"\n[!] Found: priv:" + found_der + ":",
			"",
			"\n[!] Found: ");
		emit_priv_worker_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save, false, 5);
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] rounds;
	delete[] seeds;
	STOP_THREAD = false;
}

// Host helper: SaveResultPRIVGen.
METAL_HOST void SaveResultPRIVGen(FILE* file, uint32_t& Founds, bool save, const vector<string>& Der_list, int bytes, int mode, int gen, int skipBytes) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count("save.snapshot.count.priv_gen", resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort("save.clear_device.count.priv_gen");
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	int64_t* rounds = new int64_t[count];
	uint64_t* seeds = new uint64_t[count];

	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	int64_t* dev_rounds = nullptr;
	uint64_t* dev_seeds = nullptr;

	SAVE_METAL_OR_GOTO("save.snapshot.symbols.priv_gen", metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.priv_gen", metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.priv_gen", metalReadStateValue(&dev_type, d_type, sizeof(dev_type)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.priv_gen", metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds)), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.symbols.priv_gen", metalReadStateValue(&dev_seeds, d_seed, sizeof(dev_seeds)), fail);

	SAVE_METAL_OR_GOTO("save.snapshot.copy.priv_gen", metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.priv_gen", metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.priv_gen", metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.priv_gen", metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost), fail);
	SAVE_METAL_OR_GOTO("save.snapshot.copy.priv_gen", metalMemcpy(seeds, dev_seeds, count * sizeof(uint64_t), metalMemcpyDeviceToHost), fail);

	SAVE_METAL_OR_GOTO("save.clear_device.priv_gen", metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.priv_gen", metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.priv_gen", metalMemset(dev_type, 0, count * sizeof(uint8_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.priv_gen", metalMemset(dev_rounds, 0, count * sizeof(int64_t)), fail);
	SAVE_METAL_OR_GOTO("save.clear_device.priv_gen", metalMemset(dev_seeds, 0, count * sizeof(uint64_t)), fail);

	save_clear_results_count_best_effort("save.clear_device.count.priv_gen");

	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("priv_gen", count, save, SaveResultPRIVGen_Worker, file, &Founds, save, foundPrvKeys, foundHash160, coin_type, rounds, seeds, count, bytes, mode, gen, skipBytes
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}
	return;

fail:
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] rounds;
	delete[] seeds;
}

//Bip32 passphrase save func.
static void SaveResultBip32Gen_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	std::vector<std::string> Der_list,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1],
	uint32_t(*iter_h)[1], int64_t* rounds, uint64_t* seeds,
	unsigned long long count,  int bytes, int mode, int gen, int skipBytes) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::string selected = build_binary_selected_text(&foundStrings[i][0], len_h[i][0]);
		selected += ":ITERATION ";
		selected += std::to_string(iter_h[i][0]);
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		std::ostringstream oss;
		string derivat = build_derivation_segment_ada_pair(Der_list, foundDerivation[i], foundDerivation2, i, coin_type[i]);
		oss << "Byte " << bytes << ":Shift " << skipBytes << ":Gen " << gen << ":Mode " << mode ;
		uint64_t seed = seeds[i];
		oss << ":Seed " << std::hex << std::nouppercase << seed << ":" << derivat;
		std::string found_der = oss.str();
		std::string round = build_round_suffix(rounds[i], is_ed);

		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("Bip32 passphrase:", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] len_h;
	delete[] iter_h;
	delete[] coin_type;
	delete[] rounds;
	delete[] seeds;
	STOP_THREAD = false;
}

// Host helper: SaveResultBip32Gen.
METAL_HOST void SaveResultBip32Gen(FILE* file, uint32_t& Founds, bool save, vector<string> Der_list, int bytes, int mode, int gen, int skipBytes) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	uint32_t(*iter_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];
	uint64_t* seeds = new uint64_t[count];


	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	uint32_t(*dev_iter)[1] = nullptr;
	int64_t* dev_rounds = nullptr;
	uint64_t* dev_seeds = nullptr;


	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_iter, d_iter, sizeof(dev_iter));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));
	metalReadStateValue(&dev_seeds, d_seed, sizeof(dev_seeds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(iter_h, dev_iter, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);
	metalMemcpy(seeds, dev_seeds, count * sizeof(uint64_t), metalMemcpyDeviceToHost);


	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_iter, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));
	metalMemset(dev_seeds, 0, count * sizeof(uint64_t));


	save_clear_results_count_best_effort(__func__);




	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("bip32_gen", count, save, SaveResultBip32Gen_Worker, file, &Founds, save, std::move(Der_list), foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, len_h, iter_h, rounds, seeds, count, bytes, mode, gen, skipBytes
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}



//Old PRNG

static void SaveResultOldGen_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1], int64_t* rounds, uint64_t* seeds, int bytes, int mode, int gen, int skipBytes,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::string selected;

		string hexed;
		hexed.resize((len_h[i][0] * 2));
		hexing_host((uint8_t*)&foundStrings[i], len_h[i][0], (uint8_t*)hexed.data(), (len_h[i][0] * 2));

		uint32_t swaped_seed[512 / 4];
		memcpy(swaped_seed, foundStrings[i], len_h[i][0]);
		for (int n = 0; n < len_h[i][0] / 4; n++)
		{
			swaped_seed[n] = reverseByteOrderHost(swaped_seed[n]);

		}
		string recovered_mnemonic;
		recovered_mnemonic.resize(512 * 2);
		int word_count = (len_h[i][0] / 4) * 3;
		seed_to_mnemonic_phrase(swaped_seed, word_count, wordsOLD, word_lengths, (char*)recovered_mnemonic.data());
		recovered_mnemonic.resize(strlen(recovered_mnemonic.c_str()));

		selected = recovered_mnemonic + ":seed(" + hexed + ")";

		std::string found_der = "";

		std::ostringstream oss;
		oss << "Byte " << bytes << ":Shift " << skipBytes << ":Gen " << gen << ":Mode " << mode;
		uint64_t seed = seeds[i];
		oss << ":Seed " << std::hex << std::nouppercase << seed << ":";
		found_der += oss.str();

		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		found_der += build_old_derivation_label(foundDerivation[i]);
		if (save_postcheck_coin_is_ada_base_pair(coin_type[i]) && foundDerivation2 != nullptr) {
			found_der += "|" + build_old_derivation_label(foundDerivation2[i]);
		}
		std::string round = build_round_suffix(rounds[i], is_ed);

		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] len_h;
	delete[] rounds;

	STOP_THREAD = false;
}

// Host helper: SaveResultOldGen.
METAL_HOST void SaveResultOldGen(FILE* file, uint32_t& Founds, bool save, int bytes, int mode, int gen, int skipBytes) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];
	uint64_t* seeds = new uint64_t[count];



	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;
	uint64_t* dev_seeds = nullptr;


	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));
	metalReadStateValue(&dev_seeds, d_seed, sizeof(dev_seeds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);
	metalMemcpy(seeds, dev_seeds, count * sizeof(uint64_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);


	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));
	metalMemset(dev_seeds, 0, count * sizeof(uint64_t));


	save_clear_results_count_best_effort(__func__);



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("old_gen", count, save, SaveResultOldGen_Worker, file, &Founds, save, foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, len_h, rounds, seeds, bytes, mode, gen, skipBytes, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}

static void SaveResultOldSeedGen_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	uint32_t* foundDerivation2,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1], int64_t* rounds, uint64_t* seeds, int bytes, int mode, int gen, int skipBytes,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::string selected;

		std::string selected_new;
		selected_new.assign(&foundStrings[i][0], len_h[i][0]);

		selected_new = sanitize_visible_utf8(std::move(selected_new));



		uint32_t swaped_seed[512 / 4];
		bool is_hex = unhex_strict((uint8_t*)foundStrings[i], len_h[i][0], (uint8_t*)swaped_seed, len_h[i][0] / 2);


		for (int n = 0; n < len_h[i][0] / 4; n++)
		{
			swaped_seed[n] = reverseByteOrderHost(swaped_seed[n]);

		}
		string recovered_mnemonic;
		if (len_h[i][0] % 8 == 0 && is_hex)
		{
			recovered_mnemonic.resize(512 * 2);
			int word_count = (len_h[i][0] / 8) * 3;
			seed_to_mnemonic_phrase(swaped_seed, word_count, wordsOLD, word_lengths, (char*)recovered_mnemonic.data());
			recovered_mnemonic.resize(strlen(recovered_mnemonic.c_str()));
		}
		else
		{

			recovered_mnemonic = "NULL";
			recovered_mnemonic.resize(4);
		}

		selected = recovered_mnemonic + ":seed(" + selected_new + ")";

		std::string found_der = "";

		std::ostringstream oss;
		oss << "Byte " << bytes << ":Shift " << skipBytes << ":Gen " << gen << ":Mode " << mode;
		uint64_t seed = seeds[i];
		oss << ":Seed " << std::hex << std::nouppercase << seed << ":";
		found_der += oss.str();

		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		found_der += build_old_derivation_label(foundDerivation[i]);
		if (save_postcheck_coin_is_ada_base_pair(coin_type[i]) && foundDerivation2 != nullptr) {
			found_der += "|" + build_old_derivation_label(foundDerivation2[i]);
		}
		std::string round = build_round_suffix(rounds[i], is_ed);

		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
	}
	if (save) {
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundDerivation2;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] len_h;
	delete[] rounds;
	delete[] seeds;
	STOP_THREAD = false;
}

// Host helper: SaveResultOldSeedGen.
METAL_HOST void SaveResultOldSeedGen(FILE* file, uint32_t& Founds, bool save, int bytes, int mode, int gen, int skipBytes) {

	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	uint32_t* foundDerivation2 = nullptr;
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];
	uint64_t* seeds = new uint64_t[count];


	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;
	uint64_t* dev_seeds = nullptr;


	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));
	metalReadStateValue(&dev_seeds, d_seed, sizeof(dev_seeds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);
	metalMemcpy(seeds, dev_seeds, count * sizeof(uint64_t), metalMemcpyDeviceToHost);
	foundDerivation2 = copy_found_derivation2_or_null(count);


	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));
	metalMemset(dev_seeds, 0, count * sizeof(uint64_t));

	save_clear_results_count_best_effort(__func__);



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("old_seed_gen", count, save, SaveResultOldSeedGen_Worker, file, &Founds, save, foundStrings, foundDerivation, foundDerivation2, foundPrvKeys, foundHash160, coin_type, len_h, rounds, seeds, bytes, mode, gen, skipBytes, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}

}

//Armory save func.

static void SaveResultArmory_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1], int64_t* rounds,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::string selected;
		selected = load_found_text_sanitized(&foundStrings[i][0], len_h[i][0], 511);

		selected = sanitize_visible_utf8(std::move(selected));

		std::string found_der = "";
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		found_der = "Child key " + std::to_string(foundDerivation[i]);
		std::string round = build_round_suffix(rounds[i], is_ed);


		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] len_h;
	delete[] rounds;
	STOP_THREAD = false;
}



// Host helper: SaveResultArmory.
METAL_HOST void SaveResultArmory(FILE* file, uint32_t& Founds, bool save)
{
	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));

	save_clear_results_count_best_effort(__func__);



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("armory", count, save, SaveResultArmory_Worker, file, &Founds, save, foundStrings, foundDerivation, foundPrvKeys, foundHash160, coin_type, len_h, rounds, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}



}

static void SaveResultArmoryGen_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1], int64_t* rounds, uint64_t* seeds,
	unsigned long long count, int bytes, int mode, int gen, int skipBytes) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		std::string selected;
		selected = load_found_text_sanitized(&foundStrings[i][0], len_h[i][0], 511);

		selected = sanitize_visible_utf8(std::move(selected));


		std::ostringstream oss;
		oss << "Byte " << bytes << ":Shift " << skipBytes << ":Gen " << gen << ":Mode " << mode;
		uint64_t seed = seeds[i];
		oss << ":Seed " << std::hex << std::nouppercase << seed << ":";
		selected += oss.str();


		std::string found_der = "";
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		found_der = "Child key " + std::to_string(foundDerivation[i]);
		std::string round = build_round_suffix(rounds[i], is_ed);


		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] len_h;
	delete[] rounds;
	STOP_THREAD = false;
}



// Host helper: SaveResultArmoryGen.
METAL_HOST void SaveResultArmoryGen(FILE* file, uint32_t& Founds, bool save, int bytes, int mode, int gen, int skipBytes)
{
	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];
	uint64_t* seeds = new uint64_t[count];


	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;
	uint64_t* dev_seeds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));
	metalReadStateValue(&dev_seeds, d_seed, sizeof(dev_seeds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);
	metalMemcpy(seeds, dev_seeds, count * sizeof(uint64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));
	metalMemset(dev_seeds, 0, count * sizeof(uint64_t));

	save_clear_results_count_best_effort(__func__);



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("armory_gen", count, save, SaveResultArmoryGen_Worker, file, &Founds, save, foundStrings, foundDerivation, foundPrvKeys, foundHash160, coin_type, len_h, rounds, seeds, count, bytes, mode, gen, skipBytes
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}



}


static void SaveResultArmoryRoot_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1], int64_t* rounds,
	unsigned long long count) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		uint8_t root_chain[64];
		memcpy(&root_chain[0], &foundStrings[i][0], 64);

		std::string armory_str = armory_easy16_encode(root_chain);

		std::string found_str(foundStrings[i] + 64, len_h[i][0]);



		std::string selected = armory_str + ":\n" + found_str;



		std::string found_der = "";
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		found_der = "Child key " + std::to_string(foundDerivation[i]);
		std::string round = build_round_suffix(rounds[i], is_ed);


		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] len_h;
	delete[] rounds;
	STOP_THREAD = false;
}



// Host helper: SaveResultArmoryRoot.
METAL_HOST void SaveResultArmoryRoot(FILE* file, uint32_t& Founds, bool save)
{
	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));

	save_clear_results_count_best_effort(__func__);



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("armory_root", count, save, SaveResultArmoryRoot_Worker, file, &Founds, save, foundStrings, foundDerivation, foundPrvKeys, foundHash160, coin_type, len_h, rounds, count
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}



}


static void SaveResultArmoryRootGen_Worker(FILE* file,
	uint32_t* pFounds,
	bool save,
	char          (*foundStrings)[512],
	uint32_t* foundDerivation,
	unsigned char (*foundPrvKeys)[64],
	uint32_t(*foundHash160)[20],
	uint8_t* coin_type,
	uint32_t(*len_h)[1], int64_t* rounds, uint64_t* seeds,
	unsigned long long count, int bytes, int mode, int gen, int skipBytes) {

	for (uint64_t i = 0; i < count; i++) {
		if (!save_cpu_postcheck_and_count(pFounds, foundHash160, i, coin_type[i])) {
			continue;
		}

		uint8_t root_chain[64];
		memcpy(&root_chain[0], &foundStrings[i][0], 64);

		std::string armory_str = armory_easy16_encode(root_chain);

		std::string found_str(foundStrings[i] + 64, len_h[i][0]);



		std::string selected = armory_str + ":\n" + found_str;


		std::ostringstream oss;



		oss << "Byte " << bytes << ":Shift " << skipBytes << ":Gen " << gen << ":Mode " << mode;
		uint64_t seed = seeds[i];
		oss << ":Seed " << std::hex << std::nouppercase << seed << ":";
		selected += oss.str();
		selected = trim_string_at_nul(std::move(selected));

		std::string found_der = "";
		bool is_ed = false; const char* type = byte_to_coin(coin_type[i], is_ed);
		found_der = "Child key " + std::to_string(foundDerivation[i]);
		std::string round = build_round_suffix(rounds[i], is_ed);


		const StandardKeyEmitHeads heads = make_standard_key_emit_heads("", selected, found_der,
			"\n[!] Found: ", "\n[!] Found: ", "\n[!] Found: ");
		try {
			emit_standard_key_result(file, heads, foundPrvKeys[i], foundHash160[i], coin_type[i], rounds[i], save);
		}
		catch (const std::exception& e) {
			std::cerr << "Exception caught: " << e.what() << std::endl;
		}
		save_output_flush(file);
	}

	delete[] foundStrings;
	delete[] foundDerivation;
	delete[] foundPrvKeys;
	delete[] foundHash160;
	delete[] coin_type;
	delete[] len_h;
	delete[] rounds;
	STOP_THREAD = false;
}



// Host helper: SaveResultArmoryRootGen.
METAL_HOST void SaveResultArmoryRootGen(FILE* file, uint32_t& Founds, bool save, int bytes, int mode, int gen, int skipBytes)
{
	STOP_THREAD = true;
	unsigned long long resultsCountHost = 0;
	if (!save_load_results_count(__func__, resultsCountHost)) return;

	if (resultsCountHost == 0) {
		save_clear_results_count_best_effort(__func__);
		return;
	}

	size_t count = static_cast<size_t>(resultsCountHost);
	if (count > MAX_FOUNDS) { count = MAX_FOUNDS; }

	char          (*foundStrings)[512] = new char[count][512];
	uint32_t* foundDerivation = new uint32_t[count];
	unsigned char (*foundPrvKeys)[64] = new unsigned char[count][64];
	uint32_t(*foundHash160)[20] = new uint32_t[count][20];
	uint8_t* coin_type = new uint8_t[count];
	uint32_t(*len_h)[1] = new uint32_t[count][1];
	int64_t* rounds = new int64_t[count];
	uint64_t* seeds = new uint64_t[count];

	char          (*dev_foundStrings)[512] = nullptr;
	uint32_t* dev_foundDerivations = nullptr;
	unsigned char (*dev_foundPrvKeys)[64] = nullptr;
	uint32_t(*dev_foundHash160)[20] = nullptr;
	uint8_t* dev_type = nullptr;
	uint32_t(*dev_len)[1] = nullptr;
	int64_t* dev_rounds = nullptr;
	uint64_t* dev_seeds = nullptr;

	metalReadStateValue(&dev_foundDerivations, d_foundDerivations, sizeof(dev_foundDerivations));
	metalReadStateValue(&dev_foundStrings, d_foundStrings, sizeof(dev_foundStrings));
	metalReadStateValue(&dev_foundPrvKeys, d_foundPrvKeys, sizeof(dev_foundPrvKeys));
	metalReadStateValue(&dev_foundHash160, d_foundHash160, sizeof(dev_foundHash160));
	metalReadStateValue(&dev_type, d_type, sizeof(dev_type));
	metalReadStateValue(&dev_len, d_len, sizeof(dev_len));
	metalReadStateValue(&dev_rounds, d_round, sizeof(dev_rounds));
	metalReadStateValue(&dev_seeds, d_seed, sizeof(dev_seeds));


	metalMemcpy(foundDerivation, dev_foundDerivations, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundStrings, dev_foundStrings, count * 512 * sizeof(char), metalMemcpyDeviceToHost);
	metalMemcpy(foundPrvKeys, dev_foundPrvKeys, count * 64 * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(foundHash160, dev_foundHash160, count * 20 * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(coin_type, dev_type, count * sizeof(uint8_t), metalMemcpyDeviceToHost);
	metalMemcpy(len_h, dev_len, count * sizeof(uint32_t), metalMemcpyDeviceToHost);
	metalMemcpy(rounds, dev_rounds, count * sizeof(int64_t), metalMemcpyDeviceToHost);
	metalMemcpy(seeds, dev_seeds, count * sizeof(uint64_t), metalMemcpyDeviceToHost);

	metalMemset(dev_foundDerivations, 0, count * sizeof(uint32_t));
	metalMemset(dev_foundStrings, 0, count * 512 * sizeof(char));
	metalMemset(dev_foundPrvKeys, 0, count * 64 * sizeof(uint8_t));
	metalMemset(dev_foundHash160, 0, count * 20 * sizeof(uint32_t));
	metalMemset(dev_type, 0, count * sizeof(uint8_t));
	metalMemset(dev_len, 0, count * sizeof(uint32_t));
	metalMemset(dev_rounds, 0, count * sizeof(int64_t));
	metalMemset(dev_seeds, 0, count * sizeof(uint64_t));

	save_clear_results_count_best_effort(__func__);



	{
		std::lock_guard<std::mutex> lock(g_save_threads_mutex);
		enqueue_async_save_task_for_current_gpu("armory_root_gen", count, save, SaveResultArmoryRootGen_Worker, file, &Founds, save, foundStrings, foundDerivation, foundPrvKeys, foundHash160, coin_type, len_h, rounds, seeds, count, bytes, mode, gen, skipBytes
		);
	}

	if (FULL)
	{
		flush_all_async_save_queues();
	}



}
