#ifndef METAL_CRYPTO_POETRY_H
#define METAL_CRYPTO_POETRY_H

#include <cstddef>
#include <cstdint>

constexpr uint32_t POETRY_WORD_COUNT = 1626u;
constexpr uint32_t POETRY_MAX_WORDS = 24u;
constexpr uint16_t POETRY_WILDCARD_ID = 0xffffu;
constexpr uint32_t POETRY_MAX_PHRASE_BYTES = 512u;

struct PoetryTemplateDevice {
    uint16_t words[POETRY_MAX_WORDS];
    uint8_t wildcard_positions[POETRY_MAX_WORDS];
    uint8_t word_count;
    uint8_t wildcard_count;
    uint8_t random_mode;
    uint8_t reserved;
};

struct PoetryThreadState {
    uint16_t digits[POETRY_MAX_WORDS];
    uint64_t random_state;
    uint8_t active;
    uint8_t reserved[7];
};

static_assert(sizeof(PoetryTemplateDevice) == 76, "Poetry template layout must match Metal");
static_assert(offsetof(PoetryTemplateDevice, wildcard_positions) == 48, "Poetry wildcard layout mismatch");
static_assert(sizeof(PoetryThreadState) == 64, "Poetry thread-state layout must match Metal");
static_assert(offsetof(PoetryThreadState, random_state) == 48, "Poetry random-state layout mismatch");

#endif
