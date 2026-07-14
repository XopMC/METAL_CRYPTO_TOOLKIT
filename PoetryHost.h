#ifndef METAL_CRYPTO_POETRY_HOST_H
#define METAL_CRYPTO_POETRY_HOST_H

#include "Poetry.h"

#include <string>
#include <vector>

struct PoetryPreparedTemplate {
    PoetryTemplateDevice device{};
    std::string normalized_phrase;
    std::string combination_count;
    std::string source;
    size_t line_number = 0;
};

struct PoetryDictionaryHost {
    std::vector<char> blob;
    std::vector<uint16_t> offsets;
    std::vector<uint8_t> lengths;
};

bool poetry_cli_consume(int argc, char** argv, int& argument_index, std::string& error);
bool poetry_mode_selected();
bool poetry_validate_cli_surface(int argc, char** argv, std::string& error);
void poetry_print_help();
bool poetry_prepare_templates(bool random_mode,
                              bool random_batch_enabled,
                              std::vector<PoetryPreparedTemplate>& templates,
                              PoetryDictionaryHost& dictionary,
                              std::string& error);
void poetry_reset_cli_for_tests();

#endif
