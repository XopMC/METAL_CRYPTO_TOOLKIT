#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

enum class MacPathKind {
    Missing,
    Regular,
    Directory,
    Other,
};

struct MacDirectoryEntry {
    std::string name;
    std::string path;
    MacPathKind kind = MacPathKind::Missing;
};

MacPathKind mac_path_kind(const std::string& path);
bool mac_is_regular_file(const std::string& path);
bool mac_list_directory(const std::string& path, std::vector<MacDirectoryEntry>& entries);
bool mac_create_directory(const std::string& path);
bool mac_read_text_file(const std::string& path, std::string& out, std::string& error);
bool mac_read_binary_file(const std::string& path, std::vector<uint8_t>& out, std::string& error);
bool mac_read_file_prefix(const std::string& path, void* out, size_t capacity, size_t& bytes_read);
FILE* mac_open_binary_read(const std::string& path, int& error_code);
