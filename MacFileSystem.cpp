#include "MacFileSystem.h"

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <utility>

MacPathKind mac_path_kind(const std::string& path) {
    struct stat info {};
    if (stat(path.c_str(), &info) != 0) {
        return MacPathKind::Missing;
    }
    if (S_ISREG(info.st_mode)) {
        return MacPathKind::Regular;
    }
    if (S_ISDIR(info.st_mode)) {
        return MacPathKind::Directory;
    }
    return MacPathKind::Other;
}

bool mac_is_regular_file(const std::string& path) {
    return mac_path_kind(path) == MacPathKind::Regular;
}

bool mac_list_directory(const std::string& path, std::vector<MacDirectoryEntry>& entries) {
    entries.clear();
    DIR* directory = opendir(path.c_str());
    if (directory == nullptr) {
        return false;
    }

    while (dirent* raw = readdir(directory)) {
        const std::string name = raw->d_name;
        if (name == "." || name == "..") {
            continue;
        }

        std::string full_path = path;
        if (!full_path.empty() && full_path.back() != '/') {
            full_path.push_back('/');
        }
        full_path += name;

        const MacPathKind kind = mac_path_kind(full_path);
        if (kind != MacPathKind::Missing) {
            entries.push_back({name, std::move(full_path), kind});
        }
    }

    closedir(directory);
    return true;
}

bool mac_create_directory(const std::string& path) {
    if (mkdir(path.c_str(), 0777) == 0) {
        return true;
    }
    return errno == EEXIST && mac_path_kind(path) == MacPathKind::Directory;
}

bool mac_read_text_file(const std::string& path, std::string& out, std::string& error) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "cannot open file";
        return false;
    }

    std::ostringstream stream;
    stream << file.rdbuf();
    out = stream.str();
    return true;
}

bool mac_read_binary_file(const std::string& path, std::vector<uint8_t>& out, std::string& error) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "cannot open file";
        return false;
    }

    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    if (size < 0) {
        error = "cannot determine file size";
        return false;
    }

    file.seekg(0, std::ios::beg);
    out.assign(static_cast<size_t>(size), 0u);
    if (!out.empty()) {
        file.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
        if (!file) {
            error = "failed to read file";
            return false;
        }
    }
    return true;
}

bool mac_read_file_prefix(const std::string& path, void* out, const size_t capacity, size_t& bytes_read) {
    bytes_read = 0;
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    file.read(static_cast<char*>(out), static_cast<std::streamsize>(capacity));
    bytes_read = static_cast<size_t>(file.gcount());
    return true;
}

FILE* mac_open_binary_read(const std::string& path, int& error_code) {
    FILE* file = std::fopen(path.c_str(), "rb");
    error_code = file == nullptr ? errno : 0;
    return file;
}
