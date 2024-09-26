#include "../include/file_utils.hpp"

#include <iostream>
#include <fstream>
#include <filesystem>

#define SERVER_DIR "server_root"
#define SERVER_LOGS_DIR "logs"

using namespace std;
namespace fs = std::filesystem;


uint32_t get_file_size(string filepath) {
    return get_file_size(fs::path(filepath));
}


uint32_t get_file_size(fs::path filepath) {
    return static_cast<uint32_t>(fs::file_size(filepath));
}


string list_directory_content(fs::path folderpath) {
    string result = "";
    
    for (fs::directory_entry const& dir_entry : fs::directory_iterator{folderpath}) {
        bool is_dir = fs::is_directory(dir_entry);
        if (is_dir) {
            result.append(dir_entry.path().stem().string());
            result.push_back(dir_entry.path().preferred_separator);
        } else {
            result.append(dir_entry.path().filename().string());
        }
        result.append("\n");
    }

    return result;
}


bool is_path_in_folder(fs::path contained, fs::path container) {
    // compare the relative path for contained and container
    fs::path relative_path = std::filesystem::relative(contained, container);
    return !relative_path.empty() && relative_path.native()[0] != '.';
}


void delete_directory_content(fs::path dir) {
    for (fs::directory_entry const& dir_entry : fs::directory_iterator(dir))
        fs::remove_all(dir_entry);
}
