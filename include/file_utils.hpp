#pragma once

#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

uint32_t get_file_size(string filepath);
uint32_t get_file_size(fs::path filepath);

string list_directory_content(fs::path folderpath);

bool is_path_in_folder(fs::path contained, fs::path container);

void delete_directory_content(fs::path dir);
