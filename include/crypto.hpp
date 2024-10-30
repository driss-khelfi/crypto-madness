#pragma once

#include <string>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include <vector>


#define KEY_LENGTH 32
#define SALT_LENGTH 16


std::string bytes_to_hex_string(const unsigned char* bytes, size_t n);
std::string bytes_to_hex_string(const std::vector<unsigned char> &bytes);
std::vector<unsigned char> hex_string_to_bytes(const std::string& hex);

std::string md5(const std::string &input);

std::string gensalt96();
std::string sha256_with_salt96(const std::string &input, const std::string &salt = gensalt96());
bool compare_sha256_with_salt96(const std::string &input, const std::string &hash);

uint32_t random_seed();

std::vector<unsigned char> gensalt128();
std::vector<unsigned char> derive_key(const std::string& password, const std::vector<unsigned char>& salt);

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_symmetric_key(const std::string& user_secret);
std::string encrypt_symmetric(const std::string& message, const std::vector<unsigned char>& symmetric_key);
std::string decrypt_symmetric(const std::string& encrypted_message, const std::vector<unsigned char>& symmetric_key);
