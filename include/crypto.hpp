#pragma once

#include <string>
#include <openssl/md5.h>
#include <openssl/sha.h>


std::string md5(const std::string &input);

std::string gensalt96();
std::string sha256_with_salt96(const std::string &input, const std::string &salt = gensalt96());
bool compare_sha256_with_salt96(const std::string &input, const std::string &hash);

uint32_t random_seed();