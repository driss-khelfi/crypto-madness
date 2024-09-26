#include "../include/crypto.hpp"

#include <sodium.h>
#include <cstring>

#include <iomanip>
#include <sstream>
#include <fstream>


std::string bytes_to_hex_string(const unsigned char* hash, size_t n) {
    std::stringstream ss;
    
    for(unsigned int i = 0; i < n; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>( hash[i] );
    
    return ss.str();
}


std::string md5(const std::string &input) {
    unsigned char hash[MD5_DIGEST_LENGTH];

    MD5((const unsigned char*)input.c_str(), input.size(), hash);

    return bytes_to_hex_string(hash, MD5_DIGEST_LENGTH);
}


std::string gensalt96() {
    unsigned char salt[12];
    randombytes(salt, 12);

    return bytes_to_hex_string(salt, 12);
}


std::string sha256_with_salt96(const std::string &input, const std::string &salt) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    std::string content = salt + input;

    SHA256((const unsigned char*)content.c_str(), content.size(), hash);

    return salt + bytes_to_hex_string(hash, SHA256_DIGEST_LENGTH);
}


bool compare_sha256_with_salt96(const std::string &input, const std::string &hash) {
    if (hash.size() != (SHA256_DIGEST_LENGTH + 12)*2) { return false; }

    std::string salt = hash.substr(0, 12*2);

    return hash.compare(sha256_with_salt96(input, salt)) == 0;
}


uint32_t random_seed() {
    // unsigned char bytes[4];
    uint32_t seed;
    randombytes((unsigned char *)&seed, sizeof(seed));
    // memcpy(&seed, bytes, 4);
    return seed;
}
