#include "../include/crypto.hpp"

#include <sodium.h>

#include <iomanip>
#include <sstream>
#include <fstream>
#include <random>

void generate_random_bits(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 1024 * 1024; i++) {  // Generate 1 MiB of data
        char byte = static_cast<char>(dis(gen));
        file.write(&byte, sizeof(char));
    }

    file.close();
}

std::string md5(const std::string &input) {
    unsigned char hash[MD5_DIGEST_LENGTH];

    MD5((const unsigned char*)input.c_str(), input.size(), hash);

    // to hex string
    std::stringstream ss;
    
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>( hash[i] );
    
    return ss.str();

}
