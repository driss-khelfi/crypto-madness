#include "../include/crypto.hpp"

#include <sodium.h>

#include <iomanip>
#include <sstream>


std::string md5(const std::string &input) {
    unsigned char hash[MD5_DIGEST_LENGTH];

    MD5((const unsigned char*)input.c_str(), input.size(), hash);

    // to hex string
    std::stringstream ss;
    
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>( hash[i] );
    
    return ss.str();

}
