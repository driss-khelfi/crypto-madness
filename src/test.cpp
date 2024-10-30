#include <iostream>

#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <unistd.h>

#include <cstring>

#include "../include/crypto.hpp"
#include "../include/OTPMgr.hpp"
#include "../include/LPTF_NET/LPTF_Utils.hpp"


using namespace std;


std::string to_hex_string(const unsigned char* hash, size_t n) {
    std::stringstream ss;
    
    for(unsigned int i = 0; i < n; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>( hash[i] );
    
    return ss.str();
}


int main()
{
    char password[] = "Correct Horse Battery Staple";

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_box_SEEDBYTES];

    randombytes_buf(salt, sizeof salt);

    if (crypto_pwhash (key, sizeof key, password, strlen(password), salt,
                       crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                       crypto_pwhash_ALG_DEFAULT) != 0) {
        cerr << "out of memory" << endl;
        return 1;
    }

    string message = "Hello from server!";

    cout << "Message: " << message << endl;



    cout << "Encrypted Message: " << endl;


    cout << "Decrypted Message: " << endl;

    return 0;
}