#include "../include/crypto.hpp"

#include <sodium.h>
#include <cstring>

#include <iomanip>
#include <sstream>
#include <fstream>


std::string bytes_to_hex_string(const unsigned char* bytes, size_t n) {
    std::stringstream ss;
    
    for(unsigned int i = 0; i < n; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>( bytes[i] );
    
    return ss.str();
}


std::string bytes_to_hex_string(const std::vector<unsigned char> &bytes) {
    std::stringstream ss;
    
    for(unsigned int i = 0; i < bytes.size(); i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>( bytes.at(i) );
    
    return ss.str();
}


std::vector<unsigned char> hex_string_to_bytes(const std::string& hex) {
  std::vector<unsigned char> bytes;

  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    unsigned char byte = (unsigned char) strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }

  return bytes;
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


std::vector<unsigned char> gensalt128() {
    std::vector<unsigned char> salt(SALT_LENGTH);
    randombytes_buf(salt.data(), SALT_LENGTH);
    return salt;
}


std::vector<unsigned char> derive_key(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(KEY_LENGTH);
    if (crypto_pwhash(key.data(), KEY_LENGTH, password.c_str(), password.size(), salt.data(),
                  crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
                    throw std::runtime_error("Key derivation failed");
                  }
    return key;
}

// Symmetric encrypt / decrypt

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_symmetric_key(const std::string& user_secret) {
    std::vector<unsigned char> salt = gensalt128();
    std::vector<unsigned char> symmetric_key = derive_key(user_secret, salt);
    return {symmetric_key, salt};
}


std::string encrypt_symmetric(const std::string& message, const std::vector<unsigned char>& symmetric_key) {
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> ciphertext(message.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(), reinterpret_cast<const unsigned char*>(message.c_str()), message.size(),
                          nonce.data(), symmetric_key.data());

    std::string encrypted_message(reinterpret_cast<char*>(nonce.data()), nonce.size());
    encrypted_message += std::string(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    return encrypted_message;
}


std::string decrypt_symmetric(const std::string& encrypted_message, const std::vector<unsigned char>& symmetric_key) {
    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    std::copy(encrypted_message.begin(), encrypted_message.begin() + crypto_secretbox_NONCEBYTES, nonce.begin());

    std::vector<unsigned char> ciphertext(encrypted_message.size() - crypto_secretbox_NONCEBYTES);
    std::copy(encrypted_message.begin() + crypto_secretbox_NONCEBYTES, encrypted_message.end(), ciphertext.begin());

    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(), nonce.data(), symmetric_key.data()) != 0) {
        throw std::runtime_error("Decryption failed");
    }
    return std::string(decrypted.begin(), decrypted.end());
}