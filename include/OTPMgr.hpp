#pragma once

#include <mutex>
#include <fstream>
#include <random>

#include "../include/LPTF_Net/LPTF_Socket.hpp"
#include "../include/crypto.hpp"
#include "../include/file_utils.hpp"

using namespace std;


#define OTP_FILE_SIZE 1024 * 1024   // 1 MiB of data


class OTPMgr {

private:
    string otp_filename;
    ifstream otp_file;
    uint32_t otp_file_size = 0;
    streampos pos;

    void open_otp_file() {
        close_otp_file();

        otp_file.open(otp_filename, ios::binary);

        if (!otp_file.is_open()) throw runtime_error("Unable to open Pad file !");

        otp_file.seekg(ios::beg);
        pos = otp_file.tellg();

        // store file size
        otp_file_size = get_file_size(otp_filename);
    }

    void close_otp_file() {
        if (otp_file.is_open()) {
            otp_file.close();
            otp_file_size = 0;
        }
    }

public:
    OTPMgr() {}

    OTPMgr(const string &otp_filename) : otp_filename(otp_filename) {
        open_otp_file();
    }

    ~OTPMgr() {
        close_otp_file();
    }

    void set_otp_file(const string &filename) {
        otp_filename = filename;
        open_otp_file();
    }

    // true if enough bytes in OTP, otherwise false
    bool XOR_packet_content(LPTF_Packet &packet) {

        uint16_t nbytes = packet.size() - sizeof(PACKET_HEADER);

        cout << "otp_file_size - pos: " << otp_file_size - pos << ", otp_file_size: " << otp_file_size << ", pos: " << pos << ", nbytes: " << nbytes << endl;

        if (otp_file_size - pos < nbytes)
            return false;

        uint8_t *content = (uint8_t*) packet.get_content();

        for (uint16_t i = 0; i < nbytes; i++) {
            char b;
            otp_file.read(&b, 1);

            content[i] = content[i] ^ b;
            
            pos = otp_file.tellg();
        }

        return true;

    }

    void regenerate_pad(uint32_t seed) {
        close_otp_file();

        cout << "Regen with seed: " << seed << endl;

        OTPMgr::generate_pad(seed, otp_filename);
        
        open_otp_file();
    }

    
    static void generate_pad(uint32_t seed, const string &otp_filename) {

        std::ofstream file(otp_filename, std::ios::binary);
        std::mt19937 gen(seed);
        std::uniform_int_distribution<> dis(0, 255);

        for (int i = 0; i < OTP_FILE_SIZE; i++) {
            char byte = static_cast<char>(dis(gen));
            file.write(&byte, sizeof(char));
        }
        file.close();

    }

};
