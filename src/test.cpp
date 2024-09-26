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
    auto seed = random_seed();
    string server_otp_file = "test_server_otp.bin";
    string client_otp_file = "test_client_otp.bin";

    OTPMgr::generate_pad(seed, server_otp_file);
    OTPMgr::generate_pad(seed, client_otp_file);

    OTPMgr server_mgr (server_otp_file);
    OTPMgr client_mgr (client_otp_file);
    
    string message;

    while (true) {

        cout << "Message: ";
        getline(cin, message);

        LPTF_Packet packet = build_message_packet(message);
        cout << "Plain Message Packet:" << endl;
        packet.print_specs();

        if (!client_mgr.XOR_packet_content(packet)) {
            cerr << "Client XOR content failed !"<< endl;
        } else {

            cout << "XOR Message Packet:" << endl;
            packet.print_specs();

            if (!server_mgr.XOR_packet_content(packet)) {
                cerr << "Server XOR content failed !"<< endl;
            } else {
                cout << "Server decrypt:" << endl;
                packet.print_specs();

                cout << "Client message: " << get_message_from_message_packet(packet) << endl;
            }

        }

    }

    return 0;
}