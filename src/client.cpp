#include <iostream>
#include <stdexcept>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>

#include <fstream>

#include <signal.h>
#include <thread>

#include "../include/LPTF_Net/LPTF_Socket.hpp"
#include "../include/LPTF_Net/LPTF_Utils.hpp"

#include "../include/crypto.hpp"
#include "../include/OTPMgr.hpp"

using namespace std;


void print_help() {
    cout << "Usage:" << endl;
    cout << "\tclient <username>@<ip>:<port>" << endl;
}


// handles OTP regens
ssize_t write_encrypted(LPTF_Socket &socket, LPTF_Packet &packet, OTPMgr &mgr) {

    if (!mgr.XOR_packet_content(packet)) {

        string msg = "End of byte masks !";
        LPTF_Packet p = build_error_packet(packet.type(), 0, msg);
        throw runtime_error("End of byte masks !");

        // LPTF_Packet otp_pckt (OTP_GEN_BYTES_PACKET, nullptr, 0);
        // socket.write(otp_pckt);

        // // wait for seed
        // while ((*otp_gen_packet_ptr).type() != OTP_GEN_BYTES_PACKET) {
        //     cout << "Sleep..." << endl;
        //     usleep(50000);
        // }
        
        // uint32_t seed;
        // memcpy(&seed, otp_gen_packet_ptr->get_content(), sizeof(seed));
        
        // seed = ntohl(seed);

        // cout << "New seed: " << seed << endl;

        // mgr.regenerate_pad(seed);

        // // reset OTP packet when used
        // *otp_gen_packet_ptr = LPTF_Packet();

        // // retry XOR packet content
        // if (!mgr.XOR_packet_content(packet))
        //     throw runtime_error("Unable to encrypt packet after OTP regen !");

    }

    packet.set_reserved_byte(1);    // flag to tell that the packet is encrypted
    return socket.write(packet);
}


// handles OTP regens
LPTF_Packet read_encrypted(LPTF_Socket &socket, OTPMgr &mgr) {
    LPTF_Packet pckt = socket.read();

    if (!mgr.XOR_packet_content(pckt))
        throw runtime_error("Unable to decrypt packet: OTP out of sync !");

    // if (pckt.get_header().reserved != 1) {
    //     if (pckt.type() == OTP_GEN_BYTES_PACKET) {
    //         return pckt;
    //     }
    // } else {
    //     if (!mgr.XOR_packet_content(pckt))
    //         throw runtime_error("Unable to decrypt packet: OTP out of sync !");
    // }

    return pckt;
}


bool login(LPTF_Socket *clientSocket, string username) {
    // send "login" packet
    LPTF_Packet pckt(LOGIN_PACKET, (void *)username.c_str(), username.size());
    clientSocket->write(pckt);
    // wait for server reply
    pckt = clientSocket->read();

    if (pckt.type() == REPLY_PACKET && get_refered_packet_type_from_reply_packet(pckt) == LOGIN_PACKET) {
        string password = getpass(get_reply_content_from_reply_packet(pckt).c_str());
        // cout << get_reply_content_from_reply_packet(pckt);
        // string password;
        // getline(cin, password);
        LPTF_Packet password_packet = LPTF_Packet(MESSAGE_PACKET, (void *)password.c_str(), password.size());
        clientSocket->write(password_packet);
        
        LPTF_Packet auth_reply = clientSocket->read();
        if (auth_reply.type() == REPLY_PACKET && get_refered_packet_type_from_reply_packet(auth_reply) == LOGIN_PACKET) {
            cout << "Login successful." << endl;
            return true;
        } else if (auth_reply.type() == ERROR_PACKET) {
            cout << "Unable to log in: " << get_error_content_from_error_packet(auth_reply) << endl;
        }
    } else if (pckt.type() == MESSAGE_PACKET) {
        string new_password = getpass(get_message_from_message_packet(pckt).c_str());
        // string new_password;
        // getline(cin, new_password);
        LPTF_Packet new_password_packet = LPTF_Packet(MESSAGE_PACKET, (void *)new_password.c_str(), new_password.size());
        clientSocket->write(new_password_packet);

        string new_password_confirm = getpass("Confirm Password: ");
        LPTF_Packet new_password_confirm_packet = LPTF_Packet(MESSAGE_PACKET, (void *)new_password_confirm.c_str(), new_password_confirm.size());
        clientSocket->write(new_password_confirm_packet);
        
        LPTF_Packet create_reply = clientSocket->read();
        if (create_reply.type() == REPLY_PACKET && get_refered_packet_type_from_reply_packet(create_reply) == LOGIN_PACKET) {
            cout << "User created and logged in successfully." << endl;
            return true;
        } else if (create_reply.type() == ERROR_PACKET) {
            cout << "Unable to create user: " << get_error_content_from_error_packet(create_reply) << endl;
        }
    } else if (pckt.type() == ERROR_PACKET) {
        cout << "Unable to log in: " << get_error_content_from_error_packet(pckt) << endl;
    } else {
        cout << "Unexpected server packet ! Could not log in !" << endl;
    }

    return false;
}


int main(int argc, char const *argv[]) {
    string username;
    string ip;
    int port;

    if (argc == 2 && (strcmp(argv[1], "-help") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_help();
        return 0;
    } else if (argc != 2) {
        cout << "Too few arguments !" << endl;
        print_help();
        return 2;
    }

    string serv_arg = argv[1];
    size_t user_sep_index = serv_arg.find('@');

    if (user_sep_index == string::npos) {
        cout << "Server address is wrong !" << endl;
        print_help();
        return 2;
    }

    size_t ip_sep_index = serv_arg.find(':', user_sep_index);

    if (ip_sep_index == string::npos) {
        cout << "Server address is wrong !" << endl;
        print_help();
        return 2;
    }
    
    username = serv_arg.substr(0, user_sep_index);
    ip = serv_arg.substr(user_sep_index+1, ip_sep_index-user_sep_index-1);
    port = atoi(serv_arg.substr(ip_sep_index+1, serv_arg.size()).c_str());

    // FIXME check for ip and port later
    if (username.size() == 0) {
        cout << "Username is wrong !" << endl;
        print_help();
        return 2;
    }

    if (ip.size() == 0)
        ip = "127.0.0.1";
    if (port == 0)
        port = 12345;

    cout << "Username: " << username << ", IP: " << ip << ", Port: " << port <<endl;

    try {
        LPTF_Socket clientSocket = LPTF_Socket();

        struct sockaddr_in serverAddr;
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = inet_addr(ip.c_str());
        serverAddr.sin_port = htons(port);

        clientSocket.connect(reinterpret_cast<struct sockaddr *>(&serverAddr), sizeof(serverAddr));

        // if login failed
        if (!login(&clientSocket, username)) {
            clientSocket.close();
            return 1;
        }

        string pad_file = "OTP.bin";
        // string pad_file = username+"_OTP_c.bin";
        OTPMgr otp_mgr (pad_file);

        // sync client/server pad
        // {
        //     LPTF_Packet pckt = clientSocket.read();

        //     if (pckt.type() == OTP_GEN_BYTES_PACKET) {
        //         uint32_t seed;
        //         memcpy(&seed, pckt.get_content(), sizeof(seed));

        //         seed = ntohl(seed);

        //         cout << "Using seed: " << seed << endl;

        //         OTPMgr::generate_pad(seed, pad_file);

        //         otp_mgr.set_otp_file(pad_file);
        //     } else {
        //         cerr << "Got unexpected packet type from server ! (Expected OTP packet)" << endl;
        //         clientSocket.close();
        //         return 1;
        //     }
        // }

        // OTP Gen packet requests are put here
        // LPTF_Packet *otp_gen_packet = new LPTF_Packet;

        thread read_thread ([&clientSocket, &otp_mgr] {
            while (true) {
                LPTF_Packet msg = read_encrypted(clientSocket, otp_mgr);

                if (msg.type() == MESSAGE_PACKET) {
                    cout << get_message_from_message_packet(msg) << endl;
                } else if (msg.type() == REPLY_PACKET) {
                    cout << "### REPLY ###" << endl;
                } /* else if (msg.type() == OTP_GEN_BYTES_PACKET) {
                    
                    *otp_gen_packet = msg;
                    cout << "Otp packet updated" << endl;

                } */ else {
                    cout << "Unexpected packet type !" << endl;
                }
            }
        });

        while (true) {
            string message;

            cout << "Send Message: ";
            getline(cin, message);

            LPTF_Packet msg = build_message_packet(message);
            write_encrypted(clientSocket, msg, otp_mgr);
        }

    } catch (const exception &ex) {
        cerr << "Exception: " << ex.what() << endl;
        exit(1);
    }

    return 0;
}
