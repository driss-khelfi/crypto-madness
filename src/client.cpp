#include <iostream>
#include <stdexcept>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>

#include <fstream>

#include <signal.h>
#include <thread>

#include <vector>

#include "../include/LPTF_Net/LPTF_Socket.hpp"
#include "../include/LPTF_Net/LPTF_Utils.hpp"

#include "../include/crypto.hpp"

using namespace std;


# define KEY_FILE_EXT ".key"


void print_help() {
    cout << "Usage:" << endl;
    cout << "\tclient <username>@<ip>:<port>" << endl;
}


void dump_key(string &username, std::vector<unsigned char> &key) {
    string fname = username+KEY_FILE_EXT;
    ofstream key_file (fname, ios::binary);

    for (unsigned char b : key) {
        key_file.write((const char *) &b, sizeof(b));
    }

    key_file.close();
    
}


std::vector<unsigned char> load_key(string &username) {
    string fname = username+KEY_FILE_EXT;
    ifstream key_file (fname, ios::binary);
    
    unsigned char raw_key[KEY_LENGTH];
    std::vector<unsigned char> key;

    key_file.read((char *) raw_key, KEY_LENGTH);

    for (int i = 0; i < KEY_LENGTH; i++)
        key.push_back(raw_key[i]);

    key_file.close();

    return key;
}


ssize_t write_encrypted(LPTF_Socket &socket, LPTF_Packet &packet, std::vector<unsigned char> key) {

    string encrypted_content = encrypt_symmetric(string((char *)packet.get_content(), packet.get_header().length), key);

    LPTF_Packet encr_pckt = LPTF_Packet(packet.type(), (void *) encrypted_content.c_str(), encrypted_content.size());

    encr_pckt.set_reserved_byte(1);    // flag to tell that the packet is encrypted
    return socket.write(encr_pckt);
}


LPTF_Packet read_encrypted(LPTF_Socket &socket, std::vector<unsigned char> key) {

    LPTF_Packet pckt = socket.read();

    // decrypt if content is encrypted
    if (pckt.get_header().reserved == 1) {
        string content = decrypt_symmetric(string((char*)pckt.get_content(), pckt.get_header().length), key);
        pckt = LPTF_Packet(pckt.type(), (void *) content.c_str(), content.size());
    } else {
        throw runtime_error("Packet is not encrypted !");
    }

    return pckt;
}


std::pair<bool, std::vector<unsigned char>> login(LPTF_Socket *clientSocket, string username) {
    // send "login" packet
    LPTF_Packet pckt(LOGIN_PACKET, (void *)username.c_str(), username.size());
    clientSocket->write(pckt);
    // wait for server reply
    pckt = clientSocket->read();

    // if reply -> user exist on server
    if (pckt.type() == REPLY_PACKET && get_refered_packet_type_from_reply_packet(pckt) == LOGIN_PACKET) {
        
        std::vector<unsigned char> key;
        try {
            key = load_key(username);
        } catch (const exception &ex) {
            string err_msg = "No key";
            cout << "load_key() fail: " << ex.what() << endl;
            LPTF_Packet error_packet = build_error_packet(LOGIN_PACKET, ERR_CODE_FAILURE, err_msg);
            clientSocket->write(error_packet);
            return {false, std::vector<unsigned char>()};
        }

        // decrypt and send verif
        string encr_verif = get_reply_content_from_reply_packet(pckt);
        string decr_verif = decrypt_symmetric(encr_verif, key);

        pckt = build_message_packet(decr_verif);
        clientSocket->write(pckt);
        
        LPTF_Packet auth_reply = clientSocket->read();
        if (auth_reply.type() == REPLY_PACKET && get_refered_packet_type_from_reply_packet(auth_reply) == LOGIN_PACKET) {
            cout << "Login successful." << endl;
            return {true, key};
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
            std::vector<unsigned char> key;
            
            unsigned char *data = (unsigned char *) create_reply.get_content();
            for (int i = 1; i < create_reply.get_header().length; i++) {
                key.push_back(data[i]);
            }

            dump_key(username, key);

            cout << "User created and logged in successfully." << endl;
            return {true, key};
        } else if (create_reply.type() == ERROR_PACKET) {
            cout << "Unable to create user: " << get_error_content_from_error_packet(create_reply) << endl;
        }
    } else if (pckt.type() == ERROR_PACKET) {
        cout << "Unable to log in: " << get_error_content_from_error_packet(pckt) << endl;
    } else {
        cout << "Unexpected server packet ! Could not log in !" << endl;
    }

    return {false, std::vector<unsigned char>()};
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

        std::pair<bool, std::vector<unsigned char>> ret_login = login(&clientSocket, username);

        // if login failed
        if (!ret_login.first) {
            clientSocket.close();
            return 1;
        }

        std::vector<unsigned char> key = ret_login.second;

        thread read_thread ([&clientSocket, &key] {
            while (true) {
                LPTF_Packet msg = read_encrypted(clientSocket, key);

                if (msg.type() == MESSAGE_PACKET) {
                    cout << get_message_from_message_packet(msg) << endl;
                } else if (msg.type() == REPLY_PACKET) {
                    cout << "### REPLY ###" << endl;
                } else {
                    cout << "Unexpected packet type !" << endl;
                }
            }
        });

        while (true) {
            string message;

            cout << "Send Message: ";
            getline(cin, message);

            LPTF_Packet msg = build_message_packet(message);
            write_encrypted(clientSocket, msg, key);
        }

    } catch (const exception &ex) {
        cerr << "Exception: " << ex.what() << endl;
        exit(1);
    }

    return 0;
}
