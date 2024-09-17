#include <iostream>
#include <stdexcept>
#include <cstring>
#include <unistd.h>

#include "../include/LPTF_Net/LPTF_Socket.hpp"
#include "../include/LPTF_Net/LPTF_Utils.hpp"

using namespace std;


void print_help() {
    cout << "Usage:" << endl;
    cout << "\tclient <username>@<ip>:<port>" << endl;
}


bool login(LPTF_Socket *clientSocket, string username) {
    // send "login" packet
    LPTF_Packet pckt(LOGIN_PACKET, (void *)username.c_str(), username.size());
    clientSocket->write(pckt);
    // wait for server reply
    pckt = clientSocket->read();

    if (pckt.type() == REPLY_PACKET && get_refered_packet_type_from_reply_packet(pckt) == LOGIN_PACKET) {
        cout << "Login successful." << endl;
        return true;
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

        if (!fork()) {
            // handle write
            while (true) {
                string message;

                cout << "Send Message: ";
                getline(cin, message);

                // send message
                LPTF_Packet msg = build_message_packet(message);
                clientSocket.write(msg);
            }
        } else {
            // handle read
            while (true) {
                LPTF_Packet msg = clientSocket.read();

                if (msg.type() == MESSAGE_PACKET) {
                    cout << get_message_from_message_packet(msg) << endl;
                } else if (msg.type() != REPLY_PACKET) {
                    cout << "Unexpected packet type !" << endl;
                } else {
                    cout << "### REPLY ###" << endl;
                }
            }
        }

    } catch (const exception &ex) {
        cerr << "Exception: " << ex.what() << endl;
        return 1;
    }

    return 0;
}
