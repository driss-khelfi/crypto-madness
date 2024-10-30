#include <iostream>

#include <vector>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>

#include <fstream>
#include <map>

#include <math.h>

#include "../include/LPTF_Net/LPTF_Socket.hpp"
#include "../include/LPTF_Net/LPTF_Utils.hpp"

#include <sodium.h>

#include "../include/crypto.hpp"

using namespace std;


#define PASSWORD_FILE "actually_safe_this_time.txt"
#define KEYS_FILE "user_keys_do_not_steal_plz.txt"



void close_client_connection(int clientSockfd, vector<struct client> &clients, mutex &clients_mutex);
std::pair<std::string, std::vector<unsigned char>> wait_for_login(LPTF_Socket *serverSocket, int clientSockfd, vector<struct client> &clients, mutex &clients_mutex);
bool is_user_logged_in(string username, vector<struct client> &clients, mutex &clients_mutex);
void send_message(LPTF_Socket *serverSocket, int clientSockfd, std::vector<unsigned char> *key, string userfrom, string message, time_t t);
void broadcast_message(LPTF_Socket *serverSocket, int clientSockfd, string userfrom, string message, time_t t, vector<struct client> &clients, mutex &clients_mutex);
void listen_for_client(LPTF_Socket *serverSocket, int clientSockfd, sockaddr_in clientAddr, socklen_t clientAddrLen, vector<struct client> &clients, mutex &clients_mutex);
void set_client_username(int clientSockfd, string username, vector<struct client> &clients, mutex &clients_mutex);
std::map<std::string, std::string> read_passwords();
void write_password(const std::string &username, const std::string &hashed_password);
std::map<std::string, std::vector<unsigned char>> read_keys();
void write_key(const std::string &username, const std::vector<unsigned char> &key, const std::vector<unsigned char> &salt);


ssize_t send_encrypted(LPTF_Socket *socket, int sockfdto, LPTF_Packet &packet, int flags, std::vector<unsigned char> *key) {

    string encrypted_content = encrypt_symmetric(string((char *)packet.get_content(), packet.get_header().length), *key);

    LPTF_Packet encr_pckt = LPTF_Packet(packet.type(), (void *) encrypted_content.c_str(), encrypted_content.size());

    encr_pckt.set_reserved_byte(1);    // flag to tell that the packet is encrypted
    return socket->send(sockfdto, encr_pckt, flags);

}

LPTF_Packet recv_encrypted(LPTF_Socket *socket, int sockfdfrom, int flags, std::vector<unsigned char> *key) {
    LPTF_Packet pckt = socket->recv(sockfdfrom, flags);

    if (pckt.get_header().reserved == 1) {
        string content = decrypt_symmetric(string((char *)pckt.get_content(), pckt.get_header().length), *key);
        pckt = LPTF_Packet(pckt.type(), (void *) content.c_str(), content.size());
    } else {
        throw runtime_error("Packet is not encrypted !");
    }

    return pckt;

}


struct client {
    int sockfd;
    string username;
    std::vector<unsigned char> *key;
};


bool is_password_valid(const string &password) {
    if (password.size() < 8) return false;  //8 characters long

    bool has_space = false, has_upper = false, has_special = false, has_digit = false;
    for (char c : password) {
        if (isspace(c)) has_space = true;  // no spaces
        if (isupper(c)) has_upper = true;  // upper letter
        if (isdigit(c)) has_digit = true;  // digit
        if (ispunct(c)) has_special = true;  // special character
    }

    return !has_space && has_upper && has_special && has_digit;
}

float calculate_password_entropy(const string &password) {
    if (password.empty()) return 0.0;

    map<char, int> char_count;
    for (char c : password) {
        char_count[c]++;
    }

    float entropy = 0.0;
    float log2 = log(2.0);
    for (auto &p : char_count) {
        float freq = static_cast<float>(p.second) / password.length();
        entropy -= freq * (log(freq) / log2);
    }
    
    entropy *= password.length();
    return entropy;
}


// borrowed from https://www.geeksforgeeks.org/thread-pool-in-cpp/
class ThreadPool { 
public: 
    ThreadPool(size_t num_threads = thread::hardware_concurrency()) {
        // Creating worker threads
        for (size_t i = 0; i < num_threads; ++i) { 
            threads_.emplace_back([this] { 
                while (true) { 
                    function<void()> task; 
                    { 
                        // Lock queue so that data 
                        // can be shared safely
                        unique_lock<mutex> lock( 
                            queue_mutex_); 
  
                        // Waiting until there is a task to 
                        // execute or the pool is stopped
                        cv_.wait(lock, [this] { 
                            return !tasks_.empty() || stop_; 
                        }); 
  
                        // exit the thread in case the pool 
                        // is stopped and there are no tasks 
                        if (stop_ && tasks_.empty()) { 
                            return; 
                        } 
  
                        // Get the next task from the queue 
                        task = std::move(tasks_.front()); 
                        tasks_.pop(); 
                    } 
  
                    task(); 
                } 
            }); 
        } 
    } 
  
    ~ThreadPool() 
    { 
        {
            // Lock the queue to update the stop flag safely 
            unique_lock<mutex> lock(queue_mutex_); 
            stop_ = true; 
        }

        cv_.notify_all(); 
  
        // Joining all worker threads to ensure they have 
        // completed their tasks
        for (auto& thread : threads_) { 
            thread.join(); 
        } 
    } 
  
    // Enqueue task for execution by the thread pool 
    void enqueue(function<void()> task) 
    { 
        { 
            unique_lock<mutex> lock(queue_mutex_); 
            tasks_.emplace(std::move(task)); 
        } 
        cv_.notify_one(); 
    } 
  
private: 
    // Vector to store worker threads 
    vector<thread> threads_;
    // Queue of tasks 
    queue<function<void()> > tasks_;
    // Mutex to synchronize access to shared data 
    mutex queue_mutex_;
    // Condition variable to signal changes in the state of 
    // the tasks queue 
    condition_variable cv_;
    // Flag to indicate whether the thread pool should stop 
    // or not 
    bool stop_ = false;
};


std::pair<std::string, std::vector<unsigned char>> wait_for_login(LPTF_Socket *serverSocket, int clientSockfd, vector<struct client> &clients, mutex &clients_mutex) {
    std::map<std::string, std::string> passwords = read_passwords();
    std::map<std::string, std::vector<unsigned char>> keys = read_keys();

    LPTF_Packet pckt = serverSocket->recv(clientSockfd, 0);

    if (pckt.type() == LOGIN_PACKET) {
        string client_username ((const char *)pckt.get_content(), pckt.get_header().length);

        if (client_username.size() == 0) {
            string err_msg = "Username invalid !";
            LPTF_Packet error_packet = build_error_packet(LOGIN_PACKET, ERR_CODE_FAILURE, err_msg);
            serverSocket->send(clientSockfd, error_packet, 0);
            return {string(), vector<unsigned char>()};
        } else {
            if (passwords.find(client_username) != passwords.end()) {
                // User exist -> key verif.

                // get key from file
                if (keys.find(client_username) == keys.end()) {
                    // should not happen
                    cout << "Key not found for registered user " << client_username << endl;
                    return {string(), vector<unsigned char>()};
                }

                std::vector<unsigned char> key = keys[client_username];
                
                // generate random bytes to verify user key
                unsigned char verif_bytes[16];
                randombytes(verif_bytes, 16);

                string verif_str = bytes_to_hex_string(verif_bytes, 16);
                string encr_verif_str = encrypt_symmetric(verif_str, key);

                LPTF_Packet verif_packet = build_reply_packet(LOGIN_PACKET, (void *) encr_verif_str.c_str(), encr_verif_str.size());

                serverSocket->send(clientSockfd, verif_packet, 0);

                LPTF_Packet resp = serverSocket->recv(clientSockfd, 0);

                // user doesn't have the key or error
                if (resp.type() != MESSAGE_PACKET) {
                    cout << "Invalid packet !" << endl;
                    return {string(), vector<unsigned char>()};
                }

                // fail
                if (strcmp(verif_str.c_str(), get_message_from_message_packet(resp).c_str()) != 0) {
                    string err_msg = "Invalid key !";
                    LPTF_Packet error_packet = build_error_packet(LOGIN_PACKET, ERR_CODE_UNKNOWN, err_msg);
                    serverSocket->send(clientSockfd, error_packet, 0);
                    return {string(), vector<unsigned char>()};
                }

                // check if user is logged in
                if (is_user_logged_in(client_username, clients, clients_mutex)) {
                    string err_msg = "User already logged in !";
                    LPTF_Packet error_packet = build_error_packet(LOGIN_PACKET, ERR_CODE_FAILURE, err_msg);
                    serverSocket->send(clientSockfd, error_packet, 0);
                    return {string(), vector<unsigned char>()};
                }

                LPTF_Packet success_packet = build_reply_packet(LOGIN_PACKET, (void*)"OK", 2);
                serverSocket->send(clientSockfd, success_packet, 0);
                return {client_username, key};

            } else {
                // User doesn't exist, ask for new password
                LPTF_Packet ask_password_packet = build_message_packet("Create a new Password: ");
                serverSocket->send(clientSockfd, ask_password_packet, 0);

                LPTF_Packet password_packet = serverSocket->recv(clientSockfd, 0);
                LPTF_Packet password_confirm_packet = serverSocket->recv(clientSockfd, 0);
                std::string password((const char *)password_packet.get_content(), password_packet.get_header().length);
                string password_confirm ((const char *)password_confirm_packet.get_content(), password_confirm_packet.get_header().length);

                if (password == password_confirm) {

                    if (!is_password_valid(password)) {
                        string err_msg = "Password format invalid !";
                        LPTF_Packet error_packet = build_error_packet(LOGIN_PACKET, ERR_CODE_FAILURE, err_msg);
                        serverSocket->send(clientSockfd, error_packet, 0);
                        return {string(), vector<unsigned char>()};
                    }
                    
                    if (is_user_logged_in(client_username, clients, clients_mutex)) {
                        string err_msg = "User already logged in !";
                        LPTF_Packet error_packet = build_error_packet(LOGIN_PACKET, ERR_CODE_FAILURE, err_msg);
                        serverSocket->send(clientSockfd, error_packet, 0);
                        return {string(), vector<unsigned char>()};
                    }

                    cout << "Entropy: " << calculate_password_entropy(password) << endl;

                    // generate keys and send key to client

                    auto key_n_salt = generate_symmetric_key(password);

                    write_password(client_username, sha256_with_salt96(password));
                    write_key(client_username, key_n_salt.first, key_n_salt.second);

                    unsigned char key[KEY_LENGTH];
                    for (int i = 0; i < KEY_LENGTH; i++)
                        key[i] = key_n_salt.first.at(i);

                    LPTF_Packet success_packet = build_reply_packet(LOGIN_PACKET, (void*) key, KEY_LENGTH);
                    serverSocket->send(clientSockfd, success_packet, 0);
                    return {client_username, key_n_salt.first};
                } else {
                    string err_msg = "Password and Confirmation are different !";
                    LPTF_Packet error_packet = build_error_packet(LOGIN_PACKET, ERR_CODE_UNKNOWN, err_msg);
                    serverSocket->send(clientSockfd, error_packet, 0);
                }
            }
        }
    } else {
        string err_msg = "You must log in to perform this action.";
        LPTF_Packet error_packet = build_error_packet(pckt.type(), ERR_CODE_UNKNOWN, err_msg);
        serverSocket->send(clientSockfd, error_packet, 0);
    }

    return {string(), vector<unsigned char>()};
}


bool is_user_logged_in(string username, vector<struct client> &clients, mutex &clients_mutex) {
    lock_guard<mutex> lock(clients_mutex);
    
    for (auto client : clients) {
        if (client.username.compare(username) == 0)
            return true;
    }

    return false;
}


void close_client_connection(int clientSockfd, vector<struct client> &clients, mutex &clients_mutex) {
    cout << "Closing client connection" << endl;

    {
        lock_guard<mutex> lock(clients_mutex);
        for (auto it = clients.begin(); it != clients.end(); next(it)) {
            if ((*it).sockfd == clientSockfd) {
                // delete it->key;  // not needed as key is from a local var ref and is eventually deleted
                clients.erase(it);
                break;
            }
        }  
    }
    
    close(clientSockfd);
}

void set_client_username(int clientSockfd, string username, vector<struct client> &clients, mutex &clients_mutex) {
    lock_guard<mutex> lock(clients_mutex);
    for (auto &client : clients) {
        if (client.sockfd == clientSockfd) {
            client.username = username;
            break;
        }
    }
}

void set_client_key(int clientSockfd, std::vector<unsigned char> *key, vector<struct client> &clients, mutex &clients_mutex) {
    lock_guard<mutex> lock(clients_mutex);
    for (auto &client : clients) {
        if (client.sockfd == clientSockfd) {
            client.key = key;
            break;
        }
    }
}


std::map<std::string, std::string> read_passwords() {
    std::ifstream file(PASSWORD_FILE);
    std::map<std::string, std::string> passwords;
    std::string line;
    
    while (std::getline(file, line)) {
        size_t sep = line.find(':');
        if (sep != std::string::npos) {
            std::string username = line.substr(0, sep);
            std::string password = line.substr(sep + 1);
            passwords[username] = password;
        }
    }
    file.close();
    return passwords;
}


std::map<std::string, std::vector<unsigned char>> read_keys() {
    std::ifstream file(KEYS_FILE);
    std::map<std::string, std::vector<unsigned char>> keys;
    std::string line;
    
    while (std::getline(file, line)) {
        size_t sep = line.find(':');
        if (sep != std::string::npos) {
            std::string username = line.substr(0, sep);
            // do not take salt
            std::string key_str = line.substr(sep + 1).substr(SALT_LENGTH*2);

            std::vector<unsigned char> key = hex_string_to_bytes(key_str);

            keys[username] = key;
        }
    }
    file.close();
    return keys;
}


void write_password(const std::string &username, const std::string &hashed_password) {
    std::ofstream file(PASSWORD_FILE, std::ios::app);
    file << username << ":" << hashed_password << std::endl;
    file.close();
}


void write_key(const std::string &username, const std::vector<unsigned char> &key, const std::vector<unsigned char> &salt) {
    std::ofstream file(KEYS_FILE, std::ios::app);
    file << username << ":" << bytes_to_hex_string(salt) << bytes_to_hex_string(key) << std::endl;
    file.close();
}


void send_message(LPTF_Socket *serverSocket, int clientSockfd, std::vector<unsigned char> *key, string userfrom, string message, time_t t) {
    char timestamp[22];
    strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S]", localtime(&t));

    string content (timestamp);
    content += " " + userfrom + ": " + message;

    LPTF_Packet msg = build_message_packet(content);
    send_encrypted(serverSocket, clientSockfd, msg, 0, key);
}


void broadcast_message(LPTF_Socket *serverSocket, int clientSockfd, string userfrom, string message, time_t t, vector<struct client> &clients, mutex &clients_mutex) {
    lock_guard<mutex> lock(clients_mutex);

    for (auto client : clients) {
        if (client.sockfd != clientSockfd && client.username.size() != 0) {
            
            try {
                send_message(serverSocket, client.sockfd, client.key, userfrom, message, t);
                cout << "Messsage sent to client " << client.username << endl;
            } catch (const runtime_error &ex) {
                cout << "Unable to send message to client " << client.username << ": " << ex.what();
            }

        }
    }
}


void listen_for_client(LPTF_Socket *serverSocket, int clientSockfd, sockaddr_in clientAddr, socklen_t clientAddrLen, vector<struct client> &clients, mutex &clients_mutex) {
    {
        lock_guard<mutex> lock(clients_mutex);
        clients.push_back({clientSockfd, string(), nullptr});
    }

    cout << "Handling client: " << inet_ntoa(clientAddr.sin_addr) << ":" << ntohs(clientAddr.sin_port) << " (len:" << clientAddrLen << ")" << endl;

    std::pair<std::string, std::vector<unsigned char>> ret_login;

    try {
        ret_login = wait_for_login(serverSocket, clientSockfd, clients, clients_mutex);
    } catch (const runtime_error &ex) {
        cout << "Login error: " << ex.what();
        close_client_connection(clientSockfd, clients, clients_mutex);
        return;
    }

    string username = ret_login.first;

    if (username.size() == 0) {
        close_client_connection(clientSockfd, clients, clients_mutex);
        return;
    }

    set_client_username(clientSockfd, username, clients, clients_mutex);

    cout << "Client logged in as \"" << username << "\"" << endl;

    // private key
    std::vector<unsigned char> *key = &ret_login.second;

    set_client_key(clientSockfd, key, clients, clients_mutex);

    try {
        // listen for packets
        while (true) {
            LPTF_Packet req = recv_encrypted(serverSocket, clientSockfd, 0, key);

            if (req.type() == MESSAGE_PACKET) {
                time_t t = time(0);
                string message = get_message_from_message_packet(req);

                broadcast_message(serverSocket, clientSockfd, username, message, t, clients, clients_mutex);
            } else {
                cout << "Got non-message packet from client: \"" << req.type() << "\"" << endl;
                
                string err_msg = "Not Implemented";
                LPTF_Packet err_pckt = build_error_packet(req.type(), ERR_CODE_UNKNOWN, err_msg);
                serverSocket->send(clientSockfd, err_pckt, 0);
                break;
            }
        }
    } catch (const exception &ex) {
        cout << "Exception when handling client " << username << ": " << ex.what() << endl;
    }

    close_client_connection(clientSockfd, clients, clients_mutex);
}


int main() {

    if (sodium_init() < 0) {
        cout << "Could not init sodium library !" << endl;
        return 1;
    }

    int port = 12345;
    int max_clients = 10;

    try {
        ThreadPool clientPool(max_clients);

        vector<struct client> clients;
        mutex clients_mutex;

        LPTF_Socket serverSocket = LPTF_Socket();

        struct sockaddr_in serverAddr;
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);

        serverSocket.bind(reinterpret_cast<struct sockaddr *>(&serverAddr), sizeof(serverAddr));
        serverSocket.listen(max_clients);   // limit number of clients

        cout << "Server running: " << inet_ntoa(serverAddr.sin_addr) << ":" << ntohs(serverAddr.sin_port) << endl;

        while (true) {
            cout << "Waiting for new client..." << endl;
            struct sockaddr_in clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);
            int clientSockfd = serverSocket.accept(reinterpret_cast<struct sockaddr *>(&clientAddr), &clientAddrLen);

            if (clientSockfd == -1) throw runtime_error("Error on accept connection !");

            clientPool.enqueue([&serverSocket, clientSockfd, clientAddr, clientAddrLen, &clients, &clients_mutex] { listen_for_client(&serverSocket, clientSockfd, clientAddr, clientAddrLen, clients, clients_mutex); });

        }

    } catch (const exception &ex) {
        cerr << "Exception: " << ex.what() << endl;
        return 1;
    }

    return 0;
}
