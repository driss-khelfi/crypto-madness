#include <iostream>

#include <vector>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>

#include "../include/LPTF_Net/LPTF_Socket.hpp"
#include "../include/LPTF_Net/LPTF_Utils.hpp"

using namespace std;

struct client {
    int sockfd;
    string username;
};


void close_client_connection(int clientSockfd, vector<struct client> &clients, mutex &clients_mutex);
string wait_for_login(LPTF_Socket *serverSocket, int clientSockfd, vector<struct client> &clients, mutex &clients_mutex);
bool is_user_logged_in(string username, vector<struct client> &clients, mutex &clients_mutex);
void send_message(LPTF_Socket *serverSocket, int clientSockfd, string userfrom, string message, time_t t);
void broadcast_message(LPTF_Socket *serverSocket, int clientSockfd, string userfrom, string message, time_t t, vector<struct client> &clients, mutex &clients_mutex);
void listen_for_client(LPTF_Socket *serverSocket, int clientSockfd, sockaddr_in clientAddr, socklen_t clientAddrLen, vector<struct client> &clients, mutex &clients_mutex);
void set_client_username(int clientSockfd, string username, vector<struct client> &clients, mutex &clients_mutex);


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


void close_client_connection(int clientSockfd, vector<struct client> &clients, mutex &clients_mutex) {
    cout << "Closing client connection" << endl;

    {
        lock_guard<mutex> lock(clients_mutex);
        for (auto it = clients.begin(); it != clients.end(); next(it)) {
            if ((*it).sockfd == clientSockfd) {
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


string wait_for_login(LPTF_Socket *serverSocket, int clientSockfd, vector<struct client> &clients, mutex &clients_mutex) {
    LPTF_Packet pckt = serverSocket->recv(clientSockfd, 0);

    if (pckt.type() == LOGIN_PACKET) {
        string client_username ((const char *)pckt.get_content(), pckt.get_header().length);

        if (client_username.size() == 0) {
            string err_msg = "Username invalid !";
            LPTF_Packet error_packet = build_error_packet(LOGIN_PACKET, ERR_CMD_FAILURE, err_msg);
            serverSocket->send(clientSockfd, error_packet, 0);
            return string();
        } else if (is_user_logged_in(client_username, clients, clients_mutex)) {
            string err_msg = "User already logged in !";
            LPTF_Packet error_packet = build_error_packet(LOGIN_PACKET, ERR_CMD_FAILURE, err_msg);
            serverSocket->send(clientSockfd, error_packet, 0);
            return string();
        } else {
            LPTF_Packet success_packet = build_reply_packet(LOGIN_PACKET, (void*)"OK", 2);
            serverSocket->send(clientSockfd, success_packet, 0);
            return client_username;
        }

    } else {
        string err_msg = "You must log in to perform this action.";
        LPTF_Packet error_packet = build_error_packet(pckt.type(), ERR_CMD_UNKNOWN, err_msg);
        serverSocket->send(clientSockfd, error_packet, 0);
    }

    return string();
}


bool is_user_logged_in(string username, vector<struct client> &clients, mutex &clients_mutex) {
    lock_guard<mutex> lock(clients_mutex);
    
    for (auto client : clients) {
        if (client.username.compare(username) == 0)
            return true;
    }

    return false;
}


void send_message(LPTF_Socket *serverSocket, int clientSockfd, string userfrom, string message, time_t t) {
    // FIXME change MESSAGE packet structure to include: time, userfrom, message

    char timestamp[22];
    strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S]", localtime(&t));

    string content (timestamp);
    content += " " + userfrom + ": " + message;

    LPTF_Packet msg = build_message_packet(content);
    serverSocket->send(clientSockfd, msg, 0);
}


void broadcast_message(LPTF_Socket *serverSocket, int clientSockfd, string userfrom, string message, time_t t, vector<struct client> &clients, mutex &clients_mutex) {
    lock_guard<mutex> lock(clients_mutex);

    for (auto client : clients) {
        if (client.sockfd != clientSockfd && client.username.size() != 0) {
            
            try {
                send_message(serverSocket, client.sockfd, userfrom, message, t);
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
        clients.push_back({clientSockfd, string()});
    }

    cout << "Handling client: " << inet_ntoa(clientAddr.sin_addr) << ":" << ntohs(clientAddr.sin_port) << " (len:" << clientAddrLen << ")" << endl;

    string username;

    try {
        username = wait_for_login(serverSocket, clientSockfd, clients, clients_mutex);
    } catch (const runtime_error &ex) {
        cout << "Login error: " << ex.what();
        close_client_connection(clientSockfd, clients, clients_mutex);
        return;
    }

    if (username.size() == 0) {
        close_client_connection(clientSockfd, clients, clients_mutex);
        return;
    }

    set_client_username(clientSockfd, username, clients, clients_mutex);

    cout << "Client logged in as \"" << username << "\"" << endl;

    try {
        // listen for packets
        while (true) {
            LPTF_Packet req = serverSocket->recv(clientSockfd, 0);

            if (req.type() == MESSAGE_PACKET) {
                time_t t = time(0);
                string message = get_message_from_message_packet(req);

                broadcast_message(serverSocket, clientSockfd, username, message, t, clients, clients_mutex);
            } else {
                cout << "Got non-message packet from client: \"" << req.type() << "\"" << endl;
                
                string err_msg = "Not Implemented";
                LPTF_Packet err_pckt = build_error_packet(req.type(), ERR_CMD_UNKNOWN, err_msg);
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
