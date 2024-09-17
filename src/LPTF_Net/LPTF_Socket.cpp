#include <iostream>
#include <stdexcept>
#include <memory>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../include/LPTF_Net/LPTF_Socket.hpp"
#include "../../include/LPTF_Net/LPTF_Packet.hpp"


using namespace std;


LPTF_Socket::LPTF_Socket() {
    sockfd = -1;
    init(AF_INET, SOCK_STREAM, 0);
}

LPTF_Socket::LPTF_Socket(int domain, int type, int protocol) {
    sockfd = -1;
    init(domain, type, protocol);
}
    
LPTF_Socket::~LPTF_Socket() {
    if (sockfd != -1)
        close();
}

LPTF_Socket::LPTF_Socket(const LPTF_Socket &src) {
    sockfd = src.sockfd;
}

LPTF_Socket &LPTF_Socket::operator=(const LPTF_Socket &src) {
    sockfd = src.sockfd;
    return *this;
}


void LPTF_Socket::init(int domain, int type, int protocol) {
    if (sockfd > 0) {
        throw runtime_error("Socket already created");
    }

    sockfd = socket(domain, type, protocol);
    if (sockfd == -1) {
        throw runtime_error("Failed to create socket");
    }
}

void LPTF_Socket::connect(const struct sockaddr *addr, socklen_t addrlen) {
    if (::connect(sockfd, addr, addrlen) == -1) {
        throw runtime_error("Failed to connect to server");
    }
}

ssize_t LPTF_Socket::send(int sockfdto, LPTF_Packet &packet, int flags) {
    void *data = packet.data();

    if (data) {
        ssize_t retval = ::send(sockfdto, data, packet.size(), flags);
        free(data);
        return retval;
    }

    return -1;
}

LPTF_Packet LPTF_Socket::recv(int sockfdfrom, int flags) {
    uint8_t buffer[sizeof(PACKET_HEADER)+UINT16_MAX];
    ssize_t retval = ::recv(sockfdfrom, buffer, sizeof(PACKET_HEADER)+UINT16_MAX, flags);

    if (retval < 0 /*aka -1*/ || ((size_t) retval) /*-Wsign-compare*/ < sizeof(PACKET_HEADER)) {
        char msg[64];
        sprintf(msg, "Received too few bytes (expected %ld, got %ld).", sizeof(PACKET_HEADER), retval);
        throw runtime_error(msg);
    }

    LPTF_Packet packet(buffer, sizeof(PACKET_HEADER)+UINT16_MAX);

    // cout << "Packet Received:" << endl;
    // packet.print_specs();

    return packet;
}

LPTF_Packet LPTF_Socket::read() {
    uint8_t buffer[sizeof(PACKET_HEADER)+UINT16_MAX];
    ssize_t retval = ::read(sockfd, buffer, sizeof(PACKET_HEADER)+UINT16_MAX);

    if (retval < 0 /*aka -1*/ || ((size_t) retval) /*-Wsign-compare*/ < sizeof(PACKET_HEADER)) {
        char msg[64];
        sprintf(msg, "Received too few bytes (expected %ld, got %ld).", sizeof(PACKET_HEADER), retval);
        throw runtime_error(msg);
    }

    LPTF_Packet packet(buffer, sizeof(PACKET_HEADER)+UINT16_MAX);

    // cout << "Packet Read:" << endl;
    // packet.print_specs();

    return packet;
}

ssize_t LPTF_Socket::write(LPTF_Packet &packet) {
    void *data = packet.data();

    if (data) {
        ssize_t retval = ::write(sockfd, data, packet.size());
        free(data);
        return retval;
    }
    
    return -1;
}

int LPTF_Socket::accept(sockaddr *__restrict__ addr, socklen_t *__restrict__ addr_len) {
    return ::accept(sockfd, addr, addr_len);
}

int LPTF_Socket::bind(const sockaddr *addr, socklen_t len) {
    return ::bind(sockfd, addr, len);
}

int LPTF_Socket::listen(int backlog) {
    return ::listen(sockfd, backlog);
}

int LPTF_Socket::close() {
    int ret = ::close(sockfd);
    sockfd = -1;
    return ret;
}
