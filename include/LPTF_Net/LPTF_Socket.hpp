#pragma once

#include <iostream>
#include <stdexcept>
#include <memory>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "LPTF_Packet.hpp"


class LPTF_Socket {
private:
    int sockfd;

public:
    LPTF_Socket();

    LPTF_Socket(int domain, int type, int protocol);
    
    LPTF_Socket(const LPTF_Socket &src);

    ~LPTF_Socket();

    LPTF_Socket &operator=(const LPTF_Socket &src);

    void init(int domain, int type, int protocol);

    void connect(const struct sockaddr *addr, socklen_t addrlen);

    ssize_t send(int sockfdto, LPTF_Packet &packet, int flags);

    LPTF_Packet recv(int sockfdfrom, int flags);

    LPTF_Packet read();

    ssize_t write(LPTF_Packet &packet);

    int accept(sockaddr *__restrict__ addr, socklen_t *__restrict__ addr_len);

    int bind(const sockaddr *addr, socklen_t len);

    int listen(int backlog);

    int close();
};
