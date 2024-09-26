#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <stdint.h>
#include <arpa/inet.h>

#include "../../include/LPTF_Net/LPTF_Packet.hpp"
// #include "LPTF_Utils.hpp"


/*
Default Constructor
*/
LPTF_Packet::LPTF_Packet() {
    header = {0, 0, 0};
    content = nullptr;
}

/*
Builds a packet with the specified PACKET_TYPE, data and data length.
*/
LPTF_Packet::LPTF_Packet(uint8_t type, void *rawdata, uint16_t datalen) {
    header.type = type;
    content = nullptr;

    if (datalen != 0) {
        content = malloc(datalen);
        if (!content) {
            throw std::runtime_error("Memory allocation for LPTF_Packet failed !");
        } else {
            memcpy(content, rawdata, datalen);
        }
    }

    header.length = datalen;
    header.reserved = 0;
}

/*
Builds a packet from the received raw packet data from either LPTF_Socket::recv() or LPTF_Socket::read()
*/
LPTF_Packet::LPTF_Packet(void *rawpacket, size_t buffmaxsize) {
    content = nullptr;

    if (buffmaxsize < 4)
        throw std::runtime_error("Raw data invalid: buffer is too small !");

    // interpret raw data as a 1 byte data array
    uint8_t *data = (uint8_t*)rawpacket;

    // extract header info

    memcpy(&header.type, data, 1);

    memcpy(&header.length, data+1, 2);
    header.length = htons(header.length);

    header.reserved = data[3];

    if (header.length != 0) {
        if (buffmaxsize-4 < header.length) {
            throw std::runtime_error("Buffer is too small compared to the packet's expected content size !");
        }

        content = malloc(header.length);
        if (!content) {
            throw std::runtime_error("Memory allocation for LPTF_Packet failed !");
        } else {
            memcpy(content, ((uint8_t*)data)+sizeof(PACKET_HEADER), header.length);
        }
    }

}

/*
Copy Constructor
*/
LPTF_Packet::LPTF_Packet(const LPTF_Packet &src) {
    header = src.header;
    if (header.length != 0 && src.content) {
        content = malloc(header.length);
        if (!content) {
            throw std::runtime_error("Memory allocation for LPTF_Packet Copy Constructor failed !");
        } else {
            memcpy(content, src.content, header.length);
        }
    }
}

// Destructor
LPTF_Packet::~LPTF_Packet() {
    if (content && header.length != 0) {
        free(content);
        header.length = 0;
        content = nullptr;
    }
}

// Equal Operator
LPTF_Packet &LPTF_Packet::operator=(const LPTF_Packet &src) {
    header = src.header;
    if (header.length != 0 && src.content) {
        if (content)
            free(content);
        
        content = malloc(header.length);
        if (!content) {
            throw std::runtime_error("Memory allocation for LPTF_Packet Equal Operator failed !");
        } else {
            memcpy(content, src.content, header.length);
        }
    }
    return *this;
}

uint8_t LPTF_Packet::type() {
    return header.type;
}

/*
Returns the size of the packet (header + content)
*/
uint16_t LPTF_Packet::size() {
    return sizeof(header) + header.length;
}

const PACKET_HEADER LPTF_Packet::get_header() {
    return header;
}

const void *LPTF_Packet::get_content() {
    return content;
}

/*
Returns the total data to be sent with LPTF_Socket (header + content).
A new memory section is allocated each time the function is called.

Returns 0 on failure.
*/
void *LPTF_Packet::data() {
    void *data = malloc(size());
    if (!data)
        return data;
    
    memcpy(data, &header.type, 1);
    memcpy(((uint8_t*)data)+3, &header.reserved, 1);

    if (content) {
        // copy length
        uint16_t lengthB = ntohs(header.length);
        memcpy(((uint8_t*)data)+1, &lengthB, 2);

        // copy content
        memcpy(((uint8_t*)data)+4, content, header.length);
    } else {
        // put empty len
        uint16_t empty = 0;
        memcpy(((uint8_t*)data)+1, &empty, 2);
    }

    return data;
}

void LPTF_Packet::print_specs() {
    printf("Header:\n");
    printf("  Type: %d\n", header.type);
    printf("  Length: %d\n", header.length);
    printf("  Reserved: %d\n", header.reserved);
    printf("Raw Content: ");

    for (int i = 0; i < header.length; i++) {
        printf("%d ", ((uint8_t*)content)[i]);
    }

    printf("\n");
    printf("Raw Data: ");

    uint8_t *raw = (uint8_t*)data();
    if (raw) {
        for (int i = 0; i < size(); i++) {
            printf("%d ", raw[i]);
        }
        free(raw);
    }

    std::cout << std::endl;
}


void LPTF_Packet::set_reserved_byte(uint8_t b) { header.reserved = b; }
