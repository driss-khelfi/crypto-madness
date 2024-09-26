#pragma once

#include <stdlib.h>
#include <stdint.h>


#define REPLY_PACKET 0
#define MESSAGE_PACKET 1

// command packet types

#define UPLOAD_FILE_COMMAND 2
#define DOWNLOAD_FILE_COMMAND 3
#define DELETE_FILE_COMMAND 4
#define LIST_FILES_COMMAND 5
#define CREATE_FOLDER_COMMAND 6
#define DELETE_FOLDER_COMMAND 7
#define RENAME_FOLDER_COMMAND 8
#define USER_TREE_COMMAND 9

#define BINARY_PART_PACKET 10
#define LOGIN_PACKET 11

#define OTP_GEN_BYTES_PACKET 0xFE

#define ERROR_PACKET 0xFF   // a packet type should not be higher than this value


// command error codes
#define ERR_CODE_FAILURE 0
#define ERR_CODE_UNKNOWN 1


typedef struct {
    uint16_t length;
    uint8_t type;
    uint8_t reserved;
} PACKET_HEADER;


#define FILE_TRANSFER_REP_OK "OK"

// constexpr uint16_t MAX_BINARY_PART_BYTES = UINT16_MAX - sizeof(PACKET_HEADER) - sizeof(uint32_t) - sizeof(uint32_t);
constexpr uint16_t MAX_BINARY_PART_BYTES = 8000;


class LPTF_Packet {
    private:
        PACKET_HEADER header;
        void *content;
    public:
        LPTF_Packet();

        LPTF_Packet(uint8_t type, void *rawcontent, uint16_t datalen);

        LPTF_Packet(void *rawpacket, size_t buffmaxsize);

        LPTF_Packet(const LPTF_Packet &src);

        virtual ~LPTF_Packet();

        LPTF_Packet &operator=(const LPTF_Packet &src);
        
        uint8_t type();

        uint16_t size();

        const void *get_content();
        const PACKET_HEADER get_header();

        virtual void *data();

        void print_specs();

        void set_reserved_byte(uint8_t b);
};
