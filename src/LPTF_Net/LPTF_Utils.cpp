#include <iostream>
#include <cstring>

#include <netinet/in.h>

#include "../../include/LPTF_Net/LPTF_Packet.hpp"
#include "../../include/LPTF_Net/LPTF_Utils.hpp"

using namespace std;


bool is_command_packet(uint8_t type) {
    return type >= UPLOAD_FILE_COMMAND && type <= USER_TREE_COMMAND;
}

bool is_command_packet(LPTF_Packet &packet) {
    return is_command_packet(packet.type());
}


// repfrom is the packet type this reply refers to
LPTF_Packet build_reply_packet(uint8_t repfrom, void *repcontent, uint16_t contentsize) {
    uint8_t *rawcontent = (uint8_t*)malloc(sizeof(uint8_t)+contentsize);

    if (!rawcontent)
        throw runtime_error("Memory allocation failed !");

    memcpy(rawcontent, &repfrom, sizeof(uint8_t));
    memcpy(rawcontent + sizeof(uint8_t), repcontent, contentsize);

    LPTF_Packet packet(REPLY_PACKET, rawcontent, sizeof(uint8_t)+contentsize);

    free(rawcontent);
    return packet;
}


LPTF_Packet build_message_packet(const string &message) {
    LPTF_Packet packet(MESSAGE_PACKET, (void*)message.c_str(), message.size());
    return packet;
}


LPTF_Packet build_command_packet(uint8_t cmd_type, const string &arg) {
    LPTF_Packet packet(cmd_type, (void*)arg.c_str(), arg.size());
    return packet;
}


// errfrom is the packet type this error refers to
LPTF_Packet build_error_packet(uint8_t errfrom, uint8_t err_code, string &errmsg) {
    uint8_t *rawcontent = (uint8_t*)malloc(sizeof(uint8_t)*2 + errmsg.size()+1);

    if (!rawcontent)
        throw runtime_error("Memory allocation failed !");
    
    memcpy(rawcontent, &errfrom, sizeof(uint8_t));
    memcpy(rawcontent + sizeof(uint8_t), &err_code, sizeof(uint8_t));
    memcpy(rawcontent + sizeof(uint8_t)*2, errmsg.c_str(), errmsg.size()+1);

    LPTF_Packet packet(ERROR_PACKET, rawcontent,
                       sizeof(uint8_t)*2 + errmsg.size()+1);
    free(rawcontent);
    return packet;
}


LPTF_Packet build_file_upload_request_packet(const string filepath, uint32_t filesize) {
    size_t size = filepath.size()+1 + sizeof(filesize);
    uint8_t *rawcontent = (uint8_t*)malloc(size);

    if (!rawcontent)
        throw runtime_error("Memory allocation failed !");

    filesize = htonl(filesize);

    memcpy(rawcontent, filepath.c_str(), filepath.size()+1);
    memcpy(rawcontent + filepath.size()+1, &filesize, sizeof(filesize));

    LPTF_Packet packet(UPLOAD_FILE_COMMAND, rawcontent, size);

    free(rawcontent);
    return packet;
}


LPTF_Packet build_file_download_request_packet(const string filepath) {
    return build_command_packet(DOWNLOAD_FILE_COMMAND, filepath);
}


LPTF_Packet build_file_delete_request_packet(const string filepath) {
    return build_command_packet(DELETE_FILE_COMMAND, filepath);
}

LPTF_Packet build_list_directory_request_packet(const string pathname) {
    return build_command_packet(LIST_FILES_COMMAND, pathname);
}

LPTF_Packet build_create_directory_request_packet(const string folder) {
    return build_command_packet(CREATE_FOLDER_COMMAND, folder);
}

LPTF_Packet build_remove_directory_request_packet(string folder) {
    return build_command_packet(DELETE_FOLDER_COMMAND, folder);
}


LPTF_Packet build_rename_directory_request_packet(const string newname, const string path) {
    uint16_t size = newname.size()+1 + path.size();

    uint8_t *rawcontent = (uint8_t*)malloc(size);

    if (!rawcontent)
        throw runtime_error("Memory allocation failed !");
    
    memcpy(rawcontent, newname.c_str(), newname.size()+1);
    memcpy(rawcontent + newname.size()+1, path.c_str(), path.size());

    LPTF_Packet packet(RENAME_FOLDER_COMMAND, rawcontent, size);
    free(rawcontent);
    return packet;
}


LPTF_Packet build_binary_part_packet(void *data, uint16_t datalen) {
    LPTF_Packet packet(BINARY_PART_PACKET, data, datalen);
    return packet;
}


string get_message_from_message_packet(LPTF_Packet &packet) {
    string message;

    if (packet.type() != MESSAGE_PACKET) throw runtime_error("Invalid packet (type or length)");

    message = string((const char *)packet.get_content(), packet.get_header().length);

    return message;
}


string get_arg_from_command_packet(LPTF_Packet &packet) {
    string arg;

    if (!is_command_packet(packet)) throw runtime_error("Invalid packet (type or length)");

    const char *content = (const char *)packet.get_content();

    int i = 0;
    while (i < packet.get_header().length) {
        if (content[i] == '\0') {
            arg = string(content, i);
            break;
        } else if (i == packet.get_header().length-1) {
            arg = string(content, i+1);
            break;
        }

        i++;
    }

    return arg;
}


uint8_t get_refered_packet_type_from_reply_packet(LPTF_Packet &packet) {
    uint8_t typefrom;

    if (packet.type() != REPLY_PACKET or packet.get_header().length < 1) throw runtime_error("Invalid packet (type or length)");

    typefrom = ((const uint8_t*)packet.get_content())[0];

    return typefrom;
}


string get_reply_content_from_reply_packet(LPTF_Packet &packet) {
    string message;

    if (packet.type() != REPLY_PACKET || packet.get_header().length < 2) throw runtime_error("Invalid packet (type or length)");

    message = string((const char *)packet.get_content()+1, packet.get_header().length-1);

    return message;
}


uint8_t get_refered_packet_type_from_error_packet(LPTF_Packet &packet) {
    uint8_t typefrom;

    if (packet.type() != ERROR_PACKET || packet.get_header().length < 1) throw runtime_error("Invalid packet (type or length)");

    typefrom = ((const uint8_t*)packet.get_content())[0];

    return typefrom;
}


uint8_t get_error_code_from_error_packet(LPTF_Packet &packet) {
    uint8_t code;

    if (packet.type() != ERROR_PACKET || packet.get_header().length < 2) throw runtime_error("Invalid packet (type or length)");

    code = ((const uint8_t*)packet.get_content())[1];

    return code;
}


string get_error_content_from_error_packet(LPTF_Packet &packet) {
    string message;

    if (packet.type() != ERROR_PACKET || packet.get_header().length < 2) throw runtime_error("Invalid packet (type or length)");

    message = string((const char *)packet.get_content()+1, packet.get_header().length-1);

    // Null term check
    if (message.at(packet.get_header().length-2) != '\0')
        message.append("\0");

    return message;
}


FILE_UPLOAD_REQ_PACKET_STRUCT get_data_from_file_upload_request_packet(LPTF_Packet &packet) {
    if (!is_command_packet(packet) || packet.get_header().length < 2) throw runtime_error("Invalid packet (type or length)");

    const char *content = (const char *)packet.get_content();

    string filepath;

    uint16_t i = 0;
    while (i < packet.get_header().length) {
        if (content[i] == '\0') {
            filepath = string(content, i);
            break;
        } else if (i >= packet.get_header().length-1 - sizeof(uint32_t)) {
            throw runtime_error("Invalid Packet structure ! (could not get filesize from file upload command)");
        }

        i++;
    }

    uint32_t filesize;
    memcpy(&filesize, content + i +1, sizeof(uint32_t));

    // cout << "filesize " << filesize << endl;

    filesize = ntohl(filesize);
    // cout << "filesize ntohl " << filesize << endl;

    return {filepath, filesize};
}


string get_file_from_file_download_request_packet(LPTF_Packet &packet) {
    if (packet.type() != DOWNLOAD_FILE_COMMAND) throw runtime_error("Invalid packet (type or length)");
    return get_arg_from_command_packet(packet);
}

string get_file_from_file_delete_request_packet(LPTF_Packet &packet) {
    if (packet.type() != DELETE_FILE_COMMAND) throw runtime_error("Invalid packet (type or length)");
    return get_arg_from_command_packet(packet);
}

string get_path_from_list_directory_request_packet(LPTF_Packet &packet) {
    if (packet.type() != LIST_FILES_COMMAND) throw runtime_error("Invalid packet (type or length)");
    return get_arg_from_command_packet(packet);
}

string get_path_from_create_directory_request_packet(LPTF_Packet &packet) {
    if (packet.type() != CREATE_FOLDER_COMMAND) throw runtime_error("Invalid packet (type or length)");
    return get_arg_from_command_packet(packet);
}

string get_path_from_remove_directory_request_packet(LPTF_Packet &packet) {
    if (packet.type() != DELETE_FOLDER_COMMAND) throw runtime_error("Invalid packet (type or length)");
    return get_arg_from_command_packet(packet);
}


RENAME_DIR_REQ_PACKET_STRUCT get_data_from_rename_directory_request_packet(LPTF_Packet &packet) {
    RENAME_DIR_REQ_PACKET_STRUCT result = {"", ""};

    if (packet.type() != RENAME_FOLDER_COMMAND) throw runtime_error("Invalid packet (type or length)");

    const char *content = (const char *)packet.get_content();

    // find new name and path args
    int i = 0;
    int arg_offset = 0;
    for (int n = 0; n < 2; n++) {
        while (i < packet.get_header().length) {
            if (content[i] == '\0') {
                if (n == 0)
                    result.newname = string(content, i);
                else
                    result.path = string(content+arg_offset, i - arg_offset);
                i++;
                arg_offset = i;
                break;
            } else if (i == packet.get_header().length-1) {
                if (n == 0)
                    result.newname = string(content, i+1);
                else
                    result.path = string(content+arg_offset, i+1 - arg_offset);
                i++;
                arg_offset = i;
                break;
            }

            i++;
        }
    }

    return result;
}


BINARY_PART_PACKET_STRUCT get_data_from_binary_part_packet(LPTF_Packet &packet) {
    if (packet.type() != BINARY_PART_PACKET) throw runtime_error("Invalid packet (type or length)");

    return {(const char *)packet.get_content(), packet.get_header().length};
}
