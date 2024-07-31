#ifndef STRUCTS_H
#define STRUCTS_H

#include <stdint.h>

typedef struct {
    uint8_t     dst_mac[6];
    uint8_t     src_mac[6];
    uint16_t    type;
} eth_hdr;

typedef struct {
    uint8_t     len     : 4;
    uint8_t     version : 4;
    uint8_t     type_of_service;
    uint16_t    total_packet_len;
    uint16_t    fragment_identification;
    uint16_t    flags;
    uint8_t     ttl;
    uint8_t     protocol;
    uint16_t    checksum;
    uint8_t     src_ip[4];
    uint8_t     dst_ip[4];
} ipv4_hdr;

typedef struct {
    uint16_t    src_port;
    uint16_t    dst_port;
    uint32_t    seq_num;
    uint32_t    ack_num;
    uint8_t     len   : 4;
    uint16_t    flags : 12;
    uint16_t    window_size;
    uint16_t    checksum;
    uint16_t    urgent_ptr;
    uint8_t     data[20];
} tcp_hdr;

#endif // STRUCTS_H
