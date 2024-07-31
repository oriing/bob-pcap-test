#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "structs.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void printEhternet(eth_hdr *p) {
    uint8_t *src_mac = p->src_mac;
    uint8_t *dst_mac = p->dst_mac;

    printf("src mac  : %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("dst mac  : %02x:%02x:%02x:%02x:%02x:%02x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
}

void printIph(ipv4_hdr *p) {
    uint8_t *src_ip = p->src_ip;
    uint8_t *dst_ip = p->dst_ip;

    printf("src ip   : %u.%u.%u.%u\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
    printf("dst ip   : %u.%u.%u.%u\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
}

void printTcp(tcp_hdr *p) {
    printf("src port : %d\n", htons(p->src_port));
    printf("dst port : %d\n", htons(p->dst_port));
}

void printData(tcp_hdr *p, uint8_t len) {
    printf("payload  : ");
    for (uint8_t i = 0; i < len; ++i) {
        printf("%02x ", p->data[i]);
    }
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        eth_hdr*  eth_ptr  = (eth_hdr*)packet;
        if (eth_ptr->type != 8) continue;

        uint8_t   eth_len  = 14;
        ipv4_hdr* ipv4_ptr = (ipv4_hdr*) (packet + eth_len);
        if (ipv4_ptr->protocol != 6) continue;

        uint8_t   ipv4_len = ipv4_ptr->len * 4;
        tcp_hdr*  tcp_ptr  = (tcp_hdr*) (packet + eth_len + ipv4_len);
        uint8_t   tcp_len  = (tcp_ptr->flags) * 4;

        uint8_t   data_len = header->caplen - (eth_len + ipv4_len + tcp_len);

        printEhternet(eth_ptr);
        printIph     (ipv4_ptr);
        printTcp     (tcp_ptr);
        printData    (tcp_ptr, data_len>20?20:data_len);

        printf("\n\n--------------------\n\n");
    }

    pcap_close(pcap);

    return 0;
}
