#include <string.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdlib.h>
#include "_libnet.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* interface = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        struct libnet_ethernet_hdr* ethernet;
        struct libnet_tcp_hdr* tcp;
        struct libnet_ipv4_hdr* ip;
        const u_char* payload;

        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("\n%u bytes captured", header->caplen);
        
        ethernet = (struct libnet_ethernet_hdr*)packet;
        ip = (struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr));
        tcp = (struct libnet_tcp_hdr*)(packet+sizeof(struct libnet_ipv4_hdr)+sizeof(struct libnet_ethernet_hdr));
        payload = (const u_char*)(packet+sizeof(struct libnet_ipv4_hdr)+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_tcp_hdr));

        //Print Ethernet Destination MAC address
        printf("\nEthernet Destination : ");
        for(int i=0;i<ETHER_ADDR_LEN;i++){
            if(i!=0)printf(":");
            printf("%02x",ethernet->ether_dhost[i]);
        }

        //Print Ethernet Source MAC address
        printf("\nEthernet Source : ");
        for(int i=0;i<ETHER_ADDR_LEN;i++){
            if(i!=0)printf(":");
            printf("%02x",ethernet->ether_shost[i]);
        }

        //print IP Source Address
        u_int32_t num1 = ntohl(ip->ip_src.s_addr);
        printf("\nIp Source Address : ");
        printf("%d.%d.%d.%d",(num1&0xff000000)>>24,(num1&0x00ff0000)>>16,(num1&0x0000ff00)>> 8,(num1&0x000000ff));

        //print IP Destination Address
        u_int32_t num2 = ntohl(ip->ip_dst.s_addr);
        printf("\nIp Destination Address : ");
        printf("%d.%d.%d.%d",(num2&0xff000000)>>24,(num2&0x00ff0000)>>16,(num2&0x0000ff00)>> 8,(num2&0x000000ff));

        //print TCP Source port & Destination port
        printf("\nTCP Source port : %d",ntohs(tcp->th_sport));
        printf("\nTCP Destination port : %d",ntohs(tcp->th_dport));

        //print Payload
        printf("\nPayload(data) : ");
        for(int i=0; i<8;i++){
            printf("%02x ",payload[i]);
        }
        printf("\n");
    }

    pcap_close(pcap);

}

