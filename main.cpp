#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <pcap.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <libnet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if_arp.h>
using namespace std;
#define MAX_PATTERN 256
#define eth_type_ipv4 0x0800
#define ip_protocol_tcp 0x06
#define tcp_port_http 80
unsigned char my_mac_addr[6];
char* pattern;

struct tcp_packet{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_ipv4_hdr ip_hdr;
    struct libnet_tcp_hdr tcp_hdr;
    string http_data;
};

struct pshdr{
    in_addr sip;
    in_addr dip;
    u_char reserved;
    u_char protocol;
    u_short length;
};

struct tcp_chksum{
    struct pshdr pshdr;
    struct libnet_tcp_hdr tcp;
};

struct tcp_packet forward_pkt, backward_pkt;

void usage(){
    printf("syntax : tcp-block <interface> <pattern> \n");
    printf("sample : tcp-block wlan0 Host: test.gilgil.net \n");
    return;
}

int get_my_mac()
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        return 0;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        return 0;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else {
            /* handle error */
            return 0;
        }
    }

    if (success){
        memcpy(my_mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    }
    return success;
}

bool pattern_matching(const u_char* packet){
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr* )(packet);
    if(ntohs(eth_hdr->ether_type) != eth_type_ipv4){
        return false;
    }
    int eth_hdr_len = sizeof(struct libnet_ethernet_hdr);
    struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr* )(packet + eth_hdr_len);
    //protocol is 1 byte
    if(ipv4_hdr->ip_p != ip_protocol_tcp){
        return false;
    }
    int ip_hdr_len = ipv4_hdr->ip_hl * 4;
    struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr* )(packet + eth_hdr_len + ip_hdr_len);
    if(ntohs(tcp_hdr->th_dport) != tcp_port_http){
        return false;
    }
    int tcp_hdr_len = tcp_hdr->th_off * 4;

    char* http_data = (char*)(packet + eth_hdr_len + ip_hdr_len + tcp_hdr_len);
    char* search = strstr(http_data, pattern);

    if(search == NULL){
        return false;
    }

    return true;
}

void set_packet_without_set_chksum(struct tcp_packet* packet){
    //ethernet header set
    int i;
    for(i = 0; i < 6; i++){
        forward_pkt.eth_hdr.ether_shost[i] = my_mac_addr[i];
        backward_pkt.eth_hdr.ether_shost[i] = my_mac_addr[i];
    }
    for(i = 0; i < 6; i++){
        backward_pkt.eth_hdr.ether_dhost[i] = packet->eth_hdr.ether_shost[i];
    }

    //ipv4 header set
    forward_pkt.ip_hdr.ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
    char* block_msg = "blocked!";
    backward_pkt.ip_hdr.ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + sizeof(block_msg));

    backward_pkt.ip_hdr.ip_ttl = htons(128);

    backward_pkt.ip_hdr.ip_src = packet->ip_hdr.ip_dst;
    backward_pkt.ip_hdr.ip_dst = packet->ip_hdr.ip_src;

    //tcp header set
    backward_pkt.tcp_hdr.th_sport = packet->tcp_hdr.th_dport;
    backward_pkt.tcp_hdr.th_dport = packet->tcp_hdr.th_sport;

    int data_len = sizeof(packet->http_data);
    forward_pkt.tcp_hdr.th_seq = htonl(ntohl(packet->tcp_hdr.th_seq) + data_len);

    backward_pkt.tcp_hdr.th_seq = packet->tcp_hdr.th_ack;
    backward_pkt.tcp_hdr.th_ack = forward_pkt.tcp_hdr.th_seq;

    forward_pkt.tcp_hdr.th_flags = TH_RST + TH_ACK;
    backward_pkt.tcp_hdr.th_flags = TH_FIN + TH_ACK;

    forward_pkt.http_data.clear();
    backward_pkt.http_data.clear();
    backward_pkt.http_data = block_msg;

    return;
}

void set_ip_chksum(struct tcp_packet *packet){
    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
    uint32_t sum = 0;
    u_short sh[15];
    memcpy(sh, ip_hdr, sizeof(ip_hdr));
    int i;
    for(i = 0; i < sizeof(ip_hdr) / 2; i++){
        sum = sum + ntohs(sh[i]);
    }
    if(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;
    packet->ip_hdr.ip_sum = (u_short)sum;
    return;
}

u_short set_tcp_chksum(int size, u_short *buffer) {
    unsigned long cksum=0;
    while(size >1) {
        cksum+=*buffer++;
        size -=sizeof(u_short);
    }
    if (size)
        cksum += *(u_char*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (u_short)(~cksum);
}

int main(int argc, char* argv[]){
    if(argc != 3){
        usage();
        return -1;
    }
    char* dev = argv[1];
    pattern = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    int err_handle = get_my_mac();
    if(err_handle == 0){
        printf("my mac addr error! \n");
        return -1;
    }
    struct pcap_pkthdr* header;
    const u_char* packet;
    while(true){
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0){
            continue;
        }
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        bool check = pattern_matching(packet);
        if(check == false){
            continue;
        }
        printf("1\n");
        memcpy(&forward_pkt, packet, sizeof(packet));
        memcpy(&backward_pkt, packet, sizeof(packet));
        set_packet_without_set_chksum((struct tcp_packet*)packet);
        forward_pkt.ip_hdr.ip_sum = 0;
        backward_pkt.ip_hdr.ip_sum = 0;
        forward_pkt.tcp_hdr.th_sum = 0;
        backward_pkt.tcp_hdr.th_sum = 0;
        printf("2\n");

        set_ip_chksum(&forward_pkt);
        set_ip_chksum(&backward_pkt);

        tcp_chksum forward_chk;
        tcp_chksum backward_chk;
        printf("3\n");

        forward_chk.pshdr.sip = forward_pkt.ip_hdr.ip_src;
        forward_chk.pshdr.dip = forward_pkt.ip_hdr.ip_dst;
        forward_chk.pshdr.reserved = 0;
        forward_chk.pshdr.protocol = 6;
        forward_chk.pshdr.length = htons(20);
        memcpy(&forward_chk.tcp, &forward_pkt.tcp_hdr, 20);

        backward_chk.pshdr.sip = backward_pkt.ip_hdr.ip_src;
        backward_chk.pshdr.dip = backward_pkt.ip_hdr.ip_dst;
        backward_chk.pshdr.reserved = 0;
        backward_chk.pshdr.protocol = 6;
        backward_chk.pshdr.length = htons(29);
        memcpy(&backward_chk.tcp, &backward_pkt.tcp_hdr, 20);

        forward_pkt.tcp_hdr.th_sum = set_tcp_chksum(sizeof(forward_chk), (u_short*)&forward_chk);
        backward_pkt.tcp_hdr.th_sum = set_tcp_chksum(sizeof(backward_chk), (u_short*)&backward_chk);
        printf("4\n");
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&forward_pkt), sizeof(forward_pkt));
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&backward_pkt), sizeof(backward_pkt));
        printf("6\n");

    }
    return 0;
}
