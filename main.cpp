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
int org_data_len;
#pragma pack(push, 1)
struct forward_packet{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_ipv4_hdr ip_hdr;
    struct libnet_tcp_hdr tcp_hdr;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct backward_packet{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_ipv4_hdr ip_hdr;
    struct libnet_tcp_hdr tcp_hdr;
    char http_data[11] = "blocked!!!";
};
#pragma pack(pop)

#pragma pack(push, 1)
struct pshdr{
    in_addr sip;
    in_addr dip;
    u_char reserved;
    u_char protocol;
    u_short length;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct tcp_chksum{
    struct pshdr pshdr;
    struct libnet_tcp_hdr tcp;
};
#pragma pack(pop)

struct forward_packet forward_pkt;
struct backward_packet backward_pkt;

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
    org_data_len = ntohs(ipv4_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;

    char* http_data = (char*)(packet + eth_hdr_len + ip_hdr_len + tcp_hdr_len);
    char* search = strstr(http_data, pattern);

    if(search == NULL){
        return false;
    }

    return true;
}

void set_packet_without_set_chksum(libnet_ethernet_hdr* eth_hdr, libnet_ipv4_hdr* ip_hdr, libnet_tcp_hdr* tcp_hdr){
    //ethernet header set
    int i;
    for(i = 0; i < 6; i++){
        forward_pkt.eth_hdr.ether_shost[i] = my_mac_addr[i];
        backward_pkt.eth_hdr.ether_shost[i] = my_mac_addr[i];
    }
    for(i = 0; i < 6; i++){
        forward_pkt.eth_hdr.ether_dhost[i] = eth_hdr->ether_dhost[i];
        backward_pkt.eth_hdr.ether_dhost[i] = eth_hdr->ether_shost[i];
    }
    forward_pkt.eth_hdr.ether_type=htons(eth_type_ipv4);
    backward_pkt.eth_hdr.ether_type=htons(eth_type_ipv4);

    //ipv4 header set
    forward_pkt.ip_hdr.ip_hl = 5;
    backward_pkt.ip_hdr.ip_hl = 5;

    forward_pkt.ip_hdr.ip_v = 4;
    backward_pkt.ip_hdr.ip_v = 4;

    forward_pkt.ip_hdr.ip_tos = 0;
    backward_pkt.ip_hdr.ip_tos = 0;

    forward_pkt.ip_hdr.ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
    backward_pkt.ip_hdr.ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + 11);

    forward_pkt.ip_hdr.ip_id = 0;
    backward_pkt.ip_hdr.ip_id = 0;

    forward_pkt.ip_hdr.ip_off = 0;
    backward_pkt.ip_hdr.ip_off = 0;

    forward_pkt.ip_hdr.ip_ttl = ip_hdr->ip_ttl;
    backward_pkt.ip_hdr.ip_ttl = 128;

    forward_pkt.ip_hdr.ip_p = ip_protocol_tcp;
    backward_pkt.ip_hdr.ip_p = ip_protocol_tcp;

    forward_pkt.ip_hdr.ip_sum = 0;
    backward_pkt.ip_hdr.ip_sum = 0;

    forward_pkt.ip_hdr.ip_src = ip_hdr->ip_src;
    backward_pkt.ip_hdr.ip_src = ip_hdr->ip_dst;

    forward_pkt.ip_hdr.ip_dst = ip_hdr->ip_dst;
    backward_pkt.ip_hdr.ip_dst = ip_hdr->ip_src;

    //tcp header set
    forward_pkt.tcp_hdr.th_sport = tcp_hdr->th_sport;
    backward_pkt.tcp_hdr.th_sport = tcp_hdr->th_dport;

    forward_pkt.tcp_hdr.th_dport = tcp_hdr->th_dport;
    backward_pkt.tcp_hdr.th_dport = tcp_hdr->th_sport;

    forward_pkt.tcp_hdr.th_seq = htonl(ntohl(tcp_hdr->th_seq) + org_data_len);
    backward_pkt.tcp_hdr.th_seq = tcp_hdr->th_ack;

    forward_pkt.tcp_hdr.th_ack = tcp_hdr->th_ack;
    backward_pkt.tcp_hdr.th_ack = htonl(ntohl(tcp_hdr->th_seq) + org_data_len);

    forward_pkt.tcp_hdr.th_off = 5;
    backward_pkt.tcp_hdr.th_off = 5;

    forward_pkt.tcp_hdr.th_flags = TH_RST;
    backward_pkt.tcp_hdr.th_flags = TH_FIN + TH_ACK;

    forward_pkt.tcp_hdr.th_win = htons(0x8235);
    backward_pkt.tcp_hdr.th_win = htons(0x8235);

    forward_pkt.tcp_hdr.th_sum = 0;
    backward_pkt.tcp_hdr.th_sum = 0;

    forward_pkt.tcp_hdr.th_urp = 0;
    backward_pkt.tcp_hdr.th_urp = 0;

    return;
}

u_short get_ip_chksum(u_short len_ip_header, char* IPbuff) {
    u_short word16;
    u_int sum = 0;
    u_short i;

    for(i = 0; i < len_ip_header; i = i + 2) {
        word16 = ((IPbuff[i] << 8) & 0xFF00) + (IPbuff[i+1] & 0xFF);
        sum = sum + (u_int) word16;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    sum = ~sum;

    return ((u_short) sum);
}

u_short get_tcp_chksum(int size, u_short *buffer) {
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

void forward_send(forward_packet *mypacket, pcap_t *handle){
    uint8_t * send_packet = (uint8_t *)malloc(sizeof(struct forward_packet));

    int ip_hdr_offset = sizeof(mypacket->eth_hdr);
    int tcp_hdr_offset = ip_hdr_offset + sizeof(mypacket->ip_hdr);

    memcpy(&(send_packet[0]), &(mypacket->eth_hdr), sizeof(mypacket->eth_hdr));
    memcpy(&(send_packet[ip_hdr_offset]), &(mypacket->ip_hdr), sizeof(mypacket->ip_hdr));
    memcpy(&(send_packet[tcp_hdr_offset]), &(mypacket->tcp_hdr), sizeof(mypacket->tcp_hdr));

    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&send_packet[0]), sizeof(struct forward_packet));
}

void backward_send(backward_packet *mypacket, pcap_t *handle){
    uint8_t * send_packet = (uint8_t *)malloc(sizeof(struct backward_packet));

    int ip_hdr_offset = sizeof(mypacket->eth_hdr);
    int tcp_hdr_offset = ip_hdr_offset + sizeof(mypacket->ip_hdr);
    int tcp_data_offset = tcp_hdr_offset + sizeof(mypacket->tcp_hdr);

    memcpy(&(send_packet[0]), &(mypacket->eth_hdr), sizeof(mypacket->eth_hdr));
    memcpy(&(send_packet[ip_hdr_offset]), &(mypacket->ip_hdr), sizeof(mypacket->ip_hdr));
    memcpy(&(send_packet[tcp_hdr_offset]), &(mypacket->tcp_hdr), sizeof(mypacket->tcp_hdr));
    memcpy(&(send_packet[tcp_data_offset]), &(mypacket->http_data), 11);
    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&send_packet[0]), sizeof(struct backward_packet));
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
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)(packet);
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet+14);
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet+14+ip_hdr_len);
        set_packet_without_set_chksum(eth_hdr, ip_hdr, tcp_hdr);

        forward_pkt.ip_hdr.ip_sum = ntohs(get_ip_chksum(20, (char*)(&forward_pkt) + sizeof(struct libnet_ethernet_hdr)));
        backward_pkt.ip_hdr.ip_sum = ntohs(get_ip_chksum(20, (char*)(&backward_pkt) + sizeof(struct libnet_ethernet_hdr)));

        tcp_chksum forward_chk;
        tcp_chksum backward_chk;

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
        backward_chk.pshdr.length = htons(31);
        memcpy(&backward_chk.tcp, &backward_pkt.tcp_hdr, 20);

        forward_pkt.tcp_hdr.th_sum = get_tcp_chksum(sizeof(forward_chk), (u_short*)&forward_chk);
        backward_pkt.tcp_hdr.th_sum = get_tcp_chksum(sizeof(backward_chk), (u_short*)&backward_chk);

        forward_send(&forward_pkt,handle);
        backward_send(&backward_pkt,handle);
    }
    return 0;
}
