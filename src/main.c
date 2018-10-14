#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "./wrappers/encrypt_utils.h"

unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; //Key
unsigned char *iv = (unsigned char*)"0123456789012345"; //IV

int Packetcapture(char *filter);
void callback(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int main(int argc, char **argv){
    //Packetcapture("");
    unsigned char *plaintext = (unsigned char *)"this is a test";
    unsigned char decryptedtext[66000];
    unsigned char ciphertext[66000];
    int decryptedlen, cipherlen;
    printf("Plaintext is: %s\n", plaintext);
    cipherlen = encryptMessage(plaintext, strlen((char*)plaintext), key,iv, ciphertext);
    printf("Ciphertext: %s\n",ciphertext);
    decryptedlen = decryptMessage(ciphertext, cipherlen, key, iv, decryptedtext);
    printf("Decrypted text is: %s \n", decryptedtext);

    return 0;
}

int Packetcapture(char *filter){
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

    if(pcap_compile(interfaceinfo, &fp, filter, 0, netp) == -1){
        perror("pcap_comile");
    }

    if(pcap_setfilter(interfaceinfo, &fp) == -1){
        perror("pcap_setfilter");
    }

    pcap_loop(interfaceinfo, -1, callback, NULL);
    return 0;
}

void callback(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    int i = 0;
    static int count = 0;

    printf("Packet Count: %d\n", ++count);
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Payload:\n");
    for(i=0; i < (pkthdr->len); i++){
            printf("%C \n", packet[i]);
    }
}
