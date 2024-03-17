#include <stdio.h> // printf, puts, perror
#include <stdlib.h> // malloc
#include <string.h> // memset
#include <unistd.h> // close syscall
#include <netinet/tcp.h> // TCP header
#include <netinet/udp.h> // UDP header
#include <netinet/ip_icmp.h> // ICMP header
#include <netinet/ip.h> // IP header
#include <sys/socket.h> // Socket's APIs
#include <arpa/inet.h> // inet_ntoa
#include <signal.h> // signal

/* 
    * Simple TCP packet sniffer.
    * Inspired by https://www.binarytides.com/packet-sniffer-code-c-linux/
    * Compile it with gcc -Wall -Wextra -Werror sniffer.c -o sniffer
    */

#define BUF_SIZE 65536

static void decode_packet(unsigned char *buf, size_t length, FILE *lf);
static void print_content(unsigned char *buf, size_t length, FILE *lf);

void sigint_handler() {
    // Exit gracefully. This ensures that the kernel
    // will close the log file and will free other resources
    exit(0); 
}

int main(int argc, char **argv) {
    int raw_sock = 0, psize = 0; // Raw socket file descriptor and packet size
    unsigned char *buf = (unsigned char*)malloc(BUF_SIZE);

    if(argc != 2) {
        printf("Usage: %s <FILE>\n", argv[0]);
        return 1;
    }

    // Try to open log file
    FILE *log_file = fopen(argv[1], "w");
    if(log_file == NULL) {
        perror("Unable to open logfile");
        return 1;
    }

    // Create a raw socket(TCP socket only)
    raw_sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(raw_sock == -1) {
        perror("Unable to create raw socket");
        return 1;
    }

    // Ensure that a SIGINT will cause a gracefully exit.
    // Any other signal may not correctly free allocated resources
    // such as the logfile, buffer and the raw socket.
    signal(SIGINT, sigint_handler);

    puts("Starting...");

    // Continue retrieving packages
    for(;;) {
        psize = recvfrom(raw_sock, buf, BUF_SIZE, 0, NULL, NULL); // return the number of bytes read or -1 in case of error
        if(psize == -1) {
            perror("Unable to retrieve data from socket");
            return 1;
        }
        // Extract information from raw packages and print them
        decode_packet(buf, psize, log_file);
    }

    return 0;
}

// Decode function, used to print TCP/IP header and payload
void decode_packet(unsigned char *buf, size_t length, FILE *lf) {
    fprintf(lf, "\n\n################### TCP PACKET ###################");
    // Print IP header first
    struct iphdr *ip_head = (struct iphdr*)buf;
    struct sockaddr_in ip_source, ip_dest;
    unsigned short ip_head_len = ip_head->ihl*4;
    static int packet_count = 0;

    memset(&ip_source, 0, sizeof(ip_source));
    memset(&ip_dest, 0, sizeof(ip_dest));
    ip_source.sin_addr.s_addr = ip_head->saddr; // Get source IP address
    ip_dest.sin_addr.s_addr = ip_head->daddr; // Get destination IP address

    fprintf(lf, "\nIP header\n");
    fprintf(lf, "   Version              : %d\n", (unsigned int)ip_head->version);
    fprintf(lf, "   HELEN                : %d Bytes\n", ((unsigned int)(ip_head->ihl))*4);
    fprintf(lf, "   TOS                  : %d\n", (unsigned int)ip_head->tos);
    fprintf(lf, "   Total length         : %d Bytes\n", ntohs(ip_head->tot_len));
    fprintf(lf, "   Identification       : %d\n", ntohs(ip_head->id));
    fprintf(lf, "   Time-To-Live         : %d\n", (unsigned int)(ip_head->ttl));
    fprintf(lf, "   Protocol             : %d\n", (unsigned int)(ip_head->protocol));
    fprintf(lf, "   Checsum              : %d\n", (unsigned int)(ip_head->check));
    fprintf(lf, "   Source IP            : %s\n", inet_ntoa(ip_source.sin_addr));
    fprintf(lf, "   Destination IP       : %s\n", inet_ntoa(ip_dest.sin_addr));

    // Print TCP header
    struct tcphdr *tcp_head = (struct tcphdr*)(buf + ip_head_len);

    fprintf(lf, "\nTCP header\n");
    fprintf(lf, "   Source port          : %u\n", ntohs(tcp_head->source));
    fprintf(lf, "   Destination port     : %u\n", ntohs(tcp_head->dest));
    fprintf(lf, "   Sequence number      : %u\n", ntohl(tcp_head->seq));
    fprintf(lf, "   Ack number           : %u\n", ntohl(tcp_head->ack_seq));
    fprintf(lf, "   Header length        : %u Bytes\n", (unsigned int)tcp_head->doff*4);
    fprintf(lf, "   UFLAG                : %u\n", (unsigned int)tcp_head->urg);
    fprintf(lf, "   AFLAG                : %u\n", (unsigned int)tcp_head->ack);
    fprintf(lf, "   PFLAG                : %u\n", (unsigned int)tcp_head->psh);
    fprintf(lf, "   RFLAG                : %u\n", (unsigned int)tcp_head->rst);
    fprintf(lf, "   SFLAG                : %u\n", (unsigned int)tcp_head->syn);
    fprintf(lf, "   FFLAG                : %u\n", (unsigned int)tcp_head->fin);
    fprintf(lf, "   Window               : %u\n", htons(tcp_head->window));
    fprintf(lf, "   Checksum             : %u\n", htons(tcp_head->check));
    fprintf(lf, "   urgent Pointer       : %u\n", htons(tcp_head->urg_ptr));
    fprintf(lf, "\n\t\t\t ..::: DATA :::..\n");

    // Print IP header content
    fprintf(lf, "IP header DATA\n");
    print_content(buf, ip_head_len, lf);

    // Print TCP header content
    fprintf(lf, "TCP header DATA\n");
    print_content(buf+ip_head_len, tcp_head->doff*4, lf);

    // Print PAYLOAD content
    fprintf(lf, "Payload DATA\n");
    print_content(buf+ip_head_len+tcp_head->doff*4, (length - tcp_head->doff*4-ip_head->ihl*4), lf);

    // We print to stderr since it is not buffered
    fprintf(stderr, "Captured %d TCP packet(s)\r", ++packet_count);
}

void print_content(unsigned char *buf, size_t length, FILE *lf) {
    for(size_t i = 0; i < length; i++) {
        if(i != 0 && i % 16 == 0) {
            fprintf(lf, "          ");
            for(size_t j = (i-16); j < i; j++) {
                if(buf[j] >= 32 && buf[j] <= 128) { // print "printable" characters
                    fprintf(lf, "%c", (unsigned char)buf[j]);
                } else {
                    fprintf(lf, "."); // Otherwise, add a dot
                }
            }
            fprintf(lf, "\n");
        }

        if(i%16==0)
            fprintf(lf, "    ");
        fprintf(lf, " %02X", (unsigned int)buf[i]);

        if(i == (length-1)) {
            for(size_t j = 0; j < (15-1%16); j++)
                fprintf(lf, "    ");
            fprintf(lf, "          ");

            for(size_t j=(i-i%16); j <= 1; j++) {
                if(buf[j] >= 32 && buf[j] <= 128)
                    fprintf(lf, "%c", (unsigned char)buf[j]);
                else
                    fprintf(lf, ".");
            }
            fprintf(lf, "\n");
        }
    }
}