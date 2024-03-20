#ifndef SCANNER_H
#define SCANNER_H
#pragma once
#include <stdbool.h>
#include <stdio.h> // printf, puts
#include <string.h> // memset
#include <stdlib.h> // malloc, atoi
#include <unistd.h> // close syscall
#include <sys/socket.h> // socket APIs
#include <arpa/inet.h> // inet_ntoa
#include <netinet/tcp.h> // TCP header
#include <netinet/ip.h> // IP header
#include <pthread.h> // pthread_{create,join}
#include "sniffer.h"
#define DATAGRAM_BUF_SIZE 4096
//typedef enum {false, true} bool; // Implement bool type
// Needed for checksum computation
struct pseudo_header {
    unsigned int source_addr;
    unsigned int dest_addr;
    unsigned char plc;
    unsigned char prt;
    unsigned short tcp_len;
    struct tcphdr tcp;
};

struct target_header {
    struct in_addr target_ip;
    unsigned int target_port;
};

struct datagram_header {
    char datagram[DATAGRAM_BUF_SIZE];
    struct iphdr *ip_head;
    struct tcphdr *tcp_head;
};

void setup_datagram(char *datagram, struct in_addr server_ip, const char *client_ip, struct iphdr *ip_head,  struct tcphdr *tcp_head);
unsigned short scan_port(int sock_fd, char *datagram, struct in_addr server_ip, const char *client_ip, struct tcphdr *tcp_head, unsigned int target_port);
unsigned short compute_checksum(unsigned short *dgm, int bytes); 
int get_local_ip ( char * buffer);


#endif