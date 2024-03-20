#ifndef SNIFFER_H
#define SNIFFER_H
#pragma once
#include <stdio.h> // printf, puts
#include <string.h> // memset
#include <stdlib.h> // malloc, atoi
#include <unistd.h> // close syscall
#include <sys/socket.h> // socket APIs
#include <arpa/inet.h> // inet_ntoa
#include <netinet/tcp.h> // TCP header
#include <netinet/ip.h> // IP header
#include "scanner.h"
#define BUF_SIZE 65536
enum status {
    CLOSED,
    OPEN
};

void *sniffer_thread_callback(void *ptr);


#endif
        