#include "sniffers.h"
static void sniff_network(struct in_addr server_ip, const unsigned int port);
static void print_result(unsigned int port, enum status st);

void *sniffer_thread_callback(void *ptr) {
    struct target_header *th = ptr;

    sniff_network(th->target_ip, th->target_port);

    return (void*)NULL;
}

void sniff_network(struct in_addr server_ip, const unsigned int port) {
    int sock_raw;
    int saddr_size, data_size;
    struct sockaddr saddr;
    unsigned char *buf = (unsigned char*)malloc(BUF_SIZE);

    // Create new raw socket
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock_raw < 0) {
        perror("Unable to create socket");
        exit(1);
    }

    saddr_size = sizeof(saddr);

    // Start receiving packets
    data_size = recvfrom(sock_raw, buf, BUF_SIZE, 0, (struct sockaddr*)&saddr, (socklen_t*)&saddr_size);
    if(data_size < 0) {
        perror("Unable to receive packets");
        exit(1);
    }

    // Process data
    struct iphdr *ip_head = (struct iphdr*)buf;
    struct sockaddr_in source;
    unsigned short ip_head_len = ip_head->ihl*4;
    struct tcphdr *tcp_head = (struct tcphdr*)(buf + ip_head_len);
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_head->saddr;

    if(ip_head->protocol == IPPROTO_TCP) {
        // Now check whether it's a SYN-ACK packet or not
        if(tcp_head->syn == 1 && tcp_head->ack == 1 && source.sin_addr.s_addr == server_ip.s_addr)
            print_result(port, OPEN);
        else
            print_result(port, CLOSED);
    }
    free(buf);
}

// Print the scan result just like Nmap
void print_result(unsigned int port, enum status st) {
    printf("%d/tcp\t\t%s\n", port, (st == OPEN ? "open" : "closed"));
}
  