#include "scanner.h"
/// @brief This function setup the datagram that represent the packet.
/// @param datagram  Array of chars
/// @param server_ip Destination ip address of type struct in_addr
/// @param client_ip Source IP of system , like 192.168.0.6 or 192.168.1.2
/// @param ip_head  IpHeader struct datagram
/// @param tcp_head TcpHeader struct datagram
void setup_datagram(char *datagram, struct in_addr server_ip, const char *client_ip, struct iphdr *ip_head,  struct tcphdr *tcp_head) {
    // CLear datagram buffer
    memset(datagram, 0, DATAGRAM_BUF_SIZE);

    // Setup IP header
    ip_head->ihl = 5; // HELEN
    ip_head->version = 4;
    ip_head->tos = 0; // Type of service
    ip_head->tot_len = (sizeof(struct ip) + sizeof(struct tcphdr));
    ip_head->id = htons(36521);
    ip_head->frag_off = htons(16384);
    ip_head->ttl = 64;
    ip_head->protocol = IPPROTO_TCP;
    ip_head->check = 0;
    ip_head->saddr = inet_addr(client_ip);
    ip_head->daddr = server_ip.s_addr;
    ip_head->check = compute_checksum((unsigned short*)datagram, ip_head->tot_len >> 1);

    // Setup TCP header
    tcp_head->source = htons(43591); // Source port
    tcp_head->dest = htons(80);
    tcp_head->seq = htonl(1105024978);
    tcp_head->ack_seq = 0;
    tcp_head->doff = (sizeof(struct tcphdr) / 4);
    tcp_head->fin = 0;
    tcp_head->syn = 1; // Set SYN flag
    tcp_head->rst = 0;
    tcp_head->psh = 0;
    tcp_head->ack = 0;
    tcp_head->urg = 0;
    tcp_head->window = htons(14600); // Maximum window size
    tcp_head->check = 0;
    tcp_head->urg_ptr = 0;
}

unsigned short scan_port(int sock_fd, char *datagram, struct in_addr server_ip, const char *client_ip, struct tcphdr *tcp_head, unsigned int target_port) {
    struct sockaddr_in ip_dest;
    struct pseudo_header psh;

    // Create new thread
    pthread_t sniff_th;
    struct target_header th;
    if(pthread_create(&sniff_th, NULL, sniffer_thread_callback, &th) < 0) {
        perror("Unable to create sniffer thread");
        return 1;
    }

    // Save target IP and port for later usage
    th.target_ip = server_ip;
    th.target_port = target_port;

    // Setup packet info
    ip_dest.sin_family = AF_INET;
    ip_dest.sin_addr.s_addr = server_ip.s_addr;

    // Setup TCP header
    tcp_head->dest = htons(target_port); // Set target port
    tcp_head->check = 0;

    // Configure pseudo header(needed for checksum)
    psh.source_addr = inet_addr(client_ip);
    psh.dest_addr = ip_dest.sin_addr.s_addr;
    psh.plc = 0;
    psh.prt = IPPROTO_TCP;
    psh.tcp_len = htons(sizeof(struct tcphdr));

    // Copy TCP header into our pseudo header
    memcpy(&psh.tcp, tcp_head, sizeof(struct tcphdr));
    tcp_head->check = compute_checksum((unsigned short*)&psh, sizeof(struct pseudo_header));

    // Send packet to target
    if(sendto(sock_fd, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&ip_dest, sizeof(ip_dest)) < 0) {
        perror("Unable to send SYN packet");
        return 1;
    }

    // Wait for sniffer thread to receive a response
    pthread_join(sniff_th, NULL);

    return 0;
}

// Compute checksum of IP header
// Refer to https://www.ietf.org/rfc/rfc793.txt for reference
unsigned short compute_checksum(unsigned short *dgm, int bytes) {
    register long sum = 0;
    register short answer;
    unsigned int odd_byte;

    while(bytes > 1) {
        sum += *dgm++;
        bytes -= 2;
    }

    if(bytes == 1) {
        odd_byte = 0;
        *((unsigned char*)&odd_byte) = *(unsigned char*)dgm;
        sum += odd_byte;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

/*
 Get source IP of system , like 192.168.0.6 or 192.168.1.2
 */

int get_local_ip ( char * buffer)
{
	int sock = socket ( AF_INET, SOCK_DGRAM, 0);

	const char* kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset( &serv, 0, sizeof(serv) );
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons( dns_port );

	int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*) &name, &namelen);

	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

	close(sock);
}