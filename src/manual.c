/*
	TCP send_syn_packet port scanner code in C with Linux Sockets :)
*/

#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //for exit(0);
#include<sys/socket.h>
#include<errno.h> //For errno - the error number
#include<pthread.h>
#include<netdb.h>	//hostend
#include<arpa/inet.h>
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

void * receive_callback( void *ptr );
void process_ack_from_packet(unsigned char *, int,struct in_addr dest_ip);
struct in_addr setup_source_ip();
struct in_addr setup_destination_ip(char *targetip);
unsigned short csum(unsigned short * , int );
char * hostname_to_ip(char * );
int get_local_ip (char *);
void send_syn_packet();
int create_raw_tcp_socket();
static unsigned int parse_ports_list(char *port_list, int *formatted_port_list);
struct pseudo_header    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;	
	struct tcphdr tcp;
};

struct receive_callback_args {
    struct in_addr  dest_ip;
};


int main(int argc, char *argv[])
{
	//Create a raw socket
	int s = create_raw_tcp_socket();
	if(s < 0)
	{
		printf ("Error creating socket. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	else
	{
		printf("Socket created.\n");
	}
	
	// source ip to inet_adr_t , the buffer is used to get source ip in ipv4 format.
    struct in_addr source_ip = setup_source_ip();
	if (argc < 3)
    {
        printf("Please specify a hostname and port\n");
        exit(1);
    }
	char *detination_ip_from_input = argv[1];
	char *ports_incsv_from_input =   argv[2];
	
	if(strlen(ports_incsv_from_input) < 1){
		printf("No ports are specificed for host %s to be scanned\n",detination_ip_from_input);
        exit(1);
	}
	int ports_array[1024] = {0};
	unsigned int port_count = parse_ports_list(ports_incsv_from_input, ports_array);
    //struct in_addr 
	struct in_addr dest_ip = setup_destination_ip(detination_ip_from_input);

    printf("Starting sniffer thread...\n");	
	int  iret1;
	pthread_t sniffer_thread;
	struct receive_callback_args  receive_ack_args;
	receive_ack_args.dest_ip = dest_ip;
	if( pthread_create( &sniffer_thread , NULL ,  receive_callback , (void*) &receive_ack_args) < 0)
	{
		printf ("Could not create sniffer thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}

	printf("Starting to send syn packets\n");
	//80,22,9929,11211,31337
	int sourcePort = 43591;
	for (size_t i = 0; i < port_count; i++)
	{
		send_syn_packet(s,&source_ip , sourcePort,&dest_ip,ports_array[i]);
		//send_syn_packet(s,&source_ip , sourcePort,&dest_ip,9929);
		//send_syn_packet(s,&source_ip , sourcePort,&dest_ip,11211);
		//send_syn_packet(s,&source_ip , sourcePort,&dest_ip,31337);
	}

	pthread_join( sniffer_thread , NULL);
	printf("%d" , iret1);	
	return 0;
}
// Parse a comma-separated list of ports into an array of integers
static unsigned int parse_ports_list(char *port_list, int *formatted_port_list) {
    unsigned int count = 0;
    char *token = strtok(port_list, ",");
    
    while (token != NULL) {
        formatted_port_list[count++] = atoi(token);
        token = strtok(NULL, ",");
    }
    
    return count;
}
struct in_addr setup_destination_ip(char *target)
{
	struct in_addr l_dest_ip;
    if (inet_addr(target) != -1)
    {
        l_dest_ip.s_addr = inet_addr(target);
    }
    else
    {
        char *ip = hostname_to_ip(target);
        if (ip != NULL)
        {
            printf("%s resolved to %s \n", target, ip);
            // Convert domain name to IP
            l_dest_ip.s_addr = inet_addr(hostname_to_ip(target));
        }
        else
        {
            printf("Unable to resolve hostname : %s", target);
            exit(1);
        }
    }
	return l_dest_ip;
}
/// @brief This function get local ip address of the system and return its in_addr format suitable for raw protocol to be used in ipheader
struct in_addr setup_source_ip()
{
	struct in_addr source_ip;
    char source_ip_buffer[20];
    get_local_ip(source_ip_buffer);
    in_addr_t source_in_adr_t = inet_addr(source_ip_buffer);
    source_ip.s_addr = source_in_adr_t;
	return source_ip;
}

/// @brief Send syn request
/// @param s The socket file descriptor
void send_syn_packet(int s ,  const struct in_addr *source_ip , int source_port,  const struct in_addr *dest_ip , int dest_port)
{
	//Datagram to represent the packet
	char datagram[4096];	
	memset (datagram, 0, 4096);	/* zero out the buffer */

	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons (54321);	//Id of this packet
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = source_ip->s_addr;	//Spoof the source ip address
	iph->daddr = dest_ip->s_addr;
	
	iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
	
	//TCP Header
	tcph->source = htons ( source_port );
	tcph->dest = htons (dest_port);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons ( 14600 );	// maximum allowed window size
	tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
	tcph->urg_ptr = 0;

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}

	struct sockaddr_in  dest;
	struct pseudo_header psh; // needed for checksum calculation

	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip->s_addr;

		
	psh.source_address = source_ip->s_addr;
	psh.dest_address = dest.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons( sizeof(struct tcphdr) );
	
	memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
	
	tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

	//Send the packet
	if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
	{
		printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
}
/*
	Method to sniff incoming packets and look for Ack replies
*/
void * receive_callback( void *ptr )
{
	struct receive_callback_args *args = (struct receive_callback_args *)ptr;
	//Start the sniffer thing
	struct in_addr dest_ip = args->dest_ip;
	start_packet_sniffing(dest_ip);
}

/// @brief Create a new raw socket that receive 
/// @brief TCP packets that the operating system sees, regardless of whether they are intended for your application or not.
/// @brief Note:Requires superuser privileges or CAP_NET_RAW capability.
/// @return Socket file descriptor
int create_raw_tcp_socket() {
    // Create a raw socket
    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket creation failed");
        return -1;
    }
    return sock_raw;
}

int start_packet_sniffing(struct in_addr dest_ip){	
	int saddr_size , data_size;
	struct sockaddr saddr;
	
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
	
	printf("Sniffer initialising...\n");
	fflush(stdout);
	
	//Create a raw socket that shall sniff
	int sock_raw = create_raw_tcp_socket();
	
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		fflush(stdout);
		return 1;
	}
	
	saddr_size = sizeof saddr;
	int x = 0;

	while(x!=1000)
	{
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			fflush(stdout);
			return 1;
		}
		x++;
		
		//Now process the packet
		process_ack_from_packet(buffer , data_size , dest_ip);
	}
	
	close(sock_raw);
	printf("Sniffer finished.");
	fflush(stdout);
	return 0;
}

void process_ack_from_packet(unsigned char* buffer, int size , struct in_addr dest_ip) {
    // Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    unsigned short iphdrlen;

    if (iph->protocol == IPPROTO_TCP) {
        iphdrlen = iph->ihl * 4;

        struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen);
		if(iph->saddr == dest_ip.s_addr)
        if (tcph->syn && tcph->ack && iph->saddr == dest_ip.s_addr) {
            struct sockaddr_in source;

            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = iph->saddr;

            printf("Received SYN-ACK from %s:%d\n", inet_ntoa(source.sin_addr), ntohs(tcph->source));
            printf("Port %d open\n", ntohs(tcph->source));
        } else {
            struct sockaddr_in source;

            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = iph->saddr;

            printf("Received packet from %s:%d\n", inet_ntoa(source.sin_addr), ntohs(tcph->source));
            printf("Port %d closed\n", ntohs(tcph->source));
        }
    }
}
/*
 Checksums - IP and TCP
 */
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

/*
	Get ip from domain name
 */
char* hostname_to_ip(char * hostname)
{
	struct hostent *he;
	struct in_addr **addr_list;
	int i;
		
	if ( (he = gethostbyname( hostname ) ) == NULL) 
	{
		// get the host info
		herror("gethostbyname");
		return NULL;
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	
	for(i = 0; addr_list[i] != NULL; i++) 
	{
		//Return the first one;
		return inet_ntoa(*addr_list[i]) ;
	}
	
	return NULL;
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