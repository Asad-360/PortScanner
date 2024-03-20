

#include <stdbool.h>
#include <stdio.h> // printf, puts
#include <getopt.h> // getopt_long
#include <string.h> // memset
#include <stdlib.h> // malloc, atoi
#include <unistd.h> // close syscall
#include <ctype.h> // isdigit
#include <sys/socket.h> // socket APIs
#include <arpa/inet.h> // inet_ntoa
#include <netinet/tcp.h> // TCP header
#include <netinet/ip.h> // IP header
#include <netdb.h> // gethostbyname
#include <time.h> // for localtime



#include "scanner.h"
#define HELPER_MSG(name) printf("Try \"%s --help\" for more information.\n", name)
#define MAX_PORTBUF_SIZE 1024
#define BUF_SIZE 65536
#define DNS_SERVER "1.1.1.1"
#define DNS_SERVER_PORT 53
#define VERSION "0.0.1"
//typedef enum {false, true} bool; // Implement bool type
// Private methods
static unsigned int parse_ports_list(char *port_list, int *formatted_port_list);
//static const char *resolve_hostname(const char *address);
static void get_client_ip(char *ip_addr);

void helper() {
    puts("SPS is a SYN TCP port scanner for GNU/Linux systems\n"
         "-s, --hostname HOST           | Set hostname to scan\n"
         "-p, --ports <PORT1,PORT2,...> | Check if port is open\n"
         "-h, --help                    | Print this helper\n"
         "-a, --about                   | About this tool\n"
         "Example: ./sps -s scanme.nmap.org -p 22,80\n"
    );
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

// Resolve hostname to IP address
// static const char *resolve_hostname(const char *address) {
//     struct hostent *host_entry;
//     struct in_addr **addr_list;
//     char *ip_addr = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));

//     if ((host_entry = gethostbyname(address)) == NULL) {
//         return NULL;
//     }

//     addr_list = (struct in_addr **)host_entry->h_addr_list;
//     strcpy(ip_addr, inet_ntoa(*addr_list[0]));

//     return ip_addr;
// }

// Get the IP address of the client
static void get_client_ip(char *ip_addr) {
    char hostname[256];
    struct hostent *host_entry;
    struct in_addr **addr_list;

    gethostname(hostname, sizeof(hostname));
    host_entry = gethostbyname(hostname);
    addr_list = (struct in_addr **)host_entry->h_addr_list;

    strcpy(ip_addr, inet_ntoa(*addr_list[0]));
}
int main(int argc, char **argv) {
    printf("Hello\n");
    // Compute execution time
    double duration = 0.0;
    clock_t begin = clock();

    if(argc < 2) { // Check argument count
        HELPER_MSG(argv[0]);
        printf("Hello");
        return 1;
    }

    int sock_fd = 0; // Raw socket file descriptor
    struct in_addr server_ip;
    int ports[MAX_PORTBUF_SIZE] = {0}; // Port to be scanned
    unsigned int p_count = 0;
    const char *host; // Target host
    char ip_addr[MAX_PORTBUF_SIZE]; // Local IP address
    int opt = 0;
    const char *short_opts = "p:s:ha";
    bool is_hostopt_enable = false ,is_portopt_enable = false;
    struct option long_opts[] = {
        {"hostname", required_argument, NULL, 's'},
        {"ports", required_argument, NULL, 'p'},
        {"help", no_argument, NULL, 'h'},
        {"about", no_argument, NULL, 'a'},
        {NULL, 0, NULL, 0}
    };
    #pragma region New Variables
    //Datagram to represent the packet
	char datagram[4096];

    // Destination IP
    struct in_addr dest_ip;

    // Source Ip
	char source_ip[20];
    
    get_client_ip(source_ip);
    //IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));

    setup_datagram(datagram,dest_ip,source_ip,iph,tcph);
    #pragma endregion
    // parse command line parameters
    while((opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (opt) {
        case 's': {
                // Check if host is null
                if(optarg[0] == '\0') {
                    printf("Error: \"-s\" parameter requires exactly one value.\n");
                    return 1;
                }
                // Save host parameter
                host = optarg, is_hostopt_enable = true;
            }
            break;
        case 'p': {
                // Check if port list is empty
                if(optarg[0] == '\0') {
                    printf("Error: \"-p\" parameter requires at least one value.\n");
                    return 1;
                }
                // Parse port list
                p_count = parse_ports_list(optarg, ports);
                is_portopt_enable = true;
            }
            break;
        case 'a':
            #ifdef __STDC_VERSION__
                printf("SRS - a SYN TCP port scanner for GNU/Linux systems.\n\
            Developed by Asad 2021\n\
                STDC_VERSION: %ld\n", __STDC_VERSION__);
            #else
                puts("SRS - a SYN TCP port scanner for GNU/Linux systems.\n\
                    Developed by Asad 2021\n");
            #endif
            return 0;
        
        case 'h':
            helper();
            return 0;
            
        case ':':
        case '?':
        default:
            return 1;
        
          //  return 1;        
    }
    }
    }