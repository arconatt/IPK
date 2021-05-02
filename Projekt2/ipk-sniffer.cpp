/* Standard libraries: */
#include <stdio.h>
#include <stdlib.h> 
#include <stdbool.h>
#include <string>
#include <cstring>
#include <getopt.h>  
#include <iostream>

/* Libraries for working with packets: */
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <netinet/udp.h>   
#include <netinet/tcp.h>   
#include <netinet/ip_icmp.h>    
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Libraries for printing time: */
#include <sys/time.h>
#include <time.h>

using namespace std;

/*
* Sources
* http://yuba.stanford.edu/~casado/pcap/section4.html
* https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/?fbclid=IwAR0qY12qCUFkhUJEiXQ83rbDOEijX1PDT5jQPIeaLY-cS67P3JFqk9f9cmk
*
*/

/* Error codes */
#define WRONG_ARG -1
#define ACT_DEV_ERROR 3
#define PACKET_ERR 4
#define PORT_ERR 5
#define FILTER_ERR 6

/* Packet constant */
#define PACKET_LENGTH 65535
#define ETHERNET_HEADER_SIZE 14
#define PROTOCOL_POSITION 9

/*****************************************/
/************ global variables ***********/
/*****************************************/
bool iflag = false;
bool pflag = false;
bool nflag = false;
bool tflag = false;
bool uflag = false;
bool arpflag = false;
bool icmpflag = false;

bool found_device = false;

char *interface;
int number_of_packets;
char *port;
int port_number;


char *dev;
char *net;
char *mask;

char errbuf[PCAP_ERRBUF_SIZE]; //error buffer
pcap_t *pcap_h; //packet handler
struct in_addr addr;
pcap_if_t *interfaces; //active interfaces
struct pcap_pkthdr header;
struct ether_header *ethernet_header;  /* net/ethernet.h */

const u_char *packet; //packet
u_char *ptr; /* printing out hardware header info */

struct bpf_program port_filter; //port
bpf_u_int32 ip; //ip adress


/*****************************************/
/******** declaration of functions *******/
/*****************************************/
void checkArgs(int argc, char *argv[]);
void sniffing(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void print_interfaces();
void print_help();
void print_packet(const u_char * data , int header_size, int packet_size);
void print_packet_data(int counter, const u_char* data);
void ip_address_find(bool ip_type, const u_char *packet_data);
void check_port(int port);
void tcp_packet(const u_char* packet_data, unsigned int packet_size);
void udp_packet(const u_char* packet_data, unsigned int packet_size);
void icmp_packet(const u_char* packet_data, unsigned int packet_size);

/*****************************************/
/************* MAIN FUNCTION *************/
/*****************************************/
int main (int argc, char **argv)
{
  //checking arguments
  checkArgs(argc, argv);

  //find all devices
  if(pcap_findalldevs(&interfaces,errbuf)==-1){
      cerr << "No active devices found.\n";
      exit(ACT_DEV_ERROR);
    }

  //no options given, print interfaces
  if (argc < 2){
    print_interfaces();
    exit(EXIT_SUCCESS);
  }

  //check if wanted device is on the list of active devices on machine
  if (iflag == true && interface != NULL){
    pcap_if_t *tmp;
    tmp = interfaces;
    while (tmp->next != NULL){
        if (strcmp(tmp->name, interface) == 0){
          found_device = true;
        }
        tmp=tmp->next;
    }
    if (found_device == false){
      cerr << "Wanted device not found in list of active devices on this machine.\n";
      exit(ACT_DEV_ERROR);
    }
  }

  
  //argument -i without any parameters 
  if (iflag == true && interface == NULL){
    print_interfaces();
    exit(EXIT_SUCCESS);
  }

  //open for sniffing
  pcap_h = pcap_open_live(interface, 65536 , 1 , 0 , errbuf);
  pcap_set_timeout(pcap_h,100); //settimer
  if (pcap_h == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , interface , errbuf);
		exit(1);
	}
  
  //if -n given, write only number of packets 
  if (nflag == true){
    pcap_loop(pcap_h,number_of_packets,sniffing,NULL);
  }
  else{
    pcap_loop(pcap_h,1,sniffing,NULL);
  }

  return EXIT_SUCCESS;
}



/******** Functions *******/

void ip_address_find(bool ip_type, const u_char *packet_data){
  struct iphdr* iph = (struct iphdr*)(packet_data + sizeof(struct ethhdr));
	struct sockaddr_in ip_src;
	char source_ip[INET_ADDRSTRLEN];
	memset(&ip_src, 0, sizeof(ip_src));
	if (ip_type == true) // true = src
	{
		ip_src.sin_addr.s_addr = iph->saddr;
	}
	else
	{
		ip_src.sin_addr.s_addr = iph->daddr;
	}
	strcpy(source_ip, inet_ntoa(ip_src.sin_addr));

	struct sockaddr_in ip_source;

	ip_source.sin_family = AF_INET;
	inet_pton(AF_INET, source_ip, &ip_source.sin_addr);

	char domain_name[NI_MAXHOST];
	int result;
	result = getnameinfo((struct sockaddr*) & ip_source, sizeof(ip_source), domain_name, sizeof(domain_name), NULL, 0, 0);
	if (result) printf("%s", source_ip);
	else printf("%s",domain_name); 

}

/**
 * Check validity of given port
 * */
void check_port(int port){
  if (port < 1 || port > 65535)
	{
		cerr << "Wrong port number. Cannot filter program on this port.\n";
		exit(PORT_ERR);
	}
}

/**
 * Show help, usage and arguments
 * */
void print_help(){
  cout << "ipk-sniffer is a packet sniffing program that writes data of packets depending on program arguments.\n";
	cout << endl;
  cout << "*************    Usage:    ************* \n";
  cout << endl;
  cout << "./ipk-sniffer [-i name_of_interface | --interface name_of_interface] {-p ­­port} {[--tcp|-t] [--udp|-u]} {-n number_of_packets}\n";
  cout << endl;
  cout << "*************    Program arguments:    ************* \n ";
  cout << endl;
	cout << "-i/ --interface : Defines interface, on which program listens for packets. Without specified argument after, all active ineterfaces written. \n";
	cout << "-t / --tcp : Filter that specifies, that only TCP packets will be printed on stdout. \n"; 
  cout << "-u / --udp : Filter that specifies, that only UDP packets will be printed on stdout.\n";
  cout << "-h / -help : Prints this help and ends program with exit code 0.\n";
	cout << "-n : Sets number of packets to print (without this argument program prints only one packet). \n";
  cout << "-p : Sets port for sniffing packets (filter). \n";
	cout << "If none/both arguments of -t(tcp)/-u(udp) are present, it prints both packets as they come. \n";
	}

/**
 * Print all active interfaces on the device
 * */
void print_interfaces(){
  pcap_if *tmp;
  tmp = interfaces;
  cout << "Active devices: \n";
  while (tmp->next != NULL)
    {
      printf("%s\n", tmp->name);
      tmp=tmp->next;
    }
}

/**
* Sniffing function called in main loop (print packet data)
* 
* Source:
* https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/?fbclid=IwAR0qY12qCUFkhUJEiXQ83rbDOEijX1PDT5jQPIeaLY-cS67P3JFqk9f9cmk
* */
void sniffing(u_char *args, const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    unsigned int pkt_h_size = pkthdr->len;
    //IP header part, exclude ethernet header
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

    switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			icmp_packet( packet , pkt_h_size);
			break;
		case 6:  //TCP Protocol
			tcp_packet(packet , pkt_h_size);
			break;
		case 17: //UDP Protocol
			udp_packet(packet , pkt_h_size);
			break;
		default: //Other (arp.)
			break;
	}

}

void tcp_packet(const u_char * packet_data, unsigned int packet_size){
  struct iphdr* iph = (struct iphdr *)(packet_data + sizeof(struct ethhdr));
  unsigned int iph_size = iph->ihl * 4;

  struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + iph_size + sizeof(struct ethhdr));
  
  unsigned int header_size = ETHERNET_HEADER_SIZE + iph_size + tcp_header->doff * 4;
  
  ip_address_find(true, packet_data);
  printf(" : %u > ", ntohs(tcp_header->source));
  ip_address_find(false, packet_data);
  printf(" : %u \n", ntohs(tcp_header->dest));
	print_packet(packet_data, 0, header_size);
  print_packet(packet_data + header_size, header_size, packet_size - header_size);
}

void udp_packet(const u_char* packet_data, unsigned int packet_size){
  struct iphdr* iph = (struct iphdr*)(packet_data + sizeof(struct ethhdr));
	unsigned int iph_size = iph->ihl * 4;

	struct udphdr* udp_header = (struct udphdr*)(packet_data + iph_size + sizeof(struct ethhdr));

	unsigned int header_size = ETHERNET_HEADER_SIZE + iph_size + sizeof udp_header;
  ip_address_find(true, packet_data);
  printf(" : %u > ", ntohs(udp_header->source));
  ip_address_find(false, packet_data);
  printf(" : %u \n", ntohs(udp_header->dest));
	print_packet(packet_data, 0, header_size);
  print_packet(packet_data + header_size, header_size, packet_size - header_size);
}

void icmp_packet(const u_char* packet_data, unsigned int packet_size){
  struct iphdr* iph = (struct iphdr*)(packet_data + sizeof(struct ethhdr));
	unsigned int iph_size = iph->ihl * 4;

	struct icmphdr* icmp_header = (struct icmphdr*)(packet_data + iph_size + sizeof(struct ethhdr));

	unsigned int header_size = ETHERNET_HEADER_SIZE + iph_size + sizeof icmp_header;
  ip_address_find(true, packet_data);
  ip_address_find(false, packet_data);
	print_packet(packet_data, 0, header_size);
  print_packet(packet_data + header_size, header_size, packet_size - header_size);
}

/*
* Source:
* https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/?fbclid=IwAR0qY12qCUFkhUJEiXQ83rbDOEijX1PDT5jQPIeaLY-cS67P3JFqk9f9cmk
*/
void print_packet(const u_char * data , int header_size, int packet_size){
for (int i = 0; i < packet_size ; i++)
	{
		if (i == 0 )
		{
			printf("0x%04x: ", i+header_size); // size of bytes 
		}

		if (i % 8 == 0 && i != 0 && i % 16 != 0)
		{
			printf(" "); // space between 8bytes printed 
		}
		
    // printing one line is finished
		if (i != 0 && i % 16 == 0)  
		{
			for (int j = i - 16; j < i; j++)
			{
				print_packet_data(j, data); // ascii representation 
			}
			printf("\n"); 
			printf("0x%04x: ", i + header_size);
			
		}
		printf("%02x ", (unsigned int)data[i]); // hexa bytes representation
		if (i == packet_size - 1) // printing spaces to the end of line
		{
			for (int j = 0; j < 15 - i % 16; j++)
			{
				printf("   ");
			}
			for (int j = i - i % 16; j < i + 1; j++)
			{
				print_packet_data(j, data);
			}
		}
	}
	printf("\n \n");
}

/*
* Source:
* https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/?fbclid=IwAR0qY12qCUFkhUJEiXQ83rbDOEijX1PDT5jQPIeaLY-cS67P3JFqk9f9cmk
*/
void print_packet_data(int count, const u_char* packet_data)
{
	if (count % 8 == 0 && count != 0 && count % 16 != 0)
	{
		printf(" "); // spaces
	}
	if (packet_data[count] < 32 || packet_data[count] > 128) // printing normal characters
	{
		printf("."); //un-printable characters
	}
	else
	{
		printf("%c", (unsigned char)packet_data[count]);
	}
}

/**
* Check sniffer arguments 
* */
void checkArgs(int argc, char *argv[]){

  /*
  * https://linux.die.net/man/3/getopt_long
  * https://azrael.digipen.edu/~mmead/www/Courses/CS180/getopt.html
  */
  struct option long_options[] = {
      {"interface",   optional_argument,        0,    'i' },
      {"tcp",         no_argument,        0,    't' },
      {"udp",         no_argument,        0,    'u'},
      {"arp",         no_argument,        0,    0},
      {"icmp",         no_argument,        0,    0},
      {"help",        no_argument,        0,      'h'},
      {NULL,             0,                  NULL,      0 }
  };

  int index = 0;
  int options;

  while((options = getopt_long(argc, argv, "i::p:n:tuh", long_options, &index)) != -1){
    if (options == -1){
      break;
    }
    switch( options ) {
      case NULL: 
        break;
      case 'u': 
        uflag = true;
        break;
      case 't': 
        tflag = true;
        break;
      case 'p': 
        pflag = true;
        port = optarg;
        port_number = atoi(optarg);
        check_port(port_number);
        break;
      case 'n': 
        nflag = true;
        number_of_packets = atoi(optarg);
        break;
      case 'h': 
        print_help();
        exit(EXIT_SUCCESS);
      case 'i': 
        iflag = true;
        if (!optarg and argv[optind] != nullptr and argv[optind][0] != '-') {
              //save given interface
              interface = argv[optind++];
            }
        break;
      case '?':
        cerr << "Unknow argument.\n";
			  exit(WRONG_ARG);
      default:
        cerr << "Unknow argument.\n";
			  exit(WRONG_ARG);
    }
  }
}