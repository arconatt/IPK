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
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/udp.h>   
#include <netinet/tcp.h>   
#include <netinet/ip.h>    
#include <netdb.h>

/* Libraries for printing time: */
#include <sys/time.h>
#include <time.h>

using namespace std;

/* Error codes */
#define WRONG_ARG -1
#define ACT_DEV_ERROR 3
#define PACKET_ERR 4
#define PORT_ERR 5

/* Packet constant */
#define PACKET_LENGTH 65535
#define ETHERNET_HEADER_SIZE 14


/*****************************************/
/************ global variables ***********/
/*****************************************/
bool iflag = false;
bool pflag = false;
bool nflag = false;
bool tflag = false;
bool uflag = false;

bool found_device = false;

char *interface;
int number_of_packets;
int port;


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

/*****************************************/
/******** declaration of functions *******/
/*****************************************/
void checkArgs(int argc, char *argv[]);
void sniffing(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void print_interfaces();
void print_help();
void check_port(int port);


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

  //promiscuit mode == pcap_set_promisc(pcap_h,1)
  pcap_h = pcap_open_live(interface,BUFSIZ,1,1000,errbuf);

    if(pcap_h == NULL)
    {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(PACKET_ERR);
    }

   packet = pcap_next(pcap_h,&header);

  if(packet == NULL){
    cerr <<"Didn't grab packet\n";
    exit(PACKET_ERR);
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
  cerr << "ipk-sniffer is a packet sniffing program that writes data of packets depending on program arguments.\n";
	cerr << "Usage:\n";
  cerr << "./ipk-sniffer [-i name_of_interface | --interface name_of_interface] {-p ­­port} {[--tcp|-t] [--udp|-u]} {-n number_of_packets}\n";
  cerr << "Program arguments: \n ";
	cerr << "-i/ --interface : Defines interface, on which program listens for packets. \n      Without argument after -i/--interface, program writes all active ineterfaces. \n";
	cerr << "-p : Sets port for sniffing packets (filter). \n";
	cerr << "-t / --tcp : Filter that specifies, that only TCP packets will be printed on stdout. \n"; 
  cerr << "-u / --udp : Filter that specifies, that only UDP packets will be printed on stdout.\n";
	cerr << "-n : Sets number of packets to print (without this argument program prints only one packet). \n";
	cerr << "-h / -help : Prints this help acerr <<nd ends program with exit code 0.\n";
	cerr << "If none/both arguments of -t(tcp)/-u(udp) are present, it prints both packets as they come. \n";
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
* Sniffing function (print number of packet)
* */
void sniffing(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    //format: 2021-03-19T18:42:52.362+01:00 
    char timebuff[30];
    time_t* current_time = &header.ts.tv_sec;
    size_t time = strftime(timebuff, 30, " %FT%T%z" , localtime(current_time)); //TODO: fix time %z
    printf("%s%ld source > dest,length %d bytes\n", timebuff, time, header.len); 
    printf("\n");
}

/**
* Check sniffer arguments
* */
void checkArgs(int argc, char *argv[]){
  struct option long_options[] = {
      {"interface",   optional_argument,        0,    'i' },
      {"tcp",         no_argument,        0,    't' },
      {"udp",         no_argument,        0,    'u'},
      {"help",        no_argument,        0,      'h'},
      {NULL,             0,                  NULL,      0 }
  };

  int index = 0;
  int options;

  while((options = getopt_long(argc, argv, "i::p:n:tuh", long_options, &index)) != -1){
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
        port = atoi(optarg);
        check_port(port);
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