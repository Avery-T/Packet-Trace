#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include "checksum.h" 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h> 

#define MAC_ADDR_SIZE 6 
#define ETHER_TYPE_SIZE 2
#define IP_ADDR_SIZE 4
#define PROTOCOL_INDENT_WIDTH 6 
#define INFO_INDENT_WIDTH 14 
#define ARP_BYTE_SKIP 7 

typedef struct ethernet_frame
{ 
  u_char  dest_mac_addr[6];  //mac addressses are 6 bytes
  u_char source_mac_addr[6]; 
  uint16_t type; //uint8 is 2 bytes makes the program simpular if i save it as a in
} ethernet_frame;

typedef struct arp_header
{ 
  uint16_t hardware_type; 
  uint16_t protocal_type;
  uint8_t  hardware_size; 
  uint8_t protocal_size;
	uint16_t opcode; 
	u_char sender_mac_addr[6];
  u_char sender_ip_addr[4]; 
 // struct in_addr sender_ip_addr; 
  //uint32_t sender_ip_addr; 
  u_char target_mac_addr[6];
  u_char target_ip_addr[4]; 
 // struct in_addr target_ip_addr; 
  //uint32_t target_ip_addr; 
} arp_header;

typedef struct ipv4_header
{
  uint8_t header_length : 4; 
  u_char TOS; 
  uint16_t total_length; 
  uint16_t identification; 
  uint8_t flag; 
  uint8_t fragment_offest; 
  uint8_t time_to_live; 
  uint8_t protocol; 
  uint16_t header_checksum; 
  uint32_t source_ip_address; 
  uint32_t dest_ip_address;
  u_char options[8];
}ipv4_header; 

typedef struct tcp_header
{
 uint16_t source_port; 
 uint16_t dest_port; 
 uint32_t seq_num; 
 uint32_t awk_num; 
 uint8_t header_length; 
 uint8_t flag; 
 uint16_t window; 
 uint16_t checksum; 
 uint16_t urgent_pointer;  
}tcp_header; 

typedef struct ip_sudo_header
{
    u_char source_ip_address[4]; 
    u_char dest_ip_address[4]; 
    uint8_t reserved; 
    uint8_t protocal; 
    uint16_t tcp_length; 
} ip_sudo_header;

 // for tcp checksum
typedef struct udp_header
{
 uint16_t source_port; 
 uint16_t dest_port; 
 uint16_t checksum; 
}udp_header; 

typedef struct icmp_header
{
 uint8_t type; 
}icmp_header; 

void print_ethernet_header(ethernet_frame ether_frame, uint32_t packet_num, uint32_t frame_len);
void processes_ether_type_headers(uint16_t type, const u_char * pkt_data, uint32_t data_size); 
void print_ip_addr(u_char * ip_addr);
void parse_arp_header(u_char * pkt_data);
void print_ip_header(u_char * pkt_data); 
void print_arp_header(u_char * pkt_data);
void print_tcp_header(u_char * pkt_data, ipv4_header *);
void print_udp_header(u_char * pkt_data);
void print_icmp_header(u_char * pkt_data);

int main(int argc, char * argv[])
{
  char  error_buffer[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr * pkt_header; 
  const u_char * pkt_data; 
  ethernet_frame ether_frame;  
  uint32_t packet_num = 0; 

  //only one command lin argument 
  if(argc !=2){ 
		perror("too many arguments"); 
	  exit(1);	
	} 

 //read pcpap file 
	pcap_t * pcap_file = pcap_open_offline(argv[1],error_buffer);
	if(pcap_file == NULL) { 
		perror("could not open file \n");
		exit(1); 
	}

 /* prints the ethernet header 
		finds the protocal of the packet 
		and then prints the protocals header by calling
    the correseponding funciton of each packet 
 */ 

  //reads each packet
 	 while(pcap_next_ex(pcap_file, &pkt_header, &pkt_data) == 1)
	 {
     packet_num++; 
		 if(pcap_datalink(pcap_file) != DLT_EN10MB){
				printf("cant read not a ethernet header");
     } 
		else
    {
      memcpy(ether_frame.dest_mac_addr,pkt_data, 6);
      memcpy(ether_frame.source_mac_addr,pkt_data + 6, 6);

      memcpy(&ether_frame.type,pkt_data + 12, 2);

			print_ethernet_header(ether_frame,packet_num,pkt_header->len); 
      //read the first 14 bytes so + 13 to the data and -14 to the legnth
      processes_ether_type_headers(ntohs(ether_frame.type) ,pkt_data + 13, pkt_header->len - 14 );
		} 
    
	}
	return 0;
}

void processes_ether_type_headers(uint16_t type, const  u_char * pkt_data, uint32_t data_size)
{

  switch(type)
	{
		case 0x806: 
			   print_arp_header(pkt_data); 
        break; 
    case 0x800: 
				print_ip_header(pkt_data); 
        break;
    default: 
				printf("Not Implemented"); 
  } 

  printf("\n"); 
}


void print_ethernet_header(ethernet_frame ether_frame, uint32_t packet_num, uint32_t frame_len)
{
  printf("\n");
  printf("Packet number: %d  Frame Len: %d\n\n", packet_num, frame_len); 
  printf("\tEthernet Header\n"); 
  printf("\t\tDest MAC: " );    
  char * mac_addr = ether_ntoa( (const struct ether_addr * ) ether_frame.dest_mac_addr); 
 	printf("%s", mac_addr); 
  printf("\n");
  printf("\t\tSource MAC: "); 
  mac_addr = ether_ntoa( (const struct ether_addr * ) ether_frame.source_mac_addr); 
	printf("%s", mac_addr); 
  printf("\n");
  printf("\t\tType: "); 
  switch (ntohs(ether_frame.type))
	{
		case 0x806: 
				printf("ARP"); 
        break; 

	  case 0x800: 
				printf("IP"); 
        break; 
    default: 
				printf("Not Implemented"); 
  } 
  printf("\n"); 
             
}

void print_arp_header(u_char * pkt_data)
{
   arp_header arp_head;
      memcpy(&arp_head, pkt_data+1, sizeof(arp_header)); 

  printf("\n\tARP header\n"); 
  printf("\t\tOpcode: ");

  switch (ntohs(arp_head.opcode))
	{
		case 0x1: 
				printf("Request\n"); 
        break; 
    case 0x2:
				printf("Reply\n"); 
				break; 
    default: 
				printf("Not Implemented\n"); 
  } 

  struct in_addr ip_addr_s; 
  char * ip_addr; 
  uint32_t ip = 0;
  char * mac_addr = ether_ntoa( (const struct ether_addr * ) arp_head.sender_mac_addr); 
  printf("\t\tSender MAC: %s\n",mac_addr);
   
 // memcpy(&ip, arp_head.sender_ip_addr,4); 
 // memcpy(ip_addr,(struct in_addr) inet_ntoa(ip),17);
                  
  printf("\t\tSender IP: "); 
//  ip = arp_head.sender_ip_addr;  
  memcpy(&ip_addr_s, &arp_head.sender_ip_addr,4); 
  ip_addr = inet_ntoa(ip_addr_s); 
  printf("%s",ip_addr); 
 // print_ip_addr(arp_head.sender_ip_addr); 
  printf("\n");
  mac_addr = ether_ntoa( (const struct ether_addr * ) arp_head.target_mac_addr);
  printf("\t\tTarget MAC: %s\n",mac_addr);

 //memcpy(ip_addr, inet_ntoa((struct in_addr)ip),17);
  printf("\t\tTarget IP: "); 
 // ip = arp_head.target_ip_addr;  
  memcpy(&ip_addr_s, &arp_head.target_ip_addr,4); 
  ip_addr = inet_ntoa(ip_addr_s); 
  printf("%s", ip_addr); 

 // print_ip_addr(arp_head.target_ip_addr); 
  printf("\n"); 
}

void print_ip_header(u_char * pkt_data)
{
    uint32_t ip; 
    char * ip_addr; 
   
     uint8_t tcp_flag=0, udp_flag=0,icmp_flag=0; 
      ipv4_header ip_header;
      memcpy(&ip_header, pkt_data + 1, sizeof(ipv4_header)); 
      pkt_data +=  1 + ip_header.header_length*4; //incremeintg hte data pointer to print out the next header

      printf("\n"); 
      printf("\tIP Header\n"); 
     printf("\t\tHeader Len: "); 
     printf("%u (bytes)\n", ip_header.header_length * 4); 
      printf("\t\tTOS: "); 
      printf("0x%x\n", ip_header.TOS); 
      printf("\t\tTTL: "); 
      printf("%d\n", ip_header.time_to_live);
      printf("\t\tIP PDU Len: "); 
      printf("%d (bytes)\n", ntohs(ip_header.total_length));
      printf("\t\tProtocol: "); 

switch (ip_header.protocol)
  {
  		case 0x06: 
				printf("TCP\n"); 
        tcp_flag = 1; 
       break; 
      case 0x11: 
				printf("UDP\n"); 
        udp_flag = 1; 
        break; 
      case 0x01:
				printf("ICMP\n");
				icmp_flag = 1; 
        break; 
      default: 
				printf("Unknown\n"); 
  } 

  printf("\t\tChecksum: "); 
  
   (in_cksum((unsigned short *)(&ip_header), ip_header.header_length * 4)) ? printf("Incorrect ") : printf("Correct "); 

  printf("(0x%x)\n", ip_header.header_checksum); 
  
printf("\t\tSender IP: ");
  ip = (ip_header.source_ip_address);  
  ip_addr = inet_ntoa(*(struct in_addr *)&ip); 
  printf("%s",ip_addr); 

 printf("\n"); 
printf("\t\tDest IP: "); 
 ip = (ip_header.dest_ip_address);  
  ip_addr = inet_ntoa(*(struct in_addr *)&ip); 
  printf("%s",ip_addr); 

printf("\n"); 

if(tcp_flag){
 	print_tcp_header(pkt_data, &ip_header); 
  return;
 } 
else if(udp_flag){ 
	print_udp_header( pkt_data); 
  return; 
}
else if(icmp_flag) 
	print_icmp_header(pkt_data);

}


void print_tcp_header(u_char * pkt_data, ipv4_header * ip_header)
{
    printf("\n"); 
    ip_sudo_header ip_sudo_head; 
    memcpy(&ip_sudo_head.source_ip_address, &ip_header->source_ip_address,4);
    memcpy(&ip_sudo_head.dest_ip_address, &ip_header->dest_ip_address,4); 
    ip_sudo_head.reserved = 0; 
    memcpy(&ip_sudo_head.protocal, &ip_header->protocol,1);  
    ip_sudo_head.tcp_length = htons( ntohs(ip_header->total_length) - (ip_header->header_length * 4));

      tcp_header tcp_head;
      memcpy(&tcp_head, pkt_data, sizeof(tcp_head)); 
     // *pkt_data = 1 + sizeof(ipv4_header); //incremeintg hte data pointer to print out the next header
      printf("\tTCP Header\n"); 

     printf("\t\tSource Port: "); 
     if(ntohs(tcp_head.source_port) == 80 ) 
     printf(" HTTP\n"); 
     else 

     printf(": %u\n",ntohs( tcp_head.source_port)); 
     printf("\t\tDest Port: "); 
     if(ntohs(tcp_head.dest_port) == 80 )
      printf(" HTTP\n"); 

     else{ 
      printf(": %u\n", ntohs(tcp_head.dest_port)); 
     }
      printf("\t\tSequence Number: "); 
      printf("%u\n", ntohl(tcp_head.seq_num));
      printf("\t\tACK Number: "); 
      //if theres no awk flag print not falid
      (tcp_head.flag & 16) ? (printf("%u\n", ntohl(tcp_head.awk_num))) : printf("<not valid>\n");
      printf("\t\tACK Flag: "); 
      (tcp_head.flag & 16 ) ? (printf("Yes\n")) : (printf("No\n")); 
      printf("\t\tSYN Flag: "); 
      (tcp_head.flag & 2) ? (printf("Yes\n")) : (printf("No\n")); 
      printf("\t\tRST Flag: "); 
      (tcp_head.flag & 4) ? (printf("Yes\n")) : (printf("No\n")); 
      printf("\t\tFIN Flag: "); 
      (tcp_head.flag & 1) ? (printf("Yes\n")) : (printf("No\n")); 
      printf("\t\tWindow Size: %u\n",ntohs(tcp_head.window)); 
      //check sum calculation 
      uint8_t * check_sum_header; 
      uint8_t * temp; 
      uint16_t len = sizeof(ip_sudo_head) + ntohs(ip_sudo_head.tcp_length); 
      check_sum_header =  malloc(len); 
      memcpy(check_sum_header, &ip_sudo_head, sizeof(ip_sudo_head)); 
      //temp = check_sum_header + sizeof(ip_sudo_head); 
      memcpy(check_sum_header + sizeof(ip_sudo_head) , pkt_data , ntohs(ip_sudo_head.tcp_length) ); 
      printf("\t\tChecksum: "); 
      __u_short x = in_cksum( ((unsigned short *) (check_sum_header)) ,len); 

     if(x) 
				printf("Incorrect "); 
     else if(x==0)
				printf("Correct ");
     printf("(0x%x)", ntohs(tcp_head.checksum)); 
     
    //  (in_cksum( ((unsigned short *) (&check_sum_header)) , len)) ? printf("Incorrect ") : printf("Correct "); 
      free(check_sum_header); 
  }


void print_udp_header(u_char * pkt_data)
{
     udp_header udp_head;
     memcpy(&udp_head, pkt_data , sizeof(udp_head)); 
     // *pkt_data = 1 + sizeof(ipv4_header); //incremeintg hte data pointer to print out the next header
     printf("\n");
     printf("\tUDP Header\n"); 
     printf("\t\tSource Port: : %u\n",ntohs(udp_head.source_port)); 
     printf("\t\tDest Port: : %u", ntohs(udp_head.dest_port)); 
}

void print_icmp_header(u_char * pkt_data)
{
     icmp_header icmp_head;
     memcpy(&icmp_head, pkt_data, sizeof(icmp_head)); 
     printf("\n"); 
     printf("\tICMP Header\n"); 
     printf("\t\tType: "); 

switch(icmp_head.type)
	{
		case 8: 
				printf("Request"); 
        break; 
    case 0: 
       	printf("Reply"); 
        break; 
    default: 
				printf("%u",icmp_head.type); 
  } 
}

