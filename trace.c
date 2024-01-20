#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include "checksum.h" 
#define MAC_ADDR_SIZE 6 
#define ETHER_TYPE_SIZE 2
#define IP_ADDR_SIZE 4
#define PROTOCOL_INDENT_WIDTH 8 
#define INFO_INDENT_WIDTH 15 
#define ARP_BYTE_SKIP 7 

typedef struct ethernet_frame
{ 
  u_char  dest_mac_addr[6];  //mac addressses are 6 bytes
  u_char source_mac_addr[6]; 
  uint16_t type; //uint8 is 2 bytes makes the program simpular if i save it as a in
} ethernet_frame;

typedef struct arp_header
{ 
	uint16_t opcode; 
	u_char sender_mac_addr[MAC_ADDR_SIZE];
  u_char sender_ip_addr[IP_ADDR_SIZE]; 
  u_char target_mac_addr[MAC_ADDR_SIZE];
  u_char target_ip_addr[IP_ADDR_SIZE]; 
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
  u_char source_ip_address[4]; 
  u_char dest_ip_address[4];
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
void print_mac_addr(u_char * mac_addr);
void parse_arp_header(u_char * pkt_data, uint32_t data_size);
void print_ip_header(u_char * pkt_data); 
void print_arp_header(arp_header arp_head);
void print_tcp_header(u_char * pkt_data, ip_sudo_header);
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
      ether_frame.type =  (((uint16_t) pkt_data[12]) << 8) | ((uint16_t) pkt_data[13]); //shifting by a byte and oring to convert into a number
			print_ethernet_header(ether_frame,packet_num,pkt_header->len); 
      //read the first 14 bytes so + 13 to the data and -14 to the legnth
      processes_ether_type_headers(ether_frame.type ,pkt_data + 13, pkt_header->len - 14 );
		} 
    
    printf("\n"); 
	}
	return 0;
}

void processes_ether_type_headers(uint16_t type, const  u_char * pkt_data, uint32_t data_size)
{

  switch(type)
	{
		case 0x806: 
			   parse_arp_header(pkt_data, data_size); 
        break; 
    case 0x800: 
				print_ip_header(pkt_data); 
    default: 
				printf("Not Implemented"); 
  } 

  printf("\n"); 
}
void parse_arp_header(u_char * pkt_data, uint32_t data_size)
{
     arp_header arp_head; 
		 pkt_data = pkt_data + ARP_BYTE_SKIP; 
     arp_head.opcode =  (((uint16_t) pkt_data[0]) << 8) | ((uint16_t) pkt_data[1]); //shifting by a byte and oring to convert into a number
    	pkt_data = pkt_data + 2; 
      memcpy(arp_head.sender_mac_addr,pkt_data, 6);
     	pkt_data = pkt_data + 6; 
      memcpy(arp_head.sender_ip_addr,pkt_data ,4);
      pkt_data += 4; 
      memcpy(arp_head.target_mac_addr,pkt_data, 6);
      pkt_data += 6; 
      memcpy(arp_head.target_ip_addr,pkt_data, 4);
			print_arp_header(arp_head); 

}

void print_ethernet_header(ethernet_frame ether_frame, uint32_t packet_num, uint32_t frame_len)
{
  printf("Packet number: %d Frame Len: %d\n\n", packet_num, frame_len); 
  printf("%*sEthernet Header\n",PROTOCOL_INDENT_WIDTH," "); 
  printf("%*sDest MAC: ",INFO_INDENT_WIDTH," " );    
  for(int i = 0; i<MAC_ADDR_SIZE; i++)	{ 
          if(i<MAC_ADDR_SIZE -1) 
							printf("%01x:", ether_frame.dest_mac_addr[i]); 
          else 
         		 printf("%01x", ether_frame.dest_mac_addr[i]); 
	}
  printf("\n");
  printf("%*sSOURCE MAC: ",INFO_INDENT_WIDTH," "); 

  for(int i = 0; i<MAC_ADDR_SIZE; i++)
	{ 		
					if(i<MAC_ADDR_SIZE -1) 
						printf("%01x:", ether_frame.source_mac_addr[i]); 
          else 
            printf("%01x", ether_frame.source_mac_addr[i]); 
	}

  printf("\n");
  printf("%*sTYPE: ",INFO_INDENT_WIDTH," "); 
  switch (ether_frame.type)
	{
		case 0x806: 
				printf("ARP"); 
        break; 
    default: 
				printf("Not Implemented"); 
  } 
  printf("\n"); 
             
}
void print_mac_addr(u_char * mac_addr)
{
   for(int i = 0; i<MAC_ADDR_SIZE; i++)	{ 
          if(i<MAC_ADDR_SIZE -1) 
							printf("%01x:", mac_addr[i]); 
          else 
         		 printf("%01x", mac_addr[i]); 
	}
  printf("\n");
}
void print_ip_addr(u_char * ip_addr) 
{
   for(int i = 0; i<IP_ADDR_SIZE; i++)	{ 
          if(i<IP_ADDR_SIZE -1) 
							printf("%d.", ip_addr[i]); 
          else 
         		 printf("%d", ip_addr[i]); 
	}
  printf("\n");

}
void print_arp_header(arp_header arp_head)
{
  printf("%*sARP Header\n",PROTOCOL_INDENT_WIDTH," "); 
//  switch (ether_frame.type)
//	{
//		case 0x806: 
//				printf("ARP"); 
//        break; 
//    default: 
//				printf("Not Implemented"); 
//  } 
   
  printf("%*sOPCODE: ",INFO_INDENT_WIDTH," " );
	printf("%x\n", arp_head.opcode);     
  printf("%*sSENDER MAC: ",INFO_INDENT_WIDTH," " );
  print_mac_addr(arp_head.sender_mac_addr);
  printf("%*sSENDER IP: ",INFO_INDENT_WIDTH," "); 
  print_ip_addr(arp_head.sender_mac_addr); 
  printf("%*sTARGET MAC: ",INFO_INDENT_WIDTH," " );
  print_mac_addr(arp_head.target_mac_addr);
  printf("%*sTARGET IP: ",INFO_INDENT_WIDTH," "); 
  print_ip_addr(arp_head.target_mac_addr); 
  printf("\n"); 
}

void print_ip_header(u_char * pkt_data)
{
     uint8_t tcp_flag=0, udp_flag=0,icmp_flag=0; 
      ipv4_header ip_header;
      memcpy(&ip_header, pkt_data+1, sizeof(ipv4_header)); 
      pkt_data +=  1 + sizeof(ipv4_header); //incremeintg hte data pointer to print out the next header
      printf("%*sIP Header\n",PROTOCOL_INDENT_WIDTH," "); 
     printf("%*sHeader Len: ",INFO_INDENT_WIDTH," "); 
     printf("%x (bytes)\n", ip_header.header_length); 


      printf("%*sTOS: ",INFO_INDENT_WIDTH," "); 
      printf("0x%x\n", ip_header.TOS); 
      printf("%*sTTL: ",INFO_INDENT_WIDTH," "); 
      printf("%d\n", ip_header.time_to_live);
      printf("%*sIP PDU Len: ",INFO_INDENT_WIDTH," "); 
      printf("%d (bytes)\n", ntohs(ip_header.total_length));
      printf("%*sPROTOCOL: ",INFO_INDENT_WIDTH," "); 

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
				printf("Not Implemented\n"); 
  } 

  printf("%*sCheckSum: ",INFO_INDENT_WIDTH," "); 
  
   (in_cksum((unsigned short *)(&ip_header),sizeof(ip_header))) ? printf("Incorrect ") : printf("Correct "); 

  printf("(0x%x)\n", ip_header.header_checksum); 
  
printf("%*sSender IP: ",INFO_INDENT_WIDTH," ");
      print_ip_addr(ip_header.source_ip_address);
printf("%*sDest IP: ",INFO_INDENT_WIDTH," "); 
 print_ip_addr(ip_header.dest_ip_address);

if(tcp_flag){
  //if tcp create the sudo header for tcp 
  ip_sudo_header ip_sudo_head; 
  memcpy(&(ip_sudo_head.source_ip_address), ip_header.source_ip_address,4);
  memcpy(&(ip_sudo_head.dest_ip_address), ip_header.dest_ip_address,4); 
 // ip_sudo_head.source_ip_address = ntohs(ip_sudo_head.source_ip_address); 
  //ip_sudo_head.dest_ip_address = ntohs(ip_sudo_head.dest_ip_address); 
  ip_sudo_head.reserved = 0; 
  ip_sudo_head.protocal = ip_header.protocol;  
  uint16_t t = (ntohs(ip_header.total_length) - sizeof(ipv4_header));
  ip_sudo_head.tcp_length = htons(t); 
  //ip_sudo_head.tcp_length = ip_header.total_length -sizeof(ip_header);
	print_tcp_header(pkt_data, ip_sudo_head); 
 } 
else if(udp_flag) 
	print_udp_header( pkt_data); 
else if(icmp_flag) 
	print_icmp_header(pkt_data);

}


void print_tcp_header(u_char * pkt_data, ip_sudo_header ip_sudo_head)
{
      tcp_header tcp_head;
      memcpy(&tcp_head, pkt_data, sizeof(tcp_head)); 
     // *pkt_data = 1 + sizeof(ipv4_header); //incremeintg hte data pointer to print out the next header
      printf("%*sTCP Header\n",PROTOCOL_INDENT_WIDTH," "); 

     printf("%*sSource Port: ",INFO_INDENT_WIDTH," "); 
     printf("%u (bytes)\n",ntohs( tcp_head.source_port)); 

     printf("%*sDest Port: ",INFO_INDENT_WIDTH," "); 
      printf("%u\n", ntohs(tcp_head.dest_port)); 

      printf("%*sSequence Number: ",INFO_INDENT_WIDTH," "); 
      printf("%d\n", ntohl(tcp_head.seq_num));
      printf("%*sACK NUMBER: ",INFO_INDENT_WIDTH," "); 
      printf("%u\n", ntohl(tcp_head.awk_num));
      printf("%*sACK Flag: ",INFO_INDENT_WIDTH," "); 
      (tcp_head.flag & 16 ) ? (printf("Yes\n")) : (printf("N)o\n")); 
      printf("%*sSYN Flag: ",INFO_INDENT_WIDTH," "); 
      (tcp_head.flag & 2) ? (printf("Yes\n")) : (printf("No\n")); 
      printf("%*sRST Flag: ",INFO_INDENT_WIDTH," "); 
      (tcp_head.flag & 4) ? (printf("Yes\n")) : (printf("No\n")); 
      printf("%*sFIN Flag: ",INFO_INDENT_WIDTH," "); 
      (tcp_head.flag & 1) ? (printf("Yes\n")) : (printf("No\n")); 
      printf("%*sWidow Size: %u\n",INFO_INDENT_WIDTH," ",ntohs(tcp_head.window)); 
      //check sum calculation 
      u_char * check_sum_header; 
      uint8_t * temp; 
      uint16_t len = sizeof(ip_sudo_head) + ntohs(ip_sudo_head.tcp_length); 
      printf("length %u", len);
      check_sum_header =  malloc(len); 
      memcpy(check_sum_header, &ip_sudo_head, sizeof(ip_sudo_head)); 
      //temp = check_sum_header + sizeof(ip_sudo_head); 
      memcpy(check_sum_header + sizeof(ip_sudo_head) , pkt_data , ntohs(ip_sudo_head.tcp_length) ); 
      printf("%*sChecksum: (0x) ",INFO_INDENT_WIDTH," "); 
      __u_short x = in_cksum( ((unsigned short *) (&check_sum_header)) ,len); 

     if(x) 
				printf("incorrect"); 
     if(x==0)
				printf("correct");
    //  (in_cksum( ((unsigned short *) (&check_sum_header)) , len)) ? printf("Incorrect ") : printf("Correct "); 
      free(check_sum_header); 
  }


void print_udp_header(u_char * pkt_data)
{
     udp_header udp_head;
     memcpy(&udp_head, pkt_data , sizeof(udp_head)); 
     // *pkt_data = 1 + sizeof(ipv4_header); //incremeintg hte data pointer to print out the next header
     printf("%*sUDP Header\n",PROTOCOL_INDENT_WIDTH," "); 
     printf("%*sSource Port: %u\n",INFO_INDENT_WIDTH," ", ntohs(udp_head.source_port)); 
     printf("%*sDest Port: %u\n",INFO_INDENT_WIDTH," ", ntohs(udp_head.dest_port)); 
}


void print_icmp_header(u_char * pkt_data)
{
     icmp_header icmp_head;
     memcpy(&icmp_head, pkt_data, sizeof(icmp_head)); 
     printf("%*sICMP Header\n",PROTOCOL_INDENT_WIDTH," "); 
     printf("%*sType: ",INFO_INDENT_WIDTH," "); 

switch(icmp_head.type)
	{
		case 8: 
				printf("Request\n"); 
        break; 
    case 0: 
       	printf("Reply\n"); 
        break; 
    default: 
				printf("Not Implemented\n"); 
  } 
}

