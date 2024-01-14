#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

#define MAC_ADDR_SIZE 6 
#define ETHER_TYPE_SIZE 2
#define PROTOCOL_INDENT_WIDTH 8 
#define INFO_INDENT_WIDTH 15 

typedef struct ethernet_frame
{ 
  u_char  dest_mac_addr[6];  //mac addressses are 6 bytes
  u_char source_mac_addr[6]; 
  uint16_t type; //uint8 is 2 bytes makes the program simpular if i save it as a in
} ethernet_frame;

void print_ethernet_header(ethernet_frame ether_frame, uint32_t packet_num, uint32_t frame_len);
void processes_ether_type_headers(uint16_t type, const u_char * pkt_data, uint32_t data_size); 

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
			//	parse_arp_header(pkt_data,data_size); 
			//	printf("ARP"); 
        break; 
    default: 
				printf("Not Implemented"); 
      
  } 
  printf("\n"); 
  



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


