#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

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
typedef struct ip_header{
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

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

typedef struct dns_header {
	uint16_t	id;
	uint16_t        flags;
	uint16_t        questions;
	uint16_t        answer;
	uint16_t        nscount;
	uint16_t        arcount;
} dns_header;

typedef struct dns_question {
	uint16_t	qtype;
	uint16_t	qclass;
} dns_question;

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

void
process_packet(	u_char 				*user,
		const struct pcap_pkthdr 	*header,
		const u_char 			*p) {
	u_char			*packet = (u_char *)p;
	struct ether_header 	*arp_hdr = (struct ether_header *)p;
	int			i = 0, j = 0;
	int			ip_header_len = 0;
	ip_address		*ip = NULL;
	ip_header		*p_hdr = NULL;
	udp_header		*udp = NULL;
	dns_header		*dns = NULL;
	char			*domain_name = NULL;
	dns_question		*quest = NULL;

	if (ntohs(arp_hdr->ether_type) != ETHERTYPE_IP) {
		return;
	}

	// IP packet 
	p_hdr = (ip_header *)(packet + 14);

        // UDP packet
        ip_header_len = (p_hdr->ver_ihl & 0xf)*4;

	if (p_hdr->proto != 17)
		return;

        packet_count++;
        printf("\n%dth packet: ", packet_count);
	
        printf("\nSource IP Address:");
        printf(" %d.%d.%d.%d ", p_hdr->saddr.byte1, p_hdr->saddr.byte2, p_hdr->saddr.byte3, p_hdr->saddr.byte4);
        printf("\tDestination IP Address:");
        printf(" %d.%d.%d.%d ", p_hdr->daddr.byte1, p_hdr->daddr.byte2, p_hdr->daddr.byte3, p_hdr->daddr.byte4);

	udp = (struct udp_header *)(packet + 14 + ip_header_len);
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

	domain_name = (char *)(packet + 14 + ip_header_len + 8 + 12);
	for (i = 0; i < ntohs(dns->questions); i++) {
		printf("\nQuestion domain length = %s\n", ++domain_name);
		domain_name = domain_name + strlen(domain_name) + 1;
		quest = (struct dns_question *)domain_name;
		printf("\nQuestion qtype = %d\n", ntohs(quest->qtype));
		printf("\nQuestion qclass = %d\n", ntohs(quest->qclass));
		domain_name = domain_name + sizeof(dns_question);
	}
	printf("\n=======================================================================\n");
}

void
sniff_packet(char        *interface,
             char  	 *filter_string,
   	     char	 *payload_string) {
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

	result = pcap_loop(live_device, 0, process_packet, payload_string);
	if (result < 0) {
		printf("\nEn-expected error occurred in live packet capture !!!\n");
	}		
}

int main(int argc, char **argv) {
	char 	errbuf[PCAP_ERRBUF_SIZE], option;
	int	count = 0;
	char	*interface = NULL;
	char	*attack_filename = NULL;
	char	*payload_string = NULL;
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
				printf("\nReading from pcap file: %s\n", attack_filename);
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

	sniff_packet(interface, bpf_filter, payload_string);

	return 0;
}
