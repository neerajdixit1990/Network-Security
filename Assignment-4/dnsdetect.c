#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/ip_icmp.h>

int	packet_count = 0;

// structure definition at https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut6.html
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
typedef struct __attribute__((packed, aligned(1))) udp_header{
        uint16_t        sport;          // Source port
        uint16_t        dport;          // Destination port
        uint16_t        len;            // Datagram length
        uint16_t        crc;            // Checksum
}udp_header;

typedef struct __attribute__((packed, aligned(1))) dns_header {
        uint16_t        id;
        uint16_t        flags;
        uint16_t        questions;
        uint16_t        answer;
        uint16_t        nscount;
        uint16_t        arcount;
} dns_header;

typedef struct __attribute__((packed, aligned(1))) dns_question {
        uint16_t        qtype;
        uint16_t        qclass;
} dns_question;

typedef struct __attribute__((packed, aligned(1))) dns_response {
        uint16_t        name;
        uint16_t        type;
        uint16_t        class;
        uint32_t        ttl;
        uint16_t        len;
        uint32_t        ip;
} dns_response;

typedef struct dns_resp_info {
	uint16_t	id;
	uint32_t	ip[11];
	int		ip_count;	
} dns_resp_info;

dns_resp_info	resp_data[1001];
uint32_t	resp_count = 0;

int
check_dns_response(uint16_t	id,
		   u_char      	*packet,
		   int		dns_len) {

        u_char        	*ptr = NULL;
        int             status = -1;
	int		i, j, k;
	dns_header     	*dns = NULL;
	dns_response	*answer = NULL;
	char		spoofed_ip[INET_ADDRSTRLEN];
	char		domain_name[101];

	dns = (struct dns_header *)packet;
        for(i = 0; i < resp_count; i++) {
        	if (resp_data[i].id == id) {
			printf("\n=======================================================================");
			printf("\n@@@@@@@@ DNS Poisoning Attack @@@@@@@\n");

		        ptr = (u_char *)(packet + 12);
        		for (k = 0, j = 0; k < ntohs(dns->questions); k++) {
                		while(*ptr) {
                        		strncpy(domain_name + j, ptr + 1, *ptr);
                        		j = j + *ptr;
                        		domain_name[j++] = '.';
                        		ptr = ptr + *ptr + 1;
                		}
                		domain_name[j - 1] = '\0';
                		ptr = ptr + 1;
                		printf("\nDomain name = %s\n", domain_name);
                		ptr = ptr + 4;
        		}
			printf("Transaction ID = %d\n", id);
			printf("Answer 1: ");
			for (k = 0; k < resp_data[i].ip_count; k++) {
				inet_ntop(AF_INET, &(resp_data[i].ip[k]), spoofed_ip, INET_ADDRSTRLEN);
				printf("IP: %s ", spoofed_ip);
			}
	
			printf("\nAnswer 2 = ");
			for (k = 0; k < ntohs(dns->answer); k++) {
				answer = (struct dns_response *)ptr;
				if (ntohs(answer->type) == 1) {
					inet_ntop(AF_INET, &(answer->ip), spoofed_ip, INET_ADDRSTRLEN);
					printf("IP: %s\t",spoofed_ip);
				}
				ptr = ptr + 16 + (ntohs(answer->len) - 4);
			}
			printf("\n=======================================================================\n");
			return 1;
		}
	}

	resp_data[i].id = id;
	//answer = (struct dns_response *)(packet + dns_len - 16);
	//resp_data[i].ip = answer->ip;
        ptr = (u_char *)(packet + 12);
        for (k = 0; k < ntohs(dns->questions); k++) {
        	while(*ptr)
        		ptr = ptr + *ptr + 1;
        	ptr = ptr + 5;
        }
    
	resp_data[i].ip_count = 0; 
        for (k = 0; k < ntohs(dns->answer); k++) {
        	answer = (struct dns_response *)ptr;
        	if (ntohs(answer->type) == 1)
        		resp_data[i].ip[resp_data[i].ip_count++] = answer->ip;
        	ptr = ptr + 16 + (ntohs(answer->len) - 4);
        }

	resp_count++;
        return 0;
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
	if (ntohs(udp->sport) != 53)
		return;

	dns = (struct dns_header *)(packet + 14 + ip_header_len + 8);

	status = check_dns_response(dns->id, packet + 14 + ip_header_len + 8,
				    header->len - (14 + ip_header_len + 8));

}

void 
offline_read(char	*filename,
	     char	*filter_string,
	     char	*user_arg) {
	pcap_t 			*ret = NULL;
    	char 			errbuf[PCAP_ERRBUF_SIZE];
	int			result = 0;
	struct bpf_program      fp;

	ret = pcap_open_offline(filename, errbuf);
	if (ret == NULL) {
		printf("Unable to open pcap file: %s\n", errbuf);
		return;
	}

        if(filter_string != NULL) {

                result = pcap_compile(ret, &fp, filter_string, 0, PCAP_NETMASK_UNKNOWN);
                if (result == -1) {
                        printf("\nFailed to compile filter for device : %s\nThis syntax of BPF filter is not supported\n", pcap_geterr(ret));
                        return;
                }

                result = pcap_setfilter(ret, &fp);
                if (result == -1) {
                        printf("\nFailed to set device filter !!!\n");
                        return;
                }
        }

        result = pcap_loop(ret, 0, process_packet, user_arg);
        if (result < 0) {
                printf("\nEn-expected error occurred in live packet capture !!!\n");
        }

}

void
online_read(char        *interface,
            char  	*filter_string,
	    char	*user_arg) {
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

	result = pcap_loop(live_device, 0, process_packet, user_arg);
	if (result < 0) {
		printf("\nEn-expected error occurred in live packet capture !!!\n");
	}		
}

int main(int argc, char **argv) {
	char 	errbuf[PCAP_ERRBUF_SIZE], option;
	int	count = 0;
	char	*interface = NULL;
	char	*filename = NULL;
	char	bpf_filter[50] = {0};
	int	index = -1;	

	while ((option = getopt(argc, argv, "i:r:")) != -1) {
		switch(option) {
			case 'i':
				interface = optarg;
				printf("\nSniffing on interface: %s\n", interface);
			break;
			case 'r':
				filename = optarg;
				printf("\nReading from pcap file: %s\n", filename);
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
	
	if (interface != NULL && filename != NULL) {
		printf("\nEither interface name or filename should be given as input !!!\n");
		return 0;
	}

	if (filename != NULL) {
		/* Read from pcap file */
		offline_read(filename, bpf_filter, NULL);
	} else {
		if (interface == NULL) {
        		interface = pcap_lookupdev(errbuf);
        		if (interface == NULL) {
                		printf("\nCould not find default sniffing device !!!\n");
                		return 0;
        		}
        		printf("\nSniffing on default device: %s\n", interface);
		}
		online_read(interface, bpf_filter, NULL);
	}

	return 0;
}
