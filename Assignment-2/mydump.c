#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <arpa/inet.h>

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

// http://www.tcpdump.org/pcap.html
typedef struct tcp_header {
	u_short sport;	/* source port */
	u_short dport;	/* destination port */
	u_int	th_seq;		/* sequence number */
	u_int	th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
		#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
		#define TH_FIN 0x01
		#define TH_SYN 0x02
		#define TH_RST 0x04
		#define TH_PUSH 0x08
		#define TH_ACK 0x10
		#define TH_URG 0x20
		#define TH_ECE 0x40
		#define TH_CWR 0x80
		#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
}tcp_header;

void
process_packet(	u_char 				*user,
		const struct pcap_pkthdr 	*header,
		const u_char 			*p) {
	u_char			*packet = (u_char *)p;
	struct ether_header 	*arp_hdr= (struct ether_header *)p;
	u_char 			*addr_ptr = NULL;
	int			i = 0, j = 0, count = 0;
	char			*ptr = NULL;
	u_char			*pkt = NULL;
	int			ip_header_len = 0;
	ip_address		*ip = NULL;
	ip_header		*p_hdr = NULL;
	udp_header		*udp = NULL;
	tcp_header		*tcp = NULL;
	char			temp[20] = {0};

        packet_count++;
        printf("\n%dth packet : ", packet_count);

	ptr = ctime(&header->ts.tv_sec);
	for (i = 0; ptr[i] != '\n'; i++) {
		printf("%c", ptr[i]);
	}
	//printf("\t%s", ctime(&header->ts.tv_sec));

	if (ntohs(arp_hdr->ether_type) == ETHERTYPE_IP) {
		printf("\tIP packet\t");
	} else if (ntohs(arp_hdr->ether_type) == ETHERTYPE_ARP) {
		printf("\tARP packet\t");
	} else {
		printf("\tNon IP-ARP packet\t");
	}

	addr_ptr = arp_hdr->ether_shost;
	i = ETHER_ADDR_LEN;
    	printf("\nSource MAC Address: ");
    	do {
        	printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*addr_ptr++);
    	} while(--i>0);

        addr_ptr = arp_hdr->ether_dhost;
        i = ETHER_ADDR_LEN;
        printf("\tDestination MAC Address: ");
        do {
                printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*addr_ptr++);
        } while(--i>0);

	if (ntohs(arp_hdr->ether_type) == ETHERTYPE_ARP) {
		printf("\n=======================================================================\n");
        	return;
	}

	// IP packet 
	p_hdr = (ip_header *)(packet + 14);
	printf("\nSource IP Address:");
	printf(" %d.%d.%d.%d ", p_hdr->saddr.byte1, p_hdr->saddr.byte2, p_hdr->saddr.byte3, p_hdr->saddr.byte4);
        printf("\tDestination IP Address:");
        printf(" %d.%d.%d.%d ", p_hdr->daddr.byte1, p_hdr->daddr.byte2, p_hdr->daddr.byte3, p_hdr->daddr.byte4);

        // TCP/UDP packet
        ip_header_len = (p_hdr->ver_ihl & 0xf)*4;

	if(p_hdr->proto == 1) {
		printf(" ICMP packet ");
	} else if(p_hdr->proto == 6) {
		tcp = (struct tcp_header *)(packet + 14 + ip_header_len);
		printf("\nTCP packet ");
		printf("\tSource Port: %d ", tcp->sport);
		printf("\tDestn Port: %d", tcp->dport);
		printf("\tLength = %ld", strlen(packet + 14 + ip_header_len + TH_OFF(tcp)));
	} else if (p_hdr->proto == 17) {
		udp = (struct udp_header *)(packet + 14 + ip_header_len);
		printf("\nUDP packet ");
                printf("\tSource Port: %d ", ntohs(udp->sport));
                printf("\tDestn Port: %d", ntohs(udp->dport));
		//printf("\tLength = %ld", strlen(packet + 14 + ip_header_len + 8));
		printf("\tLength = %lu", (size_t)header->len-42);
		printf("\n=========");
		printf("\nPAYLOAD:");
		printf("\n=========\n");
		count = 0;
		for (i = 14 + ip_header_len + 8; packet[i] != '\0';) {
			temp[count++] = packet[i];
			printf(" %02x ", packet[i++]);
			if ((i - 14 - ip_header_len - 8)%15 == 0) {
				temp[count] = '\0';
				printf("\t%s", temp);
				printf("\n");
				count = 0;
			}
		}
		printf("\n");
	} else {
		printf("\nOther packet ");
	}	

	printf("\n=======================================================================\n");
	if (packet_count == 10)
		exit(1);
}

void 
offline_read(char	*filename,
	     char	*filter_string) {
	pcap_t 			*ret = NULL;
    	char 			errbuf[PCAP_ERRBUF_SIZE];
	int			result = 0;
	struct bpf_program      fp;

	ret = pcap_open_offline(filename, errbuf);
	if (ret == NULL) {
		printf("Unable to open pcap file : %s\n", errbuf);
		return;
	}

        if(filter_string != NULL) {

                result = pcap_compile(ret, &fp, filter_string, 0, PCAP_NETMASK_UNKNOWN);
                if (result == -1) {
                        printf("\nFailed to compile filter for device : %s\n", pcap_geterr(ret));
                        return;
                }

                result = pcap_setfilter(ret, &fp);
                if (result == -1) {
                        printf("\nFailed to set device filter !!!\n");
                        return;
                }
        }

        result = pcap_loop(ret, 0, process_packet, NULL);
        if (result < 0) {
                printf("\nEn-expected error occurred in live packet capture !!!");
        }

}

void
online_read(char        *interface,
            char  	*filter_string) {
	char 			errbuf[PCAP_ERRBUF_SIZE];
	int			result = 0;
	bpf_u_int32 		mask;		
	bpf_u_int32 		net;		
	pcap_t 			*live_device = NULL;
	struct bpf_program 	fp;	

        live_device = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf);
        if (live_device == NULL) {
        	printf("\nFailed to open device for live capture : %s\n", errbuf);
		return;
        }

	if(filter_string != NULL) {
		result = pcap_lookupnet(interface, &net, &mask, errbuf);	
		if (result == -1) {
			printf("\nFailed to get netmask of the device !!!\n");
			return;
		}

		result = pcap_compile(live_device, &fp, filter_string, 0, net);
                if (result == -1) {
                        printf("\nFailed to compile filter for device : %s\n", pcap_geterr(live_device));
                        return;
                }

		result = pcap_setfilter(live_device, &fp);
		if (result == -1) {
			printf("\nFailed to set device filter !!!\n");
			return;
		}
	}

	result = pcap_loop(live_device, 0, process_packet, NULL);
	if (result < 0) {
		printf("\nEn-expected error occurred in live packet capture !!!");
	}		
}

int main(int argc, char **argv) {
	char 	errbuf[PCAP_ERRBUF_SIZE], option;
	int	count = 0;
	char	*interface = NULL;
	char	*filename = NULL;
	char	filter_string[50] = {0};
	int	index = -1;	

	while ((option = getopt(argc, argv, "i:r:s:")) != -1) {
		switch(option) {
			case 'i':
				interface = optarg;
				printf("\ni present = %s", interface);
			break;
			case 'r':
				filename = optarg;
				printf("\nr present = %s", filename);
			break;
			case 's':
				index = optind-1;
				while(1) {
					if (argv[index] == NULL || strstr((const char *)argv[index], "-"))
						break;
					strcat(filter_string, (const char *)argv[index]);
					strcat(filter_string, " ");
					index++;	
				}
				printf("\ns present = %s", filter_string);
			break;
			case '?':
				printf("\nUn-supported option passed !!!");
			break;
			case ':':
				printf("\nArgument missing !!!");
			break;
		}
		count++;
	}
	
	if (interface != NULL && filename != NULL) {
		printf("\nEither interface name or filename should be given !!!");
		return 0;
	}

	if (filename != NULL) {
		/* Read from pcap file */
		offline_read(filename, filter_string);
	} else {
		if (interface == NULL) {
        		interface = pcap_lookupdev(errbuf);
        		if (interface == NULL) {
                		printf("\nCould not find default device !!!");
                		return 0;
        		}
        		printf("\nDefault device is %s", interface);
		}
		online_read(interface, filter_string);
	}

	return 0;
}
