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

/* Definitions of all packet structures */

/*void process_packet(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    //printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    ih = (ip_header *) (pkt_data +
        14); //length of ethernet header

    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        sport,
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4,
        dport);
}*/

void
process_packet(	u_char 				*user,
		const struct pcap_pkthdr 	*header,
		const u_char 			*p) {
	u_char			*packet = (u_char *)p;
	struct ether_header 	*arp_hdr= (struct ether_header *)p;
	u_char 			*addr_ptr = NULL;
	int			i = 0;
	char			*ptr = NULL;
	u_char			*pkt = NULL;
	char 			IP[INET_ADDRSTRLEN];
	int			ip_header_len = 0;
	ip_address		*ip = NULL;

        packet_count++;
        printf("\n%dth packet : ", packet_count);

	ptr = ctime(&header->ts.tv_sec);
	for (i = 0; ptr[i] != '\n'; i++) {
		printf("%c", ptr[i]);
	}

	if (ntohs(arp_hdr->ether_type) == ETHERTYPE_IP) {
		printf(" IP packet ");
	} else if (ntohs(arp_hdr->ether_type) == ETHERTYPE_ARP) {
		printf(" ARP packet ");
	} else {
		printf(" Non IP-ARP packet ");
	}

	addr_ptr = arp_hdr->ether_shost;
	i = ETHER_ADDR_LEN;
    	printf(" Source MAC Address: ");
    	do {
        	printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*addr_ptr++);
    	} while(--i>0);

        addr_ptr = arp_hdr->ether_dhost;
        i = ETHER_ADDR_LEN;
        printf(" Destination MAC Address: ");
        do {
                printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*addr_ptr++);
        } while(--i>0);

	// IP packet 
	pkt = packet + 14;
	inet_ntop(AF_INET, (struct in_addr *)(packet + 110), IP, INET_ADDRSTRLEN);
	printf(" Source IP Address: %s ", IP);
	ip = (ip_address *)(packet + 142);
	printf(" Second IP = %d.%d.%d.%d", ip->byte1, ip->byte2, ip->byte3, ip->byte4);

	ip_header_len = (pkt[0] & 0xf)*4;

	// TCP/UDP packet
	pkt = packet + ip_header_len;
	
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
