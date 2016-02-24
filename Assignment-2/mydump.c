#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int	packet_count = 0;

void
process_packet(	u_char 				*user,
		const struct pcap_pkthdr 	*h,
		const u_char 			*bytes) {
	packet_count++;
	printf("\n%d live packets captured", packet_count);
}

void 
offline_read(char	*filename,
		  char	*filter_string) {
    	struct pcap_pkthdr 	*header = NULL;
    	const u_char 		*packet = NULL;
	pcap_t 			*ret = NULL;
    	char 			errbuf[PCAP_ERRBUF_SIZE];
	int			result = 0;

	ret = pcap_open_offline(filename, errbuf);
	if (ret == NULL) {
		printf("Unable to open pcap file : %s\n", errbuf);
		return;
	}

	while(1) {
		result = pcap_next_ex(ret, &header, &packet);
		if (result == -2)
			break;

		packet_count++;	
	}
	printf("\n%d packets read ...", packet_count);
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
