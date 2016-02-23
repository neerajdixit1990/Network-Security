#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <stdint.h>

void offline_read(char	*filename,
		  char	*filter_string) {
    	struct pcap_pkthdr 	*header = NULL;
    	const u_char 			*packet = NULL;
	pcap_t 			*ret = NULL;
    	char 			errbuf[PCAP_ERRBUF_SIZE];
	uint32_t		count = 0;
	int			result = 0;

	ret = pcap_open_offline(filename, errbuf);
	if (ret == NULL) {
		printf("Unable to open pcap file : %s", errbuf);
		return;
	}

	while(1) {
		result = pcap_next_ex(ret, &header, &packet);
		if (result == -2)
			break;

		count++;	
	}
	printf("\n%d packets read ...", count);
}

int main(int argc, char **argv) {
	char 	errbuf[PCAP_ERRBUF_SIZE], option;
	int	count = 0;
	char	*interface = NULL;
	char	*filename = NULL;
	char	*filter_string = NULL;
	

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
				filter_string = optarg;
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

	offline_read(filename, filter_string);	
	if (interface == NULL) {
        	interface = pcap_lookupdev(errbuf);
        	if (interface == NULL) {
                	printf("\nCould not find default device !!!");
                	return 0;
        	}
        	printf("\nDefault device is %s", interface);
	}

	return 0;
}
