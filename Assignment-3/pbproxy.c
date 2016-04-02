#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <ctype.h>

/* AES key for Encryption and Decryption */
const static unsigned char aes_key[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

/* Print Encrypted and Decrypted data packets */
void print_data(const char *tittle, const void* data, int len);

int aes_cbc( )
{
	/* Input data to encrypt */
	unsigned char aes_input[]={0x0,0x1,0x2,0x3,0x4,0x5};
	
	/* Init vector */
	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, 0x00, AES_BLOCK_SIZE);
	
	/* Buffers for Encryption and Decryption */
	unsigned char enc_out[sizeof(aes_input)];
	unsigned char dec_out[sizeof(aes_input)];
	
	/* AES-128 bit CBC Encryption */
	AES_KEY enc_key, dec_key;
	AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
	AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv, AES_ENCRYPT);
	/* AES-128 bit CBC Decryption */
	memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
	AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
	AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, iv, AES_DECRYPT);
	
	/* Printing and Verifying */
	print_data("\n Original ",aes_input, sizeof(aes_input)); // you can not print data as a string, because after Encryption its not ASCII
	
	print_data("\n Encrypted",enc_out, sizeof(enc_out));
	
	print_data("\n Decrypted",dec_out, sizeof(dec_out));
	
	return 0;
}

void print_data(const char *tittle, const void* data, int len)
{
	printf("%s : ",tittle);
	const unsigned char * p = (const unsigned char*)data;
	int i = 0;
	
	for (; i<len; ++i)
		printf("%02X ", *p++);
	
	printf("\n");
}

int	
client_connections(char		*destn,
		   int		destn_port,
		   int		*ret) {
	
	int 			soc_fd, status; 
	struct sockaddr_in 	client;

	soc_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (soc_fd < 0) {
		printf("\nUnable to create socket for client !!!\n");
		return -1;
	}

    	bzero(&client, sizeof(client));
    	client.sin_family = AF_INET;
    	client.sin_port = htons(destn_port);
    	inet_pton(AF_INET, destn, &client.sin_addr);
	
	/* Socket connect, no need to bind */
	status = connect(soc_fd, (struct sockaddr *)&client, sizeof(client));
	if (status != 0) {
		printf("\nUnable to connect client on requested connection !!!\n");
		return -1;
	}
	
	*ret = soc_fd;	
	return 0;	
}

int
client_launch(int	soc_fd) {
	int	status = -1;

	while(1) {
		fd_set 		mon_fd;
		
		FD_ZERO(&mon_fd);
		FD_SET(soc_fd, &mon_fd);
		FD_SET(fileno(stdin), &mon_fd);
		
		/* Monitor keyboard input and socket input */
		status = select(soc_fd + 1, &mon_fd, NULL, NULL, NULL);
		if (status < 0) {
			printf("\nStatus = %d, Unable to monitor sockets !!! Exiting ...\n",status);
			return 0;
		}
		
		if (FD_ISSET(fileno(stdin), &mon_fd)) {
			printf("\nSocket has data :)");
		} else if (FD_ISSET(soc_fd, &mon_fd)) {
			printf("\nstdin has data :)");
		} else {
			printf("\nAbnormal return by select() function ...");
		}
	}
	return 0;	
}

int
server_connections(char		*destn,
		   int		destn_port,
		   int		proxy_port,
		   int		*destn_ret,
		   int		*proxy_ret) {
        int                     destn_soc_fd, status, proxy_soc_fd;
        struct sockaddr_in      server;

        destn_soc_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (destn_soc_fd < 0) {
                printf("\nUnable to create socket for server !!!\n");
                return -1;
        }

    	bzero(&server, sizeof(server));
    	server.sin_family = AF_INET;
	inet_pton(AF_INET, destn, &server.sin_addr);
	server.sin_port = htons (destn_port);

    	status = bind(destn_soc_fd, (struct sockaddr *)&server, sizeof(server));
	if (status != 0) {
		printf("\nStatus = %d, Unable to bind server socket !!!",status);
		return -1;
	}

	status = listen(destn_soc_fd, 20);
	if (status != 0) {
		printf("\nStatus = %d, Unable to listen on server socket !!!",status);
		return -1;
	}
	*destn_ret = destn_soc_fd;


        proxy_soc_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (proxy_soc_fd < 0) {
                printf("\nUnable to create socket for server !!!\n");
                return -1;
        }

        bzero(&server, sizeof(server));
        server.sin_family = AF_INET;
	inet_pton(AF_INET, destn, &server.sin_addr);	
        server.sin_port = htons(proxy_port);

        status = bind(proxy_soc_fd, (struct sockaddr *)&server, sizeof(server));
        if (status != 0) {
                printf("\nStatus = %d, Unable to bind server socket !!!",status);
                return -1;
        }

        status = listen(proxy_soc_fd, 20);
        if (status != 0) {
                printf("\nStatus = %d, Unable to listen on server socket !!!",status);
                return -1;
        }
        *proxy_ret = proxy_soc_fd;

	return 0;
}

int
server_launch(int	destn_soc_fd,
	      int	proxy_soc_fd) {
        int     status = -1;

        while(1) {
                fd_set          mon_fd;

                FD_ZERO(&mon_fd);
                FD_SET(destn_soc_fd, &mon_fd);
                FD_SET(proxy_soc_fd, &mon_fd);

                if (destn_soc_fd > proxy_soc_fd)
			status = select(destn_soc_fd + 1, &mon_fd, NULL, NULL, NULL);
		else
			status = select(proxy_soc_fd + 1, &mon_fd, NULL, NULL, NULL);
                if (status < 0) {
                        printf("\nStatus = %d, Unable to monitor sockets on server !!! Exiting ...\n",status);
                        return 0;
                }

                if (FD_ISSET(destn_soc_fd, &mon_fd)) {
                        printf("\ndestination Socket has data :)");
                } else if (FD_ISSET(proxy_soc_fd, &mon_fd)) {
                        printf("\nproxy socket has data :)");
                } else {
                        printf("\nAbnormal return by select() function ...");
                }
        }
        return 0;

}

int main(int argc, char **argv) {
        int     	count = 0, soc_fd = -1;
	int		destn_soc_fd = -1, proxy_soc_fd = -1;
        char    	option;
        char    	*key_file = NULL;
        char    	destn[50] = {0}, *ptr = NULL;
        int     	index = -1, status;
	int		destn_port = -1, proxy_port = -1;
	long long int	temp = -1;

	if (argc < 4) {
		printf("\nPlease enter correct number of arguments !!!\n");
		return 0;
	}
	
        while ((option = getopt(argc, argv, "l:k:")) != -1) {
                switch(option) {
                        case 'k':
                                key_file = optarg;
                        break;
                        case 'l':
				temp = strtol(optarg, &ptr, 10);
				if (temp < 0 || temp > 65535) {
					printf("\nDestination Port numbers must be between 0-65535\n");
					return 0;
				}
				proxy_port = (int)temp;
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

        index = 2*count + 1;
	strncpy(destn, argv[index], strlen(argv[index]));
        temp = strtol(argv[++index], &ptr, 10);
        if (temp < 0 || temp > 65535) {
        	printf("\nProxy Port numbers must be between 0-65535\n");
        	return 0;
        } 
	destn_port = (int)temp;
	printf("\nKey File = %s, proxy port = %d, destn = %s, destn Port = %d\n", key_file, proxy_port, destn, destn_port);

	if (proxy_port == -1) {
		/* client mode */
		status = client_connections(destn, destn_port, &soc_fd);
		if (status != 0) {
			printf("\nUnable to establish client connections !!!\n");
			return -1;
		}

		status = client_launch(soc_fd);
		if (status != 0) {
			printf("\nClient unable to communicate with server !!!\n");
			return -1;
		}
	} else {
		/* server mode */
		status = server_connections(destn, destn_port, proxy_port, &destn_soc_fd, &proxy_soc_fd);
                if (status != 0) {
                        printf("\nUnable to establish client connections !!!\n");
                        return -1; 
                }   

                status = server_launch(destn_soc_fd, proxy_soc_fd);
                if (status != 0) {
                        printf("\nClient unable to communicate with server !!!\n");
                        return -1; 
                }   
	}

	return 0;
}
