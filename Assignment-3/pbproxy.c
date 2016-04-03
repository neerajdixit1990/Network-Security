#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <ctype.h>
#include<fcntl.h>
#include "unp.h"

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

typedef struct service_ {
	int	new_fd;
}service;

int
destn_service_handler(int				new_fd,
              	      int       			destn_port,
              	      char      			*destn) {

	int			status, destn_soc_fd, no_bytes;
	struct sockaddr_in      server;
	char			buf[4097];

        destn_soc_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (destn_soc_fd < 0) {
                fprintf(stderr, "\nUnable to create socket for server !!!\n");
                return -1;
        }

        bzero(&server, sizeof(server));
        server.sin_family = AF_INET;
        inet_pton(AF_INET, destn, &server.sin_addr);
        server.sin_port = htons(destn_port);

        status = connect(destn_soc_fd, (struct sockaddr *)&server, sizeof(server));
        if (status != 0) {
                fprintf(stderr, "\nUnable to connect server on requested connection !!!\n");
                return -1;
        }

        /*int flags = fcntl(new_fd, F_GETFL);
        if (flags == -1) {
                printf("read sock 1 flag error!\n");
                printf("Closing connections and exit thread!\n");
        }
        fcntl(new_fd, F_SETFL, flags | O_NONBLOCK);
    
        flags = fcntl(destn_soc_fd, F_GETFL);
        if (flags == -1) {
                printf("read ssh_fd flag error!\n");
        }
        fcntl(destn_soc_fd, F_SETFL, flags | O_NONBLOCK);*/

        while(1) {
                fd_set          mon_fd;

                FD_ZERO(&mon_fd);
                FD_SET(destn_soc_fd, &mon_fd);
                FD_SET(new_fd, &mon_fd);

		if (new_fd > destn_soc_fd)
                	status = select(new_fd + 1, &mon_fd, NULL, NULL, NULL);
		else
			status = select(destn_soc_fd + 1, &mon_fd, NULL, NULL, NULL);
                if (status < 0) {
                        fprintf(stderr, "\nStatus = %d, Unable to monitor sockets !!! Exiting ...\n",status);
                        return 0;
                }

                if (FD_ISSET(new_fd, &mon_fd)) {
			/* packet from client, send to server using destn_soc_fd*/
			no_bytes = Read(new_fd, buf, sizeof(buf));
                        if (no_bytes > 0) {
                                fprintf(stderr, "\nFrom client: %s\n",buf);
                        } else if (no_bytes == 0) {
                                // Server termination will lead to a 0 read on this socket
                                fprintf(stderr, "\nConnection terminated by remote client !!!\n");
                                return -1;
                        } else {
                                fprintf(stderr, "\nCannot receive data on server socket !!!\n");
                                return -1;
                        }
	
                        Write(destn_soc_fd, buf, no_bytes);
                        /*if (no_bytes <= 0) {
                                fprintf(stderr, "\nCannot send data to server !!!");
                        } else if (no_bytes < strlen(buf)) {
                                fprintf(stderr, "\nPartial send occurred ...");
                        }*/
			fprintf(stderr, "\nSend to SSH server done with %d\n", no_bytes);
		}
		
		if (FD_ISSET(destn_soc_fd, &mon_fd)) {
			/* packet from proxy, send to client using new_fd*/
                        no_bytes = Read(destn_soc_fd, buf, sizeof(buf));
                        if (no_bytes > 0) {
                                fprintf(stderr, "\nFrom proxy: %s\n",buf);
                        } else if (no_bytes == 0) {
                                // Server termination will lead to a 0 read on this socket
                                fprintf(stderr, "\nConnection terminated by SSH server !!!\n");
                                return -1;
                        } else {
                                fprintf(stderr, "\nCannot receive data on proxy socket !!!\n");
                                return -1;
                        }

			//fprintf(stderr,"\nPreparing for send ....\n");
                        Write(new_fd, buf, no_bytes);
                        /*if (no_bytes <= 0) {
                                fprintf(stderr, "\nCannot send data to server !!!");
                        } else if (no_bytes < strlen(buf)) {
                                fprintf(stderr, "\nPartial send occurred ...");
                        }*/
			fprintf(stderr, "\nSend to client done with %d\n", no_bytes);
		}
	}
}

int	
client_connections(char		*destn,
		   int		destn_port,
		   int		*ret) {
	
	int 			soc_fd, status; 
	struct sockaddr_in 	client;

	soc_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (soc_fd < 0) {
		fprintf(stderr, "\nUnable to create socket for client !!!\n");
		return -1;
	}

    	bzero(&client, sizeof(client));
    	client.sin_family = AF_INET;
    	client.sin_port = htons(destn_port);
    	inet_pton(AF_INET, destn, &client.sin_addr);
	
	/* Socket connect, no need to bind */
	status = connect(soc_fd, (struct sockaddr *)&client, sizeof(client));
	if (status != 0) {
		fprintf(stderr, "\nUnable to connect client on requested connection !!!\n");
		return -1;
	}
	
	*ret = soc_fd;	
	return 0;	
}

int
client_launch(int	soc_fd) {
	int		status = -1, no_bytes = -1;
	char		buf[4097], *ret_ptr = NULL;

	while(1) {
		fd_set 		mon_fd;
		
		FD_ZERO(&mon_fd);
		FD_SET(soc_fd, &mon_fd);
		FD_SET(STDIN_FILENO, &mon_fd);
		
		/* Monitor keyboard input and socket input */
		status = select(soc_fd + 1, &mon_fd, NULL, NULL, NULL);
		if (status < 0) {
			fprintf(stderr, "\nStatus = %d, Unable to monitor sockets !!! Exiting ...\n",status);
			return 0;
		}
		
		if (FD_ISSET(STDIN_FILENO, &mon_fd)) {
			no_bytes = read(STDIN_FILENO, buf, sizeof(buf));
			
			no_bytes = write(soc_fd, buf, no_bytes);
			if (no_bytes <= 0) {
				fprintf(stderr, "\nCannot send data on client socket ...");
			} else if (no_bytes < strlen(buf)) {
				fprintf(stderr, "\nPartial send occurred ...");
			}
			fprintf(stderr, "\nSend to server done with %d\n", no_bytes);
		}

		if (FD_ISSET(soc_fd, &mon_fd)) {
			no_bytes = read(soc_fd, buf, sizeof(buf));
			if (no_bytes > 0) {
				no_bytes = write(STDOUT_FILENO, buf, no_bytes);
				//fprintf(stderr, "\nServer : %s\t = %d bytes\n", buf, no_bytes);
			} else if (no_bytes == 0) {
				/* Server termination will lead to a 0 read on this socket */
				fprintf(stderr, "\nConnection terminated by remote server !!!\n");
				return -1;
			} else {
				fprintf(stderr, "\nCannot receive data on client socket !!!\n");
				return -1;
			}   
		}
	}
	return 0;	
}

int
server_connections(char		*destn,
		   int		proxy_port,
		   int		*proxy_ret) {
        int                     status, proxy_soc_fd;
        struct sockaddr_in      server;

        proxy_soc_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (proxy_soc_fd < 0) {
                fprintf(stderr, "\nUnable to create socket for server !!!\n");
                return -1;
        }

    	bzero(&server, sizeof(server));
    	server.sin_family = AF_INET;
	inet_pton(AF_INET, destn, &server.sin_addr);
	server.sin_port = htons (proxy_port);

    	status = bind(proxy_soc_fd, (struct sockaddr *)&server, sizeof(server));
	if (status != 0) {
		fprintf(stderr, "\nStatus = %d, Unable to bind server socket !!!",status);
		return -1;
	}

	status = listen(proxy_soc_fd, 20);
	if (status != 0) {
		fprintf(stderr, "\nStatus = %d, Unable to listen on server socket !!!",status);
		return -1;
	}
	*proxy_ret = proxy_soc_fd;

	return 0;
}

int
server_launch(int	proxy_soc_fd,
	      int	destn_port,
	      char	*destn) {
        int     			status = -1, new_fd;
	struct sockaddr_storage		in_data;
	socklen_t			in_len;

        while(1) {
                fd_set          mon_fd;

                FD_ZERO(&mon_fd);
                FD_SET(proxy_soc_fd, &mon_fd);

		status = select(proxy_soc_fd + 1, &mon_fd, NULL, NULL, NULL);
                if (status < 0) {
                        fprintf(stderr, "\nStatus = %d, Unable to monitor sockets on server !!! Exiting ...\n",status);
                        return -1;
                }

                if (FD_ISSET(proxy_soc_fd, &mon_fd)) {
			in_len = sizeof(in_data);
           		new_fd = accept(proxy_soc_fd, (struct sockaddr *)&in_data, &in_len);
			if (new_fd < 0) {
				fprintf(stderr, "\nStatus = %d, Unable to accept connections !!! Exiting ...",new_fd);
				return -1;
			}

			status = destn_service_handler(new_fd, destn_port, destn);
			if (status != 0) {
				fprintf(stderr, "\nStatus = %d, Unable to service clients !!! Exiting ...",status);
				return -1;
			}
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
		fprintf(stderr, "\nPlease enter correct number of arguments !!!\n");
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
					fprintf(stderr, "\nDestination Port numbers must be between 0-65535\n");
					return 0;
				}
				proxy_port = (int)temp;
                        break;
                        case '?':
                                fprintf(stderr, "\nUn-supported option passed !!!\n");
                        break;
                        case ':':
                                fprintf(stderr, "\nArgument missing !!!\n");
                        break;
                }
                count++;
        }

        index = 2*count + 1;
	strncpy(destn, argv[index], strlen(argv[index]));
        temp = strtol(argv[++index], &ptr, 10);
        if (temp < 0 || temp > 65535) {
        	fprintf(stderr, "\nProxy Port numbers must be between 0-65535\n");
        	return 0;
        } 
	destn_port = (int)temp;
	fprintf(stderr, "\nKey File = %s, proxy port = %d, destn = %s, destn Port = %d\n", key_file, proxy_port, destn, destn_port);

	if (proxy_port == -1) {
		/* client mode */
		status = client_connections(destn, destn_port, &soc_fd);
		if (status != 0) {
			fprintf(stderr, "\nUnable to establish client connections !!!\n");
			return -1;
		}

		status = client_launch(soc_fd);
		if (status != 0) {
			fprintf(stderr, "\nClient unable to communicate with server !!!\n");
			return -1;
		}
	} else {
		/* server mode */
		status = server_connections(destn, proxy_port, &proxy_soc_fd);
                if (status != 0) {
                        fprintf(stderr, "\nUnable to establish client connections !!!\n");
                        return -1; 
                }   

                status = server_launch(proxy_soc_fd, destn_port, destn);
                if (status != 0) {
                        fprintf(stderr, "\nClient unable to communicate with client !!!\n");
                        return -1; 
                }   
	}

	return 0;
}
