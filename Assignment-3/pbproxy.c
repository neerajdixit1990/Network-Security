#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "unp.h"

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>


typedef struct service_ {
	int	new_fd;
}service;

// http://stackoverflow.com/questions/20039066/aes-ctr128-encrypt-string-and-vice-versa-ansi-c
struct ctr_state { 
    unsigned char ivec[AES_BLOCK_SIZE];  
    unsigned int num; 
    unsigned char ecount[AES_BLOCK_SIZE]; 
};

int
init_ctr(struct ctr_state *state, const unsigned char *iv)
{        
    	state->num = 0;
    	memset(state->ecount, 0, 16);
    	memset(state->ivec, 0, 16);
 	memcpy(state->ivec, iv, 8);
}

int
encrypt_data(char		*input,
	     char		*output,
	     int		count,
	     AES_KEY		*session_key,
	     struct ctr_state	*state) {
	
	int	status = -1;

	status = RAND_bytes(output, 8);
	if (status != 1) {
		fprintf(stderr, "Unable to generate initial vector !!!\n");
		return -1;
	}

	status = init_ctr(state, output);

	AES_ctr128_encrypt(input, output + 8, count, session_key,
			   state->ivec, state->ecount, &(state->num));

	return 0;	
}


int
decrypt_data(char       	*input,
             char       	*output,
             int        	count,
             AES_KEY    	*session_key,
             struct ctr_state  	*state) {
        
        int     status = -1;

        status = init_ctr(state, input);

        AES_ctr128_encrypt(input + 8, output, count - 8, session_key,
                           state->ivec, state->ecount, &(state->num));     

        return 0;
}


int
destn_service_handler(int				new_fd,
              	      int       			destn_port,
              	      char      			*destn,
		      char				*key) {

	int			status, destn_soc_fd;
	int			send_bytes, recv_bytes;
	struct sockaddr_in      server;
	char			plain[5000], cipher[5000];
	struct ctr_state	server_state;
        AES_KEY                 session_key;

        status = AES_set_encrypt_key(key, 128, &session_key);
        if (status != 0) {
                fprintf(stderr, "\nUnable to set session key in client !!!\n");
                return -1;
        }

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
			recv_bytes = read(new_fd, cipher, sizeof(cipher));
                        if (recv_bytes == 0) {
                                // Server termination will lead to a 0 read on this socket
                                fprintf(stderr, "\nConnection terminated by remote client !!!\n");
                                return -1;
                        } else if (recv_bytes < 0) {
                                fprintf(stderr, "\nCannot receive data on server socket !!!\n");
                                return -1;
                        }

			status = decrypt_data(cipher, plain, recv_bytes, &session_key, &server_state);
			if (status != 0) {
				fprintf(stderr, "\nUnable to decrypt data at server !!!\n");
				return -1;
			}
	
                        send_bytes = write(destn_soc_fd, plain, recv_bytes - 8);
                        if (send_bytes <= 0) {
                                fprintf(stderr, "\nCannot send data to server !!!");
                        } else if (send_bytes < (recv_bytes - 8)) {
                                fprintf(stderr, "\nPartial send occurred ...");
                        }
			//fprintf(stderr, "\nSend to SSH server done with %d\n", no_bytes - 8);
		}
		
		if (FD_ISSET(destn_soc_fd, &mon_fd)) {
			/* packet from proxy, send to client using new_fd*/
                        recv_bytes = read(destn_soc_fd, plain, sizeof(plain));
                        if (recv_bytes == 0) {
                                // Server termination will lead to a 0 read on this socket
                                fprintf(stderr, "\nConnection terminated by SSH server !!!\n");
                                return -1;
                        } else if (recv_bytes < 0) {
                                fprintf(stderr, "\nCannot receive data on proxy socket !!!\n");
                                return -1;
                        }

			status = encrypt_data(plain, cipher, recv_bytes, &session_key, &server_state);
                        if (status != 0) {
                                fprintf(stderr, "\nUnable to encrypt data at server !!!\n");
                                return -1;
                        }

			//fprintf(stderr,"\nPreparing for send ....\n");
                        send_bytes = write(new_fd, cipher, recv_bytes + 8);
                        if (send_bytes <= 0) {
                                fprintf(stderr, "\nCannot send data to server !!!");
                        } else if (send_bytes < (recv_bytes + 8)) {
                                fprintf(stderr, "\nPartial send occurred ...");
                        }
			//fprintf(stderr, "\nSend to client done with %d\n", no_bytes);
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
client_launch(int	soc_fd,
 	      char	*key) {
	int			status = -1;
	int			send_bytes, recv_bytes;
	char			plain[5000], cipher[5000];
	struct ctr_state        client_state;
       	AES_KEY 		session_key;

	status = AES_set_encrypt_key(key, 128, &session_key);
	if (status != 0) {
		fprintf(stderr, "\nUnable to set session key in client !!!\n");
		return -1;
	}

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
			recv_bytes = read(STDIN_FILENO, plain, sizeof(plain));
		
			status = encrypt_data(plain, cipher, recv_bytes, &session_key, &client_state);
			if (status != 0) {
				fprintf(stderr, "\nUnable to encrypt data at client !!!\n");
				return -1;
			}
	
			send_bytes = write(soc_fd, cipher, recv_bytes + 8);
			if (send_bytes <= 0) {
				fprintf(stderr, "\nCannot send data on client socket ...");
			} else if (send_bytes < (recv_bytes + 8)) {
				fprintf(stderr, "\nPartial send occurred ...");
			}
			//fprintf(stderr, "\nSend to server done with %d\n", no_bytes);
		}

		if (FD_ISSET(soc_fd, &mon_fd)) {
			recv_bytes = read(soc_fd, cipher, sizeof(cipher));
			if (recv_bytes == 0) {
				/* Server termination will lead to a 0 read on this socket */
				fprintf(stderr, "\nConnection terminated by remote server !!!\n");
				return -1;
			} else if (recv_bytes < 0) {
				fprintf(stderr, "\nCannot receive data on client socket !!!\n");
				return -1;
			}

                        status = decrypt_data(cipher, plain, recv_bytes, &session_key, &client_state);
                        if (status != 0) {
                        	fprintf(stderr, "\nUnable to decrypt data at client !!!\n");
                        	return -1; 
                        }
    
                        send_bytes = write(STDOUT_FILENO, plain, recv_bytes - 8);
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
	      char	*destn,
	      char	*key) {
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

			status = destn_service_handler(new_fd, destn_port, destn, key);
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
        char    	*key_file = NULL, key[21];
        char    	destn[50] = {0}, *ptr = NULL;
        int     	index = -1, status;
	int		destn_port = -1, proxy_port = -1, len;
	long long int	temp = -1;
	FILE 		*file = NULL;

	if (argc < 4) {
		fprintf(stderr, "\nPlease enter correct number of arguments !!!\n");
		return 0;
	}
	
        while ((option = getopt(argc, argv, "l:k:")) != -1) {
                switch(option) {
                        case 'k':
                                key_file = optarg;
				file = fopen(key_file, "r");
				if (file == NULL) {
					fprintf(stderr, "\nKey file not present, please provide complete path for key file\n");
					return -1;
				}

				ptr = fgets(key, 21, file);
				if (strlen(key) != 17) {
					fprintf(stderr, "\nKey length should be 16 bytes only, check key file\n");
				}
				key[16] = '\0';
        			//printf("Retrieved key: %s\tLength = %zd\n", key, strlen(key));

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
	fprintf(stderr, "\nKey = %s, proxy port = %d, destn = %s, destn Port = %d\n", key, proxy_port, destn, destn_port);

	if (proxy_port == -1) {
		/* client mode */
		status = client_connections(destn, destn_port, &soc_fd);
		if (status != 0) {
			fprintf(stderr, "\nUnable to establish client connections !!!\n");
			return -1;
		}

		status = client_launch(soc_fd, key);
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

                status = server_launch(proxy_soc_fd, destn_port, destn, key);
                if (status != 0) {
                        fprintf(stderr, "\nClient unable to communicate with client !!!\n");
                        return -1; 
                }   
	}

	return 0;
}
