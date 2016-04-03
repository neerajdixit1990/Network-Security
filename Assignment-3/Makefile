CC = gcc

LIBS = -lpthread -lcrypto /home/neeraj/Desktop/Network-Security/unpv13e/libunp.a 
	
FLAGS = -g -O2 -I/home/neeraj/Desktop/Network-Security/unpv13e/lib

all: pbproxy 

pbproxy: pbproxy.o 
	${CC} ${FLAGS} -o pbproxy pbproxy.o ${LIBS}
pbproxy.o: pbproxy.c
	${CC} ${FLAGS} -c pbproxy.c

clean:
	rm pbproxy.o pbproxy 

