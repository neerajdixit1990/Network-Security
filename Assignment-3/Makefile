CC = gcc

LIBS = -lpthread -lcrypto 
	
FLAGS = -g -O2 

all: pbproxy 

pbproxy: pbproxy.o 
	${CC} ${FLAGS} -o pbproxy pbproxy.o ${LIBS}
pbproxy.o: pbproxy.c
	${CC} ${FLAGS} -c pbproxy.c

clean:
	rm pbproxy.o pbproxy 

