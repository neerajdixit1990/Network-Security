CC = gcc

LIBS = -lpthread -lpcap
	
FLAGS = -g -O2

all: dnsinject dnsdetect 

dnsinject: dnsinject.o 
	${CC} ${FLAGS} -o dnsinject dnsinject.o ${LIBS}
dnsinject.o: dnsinject.c
	${CC} ${FLAGS} -c dnsinject.c 

dnsdetect: dnsdetect.o
	${CC} ${FLAGS} -o dnsdetect dnsdetect.o ${LIBS}
dnsdetect.o: dnsdetect.c
	 ${CC} ${FLAGS} -c dnsdetect.c
clean:
	rm dnsinject.o dnsinject dnsdetect.o dnsdetect 

