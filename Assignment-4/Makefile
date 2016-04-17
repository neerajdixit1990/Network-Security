CC = gcc

LIBS = -lpthread -lpcap
	
FLAGS = -g -O2

all: dnsinject 

dnsinject: dnsinject.o 
	${CC} ${FLAGS} -o dnsinject dnsinject.o ${LIBS}
dnsinject.o: dnsinject.c
	${CC} ${FLAGS} -c dnsinject.c 


clean:
	rm dnsinject.o dnsinject 

