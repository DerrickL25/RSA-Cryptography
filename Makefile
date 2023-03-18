/*********************************************************************************
* Makefile
* Compiles with Clang and links files; generates executable binaries
*
* make                makes keygen, encrypt, decrypt
* make clean          removes all binaries
* make cleankeys      removes files containing key pairs
*********************************************************************************/

CC = clang
CFLAGS = -Wall -Werror -Wextra -Wpedantic -O3 $(shell pkg-config --cflags gmp)
LFLAGS = -O3 $(shell pkg-config --libs gmp)

all: keygen encrypt decrypt

keygen: keygen.o rsa.o randstate.o numtheory.o
	$(CC) -o $@ $^ $(LFLAGS) 

encrypt: encrypt.o rsa.o randstate.o numtheory.o
	$(CC) -o $@ $^ $(LFLAGS)

decrypt: decrypt.o rsa.o randstate.o numtheory.o
	$(CC) -o $@ $^ $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f keygen encrypt decrypt *.o

cleankeys:
	rm -f *.{pub,priv}
