main: main.c ./src/encrypt_utils.c ./src/socketwrappers.c
	gcc -g -o sniffer main.c ./src/encrypt_utils.c ./src/socketwrappers.c -lpcap -lcrypto

clean:
	rm -f *.o sniffer
