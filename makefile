main: main.c ./src/encrypt_utils.c
	gcc -g -o sniffer main.c ./src/encrypt_utils.c -lpcap -lcrypto

clean:
	rm -f *.o sniffer
