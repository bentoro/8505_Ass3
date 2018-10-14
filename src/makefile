main: main.c ./wrappers/encrypt_utils.c
	gcc -g -o sniffer main.c ./wrappers/encrypt_utils.c -lpcap -lcrypto

clean:
	rm -f *.o
	rm -f sniffer
