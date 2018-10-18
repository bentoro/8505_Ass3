main: main.c ./src/encrypt_utils.c ./src/socketwrappers.c ./src/covert_wrappers.c
	gcc -g -o sniffer main.c ./src/encrypt_utils.c ./src/socketwrappers.c ./src/covert_wrappers.c -lpcap -lcrypto

clean:
	rm -f *.o sniffer
	rm -f results cmd.sh
