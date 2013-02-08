sniffer: sniffer.c Radiotap.c
	gcc -o sniffer sniffer.c Radiotap.c -I. -lpcap -lmqttv3c -pthread -std=gnu99
