all: arp-spoof

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o
	g++ -o arp-spoof main.o arphdr.o ethhdr.o ip.o mac.o -lpcap

clean:
	rm -f arp-spoof *.o