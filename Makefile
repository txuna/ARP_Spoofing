all : arp_sender

arp_sender: Handler.o get_mac.o print_information.o help.o transelate_IP_to_dec.o main.o error_handling.o
	g++ -o arp_sender Handler.o get_mac.o print_information.o help.o transelate_IP_to_dec.o main.o error_handling.o -lpcap

Handler.o: pcap_header.h Handler.cpp 
	g++ -c -o Handler.o Handler.cpp 

get_mac.o: pcap_header.h get_mac.cpp 
	g++ -c -o get_mac.o get_mac.cpp 

print_information.o: pcap_header.h print_information.cpp 
	g++ -c -o print_information.o print_information.cpp 

help.o: pcap_header.h help.cpp 
	g++ -c -o help.o help.cpp 

transelate_IP_to_dec.o: pcap_header.h transelate_IP_to_dec.cpp 
	g++ -c -o transelate_IP_to_dec.o transelate_IP_to_dec.cpp 

main.o: pcap_header.h main.cpp 
	g++ -c -o main.o main.cpp 

error_handling.o: pcap_header.h error_handling.cpp 
	g++ -c -o error_handling.o error_handling.cpp 

clean:
	rm *.o 
