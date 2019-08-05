#include "pcap_header.h"

int ip_to_dec(Target* target, const char* Sender_IP, const char* Target_IP)
{
	unsigned long int Sender = inet_addr(Sender_IP);
	unsigned long int Target = inet_addr(Target_IP);

	int bit = 0;
	for(int i=0;i<4;i++)
	{
		target->Sender_IP[i] = (Sender>>bit )& 0xff;
		target->Target_IP[i] = (Target>>bit)& 0xff;
		bit+=8;
	}

}
