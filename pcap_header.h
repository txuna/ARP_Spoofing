#ifndef __PCAP_H_
#define __PCAP_H_

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>


#define HWADDR_len 6
//send_arp <interface> <sender ip> <target ip>

#pragma pack(push, 1)
typedef struct _Target
{
  const char* wlan_name;
  u_char Sender_IP[4];
  u_char Target_IP[4];
  u_char MyMac[6];
  u_char Target_Mac[6];
}Target;

typedef struct _Ethernet{
	u_char dest_mac[6];
	u_char src_mac[6];
  u_short Protocol;
}Ethernet;

typedef struct _IPv4{
	u_char Version_HeaderLength; //4bit & 4bit need for bit mask
	u_char TypeOfService;
	u_short TotalPacketLength;
	u_short Fragment_Identifier;
	u_short FragmentationFlag_Offset; // umm... 4bit + 12bit? bit mask
	u_char TTL;
	u_char Protocol;
	u_short Header_Checksum;
	u_char Source_IP_Address[4];
	u_char Destion_IP_Address[4];
}IPv4;

typedef struct _TCP_Header{
	u_short SourcePort;
	u_short DestinationPort;
	u_char Sequence_Number[4];
	u_char Acknowledgement[4];
	u_short Header_Reserved_Flag;
	u_short Windows_size;
	u_short CheckSum;
	u_short UrgentPointer;
	u_char Option[12];
}TCP_Header;

typedef struct _ARP_Header{
	u_short HardWare_AddressType;
  u_short Protocol;
  u_char HardWareAddressLength;
  u_char ProtocolAddressLength;
  u_short Operation;
  u_char SourceHardWareAddress[6]; //source mac
  u_char SourceProtocolAddress[4]; //source ip
  u_char TargetHardWareAddress[6]; //target mac
  u_char TargetProtocolAddress[4]; //target ip
}ARP_Header;

typedef struct _Packet
{
    Ethernet ethernet;
    ARP_Header arp_header;
}Packet;
#pragma pack(pop)
int check_arp_packet(const u_char* network_packet);
int cature_packet(Target* target);
int Handler(Target* target);
int ARP_Parse(Packet* arp_header, Target* target);
void help();
int get_mac(Target* target);
void error_handling(const char* msg, bool exist_error);
int request_arp_packet(Packet* packet, Target* target);
int reply_arp_packet(Packet* packet, Target* target);
void make_arp_packet(Packet* packet, Target* target);
void arp_infection(Packet* packet, Target* target);
int ip_to_dec(Target* target, const char* Sender_IP, const char* Target_IP);
#endif
