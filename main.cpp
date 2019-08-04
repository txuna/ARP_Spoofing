#include "pcap_header.h"
//send_arp <interface> <sender ip> <target ip>
int main(int argc,  char** argv)
{
  if(argc != 4)
  {
    printf("struct size : %lu\n", sizeof(Packet));
    error_handling("Usage Two argument ex)send_arp <interface> <sender ip> <target ip>", false);
  }
  help();
  Target target;
  target.wlan_name = argv[1];
  ip_to_dec(&target, argv[2], argv[3]);
  get_mac(&target);
  get_my_ip(&target);
  printf("[DEBUG] : %d.%d.%d.%d and.%d.%d.%d.%d and %d.%d.%d.%d and %02x:%02x:%02x:%02x:%02x:%02x\n",
  target.Sender_IP[0], target.Sender_IP[1], target.Sender_IP[2], target.Sender_IP[3],
  target.Target_IP[0], target.Target_IP[1], target.Target_IP[2], target.Target_IP[3],
  target.My_IP[0], target.My_IP[1], target.My_IP[2], target.My_IP[3],
  target.MyMac[0], target.MyMac[1], target.MyMac[2], target.MyMac[3], target.MyMac[4], target.MyMac[5]);
  for(int i=0;i<6;i++)
  {
    target.Target_Mac[i] =0x00;
  }
  Handler(&target);
}
