#include "pcap_header.h"
//send_arp <interface> <sender ip> <target ip>
int main(int argc,  char** argv)
{
  if(argc != 4)
  {
    error_handling("Usage Two argument ex)send_arp <interface> <sender ip> <target ip>", false);
  }
  Target target;
  target.wlan_name = argv[1]; //argv[1]
  /*
  target.wlan_name = argv[1];
  target.Sender_IP = argv[2];
  target.Target_IP = argv[3];
  */
  ip_to_dec(&target, argv[2], argv[3]);
  get_mac(&target);
  //mac_eth0(&target);
  //cature_packet(&target);
  Handler(&target);
}

/*
// arp spoofing하는데 딱히 packet을 얻어올 필요는 없을듯.,...
int cature_packet(Target* target)
{
  char* dev = target->wlan_name;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    error_handling("couldn't open device", true);
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    Handler(packet, target);
  }
  pcap_close(handle);
  return 0;
}
*/
