#include "pcap_header.h"

int get_mac(Target* target)
{
  int fd;
	struct ifreq ifr;
	const char *iface = target->wlan_name;
	unsigned char *mac;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
  for(int i=0;i<6;i++)\
  {
    target->MyMac[i] = mac[i];
  }

}
