#include "pcap_header.h"
int get_my_ip(Target* target)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1)
    {
      error_handling("getifaddrs error", true);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if((strcmp(ifa->ifa_name,target->wlan_name)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
        {
            if (s != 0)
            {
              error_handling("getnameinfo() error", true);
            }
            unsigned long int ip = inet_addr(host);
            int bit = 0;
            for(int i=0;i<4;i++)
            {
              target->My_IP[i] = (ip>>bit )& 0xff;
              bit+=8;
            }
        }
    }
    freeifaddrs(ifaddr);
}
