#include "pcap_header.h"

void error_handling(const char* msg, bool exist_error)
{
  if(exist_error)
  {
    perror(msg);
  }
  else{
    printf("[Error] : %s", msg);
  }
  exit(0);
}
