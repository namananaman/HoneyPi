#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <hp_ioctl.h>
#include "ip-tree.h"

static char * dev_file = "/dev/honeypi";

ipt * src_ip;
ipt * dst_ip;
ipt * dst_p;
ipt * src_p;
ipt * protocol;


void init_ipts(void)
{
  src_ip = create();
  dst_ip = create();
  src_p = create();
  dst_p = create();
  protocol = create();
}

int32_to_charptr(uint32_t val, char arr[4])
{
  arr[3] = (val >> 24)&0xff;
  arr[2] = (val >> 16)&0xff;
  arr[1] = (val >> 8)&0xff;
  arr[0] = (val >> 0)&0xff;
}

int16_to_charptr(uint16_t val, char arr[2])
{
  arr[1] = (val >> 8)&0xff;
  arr[0] = (val >> 0)&0xff;
}
void handle_pkt(struct hp_pkt * pkt)
{
  //printf("%x %x %x %x\n",pkt->src_ip,pkt->dst_ip, pkt->src_port, pkt->dst_port);
  char _src_ip[4];
  char _dst_ip[4];
  char _src_p[2];
  char _dst_p[2];
  int32_to_charptr(pkt->src_ip,_src_ip);
  int32_to_charptr(pkt->dst_ip,_dst_ip);
  int16_to_charptr(pkt->src_port,_src_p);
  int16_to_charptr(pkt->dst_port,_dst_p);
  ipt_add(src_ip,_src_ip,4,1,1);
  ipt_add(dst_ip,_dst_ip,4,1,1);
  ipt_add(src_p,_src_p,2,1,1);
  ipt_add(dst_p,_dst_p,2,1,1);
  ipt_add(protocol,(char*)&(pkt->protocol),1,1,1);
}


void print_ip (void * val, uint8_t * key, int k_len )
{
  printf("%u.%u.%u.%u:",key[0],key[1],key[2],key[3]);
  printf("%ld\n",(long)val);
}

void print_port(void * val, uint8_t * key, int k_len)
{
  uint16_t port = (key[0] << 8) | key[1];
  printf("%u:",port);
  printf("%ld\n",(long)val);
}
void print_proto(void * val, uint8_t * key, int k_len)
{
  printf("%u:",key[0]);
  printf("%ld\n",(long)val);
}


void int_handler(int sig)
{
  uint8_t key[4];
  printf("Source IPs:\n");
  ipt_iter(src_ip,4,4,key,print_ip);
  printf("Destination IPs:\n");
  ipt_iter(dst_ip,4,4,key,print_ip);
  printf("Source Ports:\n");
  ipt_iter(src_p,2,2,key,print_port);
  printf("Destination Ports:\n");
  ipt_iter(dst_p,2,2,key,print_port);
  printf("Protocols:\n");
  ipt_iter(protocol, 1,1,key,print_proto);
  exit(0);
}

int main(int argc, char **argv)
{
  signal(SIGINT,int_handler);
  init_ipts();
  int dev_fd = open(dev_file, O_RDONLY);
  while(1)
  {
    struct hp_pkt pkt[64];
    int bytes_read = read(dev_fd,(char*)pkt, sizeof(struct hp_pkt) * 64);
    if (bytes_read < sizeof(struct hp_pkt))
    {
      printf("didn't read a packet\n");
      exit(0);
    }
    int n_packets = bytes_read / sizeof(struct hp_pkt);
    int i;
    for (i = 0; i < n_packets; i++)
    {
      handle_pkt(&(pkt[i]));
    }
  }
}
