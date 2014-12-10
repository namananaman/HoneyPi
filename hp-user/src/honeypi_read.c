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
#include "hashtable.h"
#include "net.h"
#define USE_NET 1
#if USE_NET
#define print(...) sprintf(buf,__VA_ARGS__); write_agg(buf,strlen(buf))
#else
#define print(...) printf(__VA_ARGS__)
#endif



static char buf[256];
void int_handler(int sig);
static char * dev_file = "/dev/honeypi";

struct hashmap spammers;
struct hashmap vulnerable;
struct hashmap  evil;
ipt* protocol;

void init_ipts(void)
{
  hashtable_initialize(&spammers,200,default_hash, 4);
  hashtable_initialize(&vulnerable,200,default_hash, 2);
  hashtable_initialize(&evil,200,default_hash, 4);
  protocol = create();
}


void
int32_to_uint8_tptr(uint32_t val, uint8_t arr[4])
{
  arr[3] = (val >> 24)&0xff;
  arr[2] = (val >> 16)&0xff;
  arr[1] = (val >> 8)&0xff;
  arr[0] = (val >> 0)&0xff;
}


void
int16_to_uint8_tptr(uint16_t val, uint8_t arr[2])
{
  arr[1] = (val >> 8)&0xff;
  arr[0] = (val >> 0)&0xff;
}


void handle_command(struct hp_pkt * cmd) {

  uint8_t _src_ip[4];
  uint8_t _dst_port[2];
  uint8_t djb2_hash[4];
  uint16_t dst_port = (uint16_t)(cmd->src_ip>>16);
  int32_to_uint8_tptr(cmd->src_ip,_src_ip);
  int32_to_uint8_tptr(cmd->djb2_hash,djb2_hash);
  int32_to_uint8_tptr(dst_port,_dst_port);
  switch(cmd->cmd) {
    case HONEYPOT_ADD_SPAMMER_BE:
      hashtable_add(&spammers,_src_ip,0);
      break;
    case HONEYPOT_ADD_EVIL_BE:
      hashtable_add(&evil,djb2_hash, 0);
      break;
    case HONEYPOT_ADD_VULNERABLE_BE:
      hashtable_add(&vulnerable,_dst_port,0);
      break;
    case HONEYPOT_DEL_SPAMMER_BE:
      hashtable_delete(&spammers,_src_ip);
      break;
    case HONEYPOT_DEL_EVIL_BE:
      hashtable_delete(&evil,djb2_hash);
      break;
    case HONEYPOT_DEL_VULNERABLE_BE:
      hashtable_delete(&vulnerable,_dst_port);
      break;
    case HONEYPOT_PRINT_BE:
      int_handler(0);
      return;
  }
}


void handle_pkt(struct hp_pkt * pkt)
{
  //printf("%x %x %x %x\n",pkt->src_ip,pkt->dst_ip, pkt->src_port, pkt->dst_port);
  ipt_add(protocol, (uint8_t*)&(pkt->protocol),1,1,1);
  if (pkt->cmd != 0) {
    bcast_cmd((char*)pkt, sizeof(struct hp_pkt));
    handle_command(pkt);
    return;
  }
  uint8_t _src_ip[4];
  uint8_t _dst_p[2];
  uint8_t djb2_hash[4];
  uint8_t temp[4];
  int32_to_uint8_tptr(pkt->src_ip,_src_ip);
  int32_to_uint8_tptr(pkt->djb2_hash,temp);
  int16_to_uint8_tptr(pkt->dst_port,_dst_p);

  djb2_hash[0] = temp[3];
  djb2_hash[1] = temp[2];
  djb2_hash[2] = temp[1];
  djb2_hash[3] = temp[0];

  hashtable_increment(&spammers,_src_ip,1);
  hashtable_increment(&vulnerable,_dst_p,1);
  hashtable_increment(&evil,djb2_hash,1);
}


void print_ip (void * val, uint8_t * key, int k_len )
{
  print("%u.%u.%u.%u:",key[0],key[1],key[2],key[3]);
  print("%ld\n",(long)val);
}

void print_port(void * val, uint8_t * key, int k_len)
{
  uint16_t port = (key[0] << 8) | key[1];
  print("%u:",port);
  print("%ld\n",(long)val);
}
void print_proto(void * val, uint8_t * key, int k_len)
{
  print("%u:",key[0]);
  print("%ld\n",(long)val);
}
void print_evil(void *val, uint8_t * key, int k_len) {
  int i;
  for (i = 0; i < k_len; i++) {
    print("%02x",key[i]);
  }
  print(":%ld\n",(long)val);
}


void int_handler(int sig)
{
  connect_agg();
  print("Begin honeypot output:\n");
  print("Spammers:\n");
  hashtable_iter(&spammers,print_ip);
  print("Vulnerable Ports:\n");
  hashtable_iter(&vulnerable,print_port);
  print("Evil Packets:\n");
  hashtable_iter(&evil,print_evil);
  print("Protocols:\n");
  uint8_t k;
  ipt_iter(protocol, 1,1, &k,print_proto);
  print("End of output.\n");
  close_agg();
}

int main(int argc, char **argv)
{
  init_ipts();

  int dev_fd = open(dev_file, O_RDONLY);

  if (net_init() > 0) {
    printf("couldn't bind to a socket\n");
    exit(-1);
  }
  int count = 1000;
  while(1)
  {
    struct hp_pkt pkt;
    int bytes_read = read_cmd((char*)&pkt, sizeof (struct hp_pkt));

    // not every pi is going to get the PRINT command from the generator
    if((--count) == 0) {
      count = 1000;
      int_handler(0);
    }

    if (bytes_read == sizeof(struct hp_pkt)) {
      handle_command(&pkt);
    }
    bytes_read = read(dev_fd,(char*)&pkt, sizeof(struct hp_pkt));
    if (bytes_read < sizeof(struct hp_pkt))
    {
      printf("didn't read a packet\n");
      exit(0);
    }
    handle_pkt(&(pkt));
  }
}
