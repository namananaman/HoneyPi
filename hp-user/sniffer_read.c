#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <time.h>
#include <getopt.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <hp_ioctl.h>
#include <signal.h>
#include "ip-tree.h"

ipt * protocols; //depth 1

ipt * d_ips; // depth 4
ipt * s_ips; // depth 4

static char * program_name;
static char * dev_file = "/dev/honeypi";

void usage()
{
  fprintf(stderr, "Usage: %s [-i input_file] [-o output_file]\n", program_name);
  exit(EXIT_FAILURE);
}


char* read_packet(int in_fd, int *len) {

  char *packet = malloc(8192); // this is alot but just to make sure we get the whole packet in one go.
  char *offset = packet;
  int nread = 0;
  int n = 0;
  while((nread = read(in_fd,offset,8192-n)) > 0) {
    offset+=nread;
    n+=nread;
  }
  if (nread < 0 || n == 0) {
    return NULL;
  }
  len[0] = n;

  return packet;
}

void
sig_info(int signum)
{
   printf("Caught SIGUSR1\n");
}



int main(int argc, char **argv)
{
  int c;
  char *input_file, *output_file = NULL;
  int out_fd = stdout;
  int in_fd;
  program_name = argv[0];

  input_file= dev_file;

  signal(SIGUSR1, sig_info);

  while((c = getopt(argc, argv, "i:o:")) != -1) {
    switch (c) {
      case 'i':
        input_file = strdup(optarg);
        break;
      case 'o':
        output_file = strdup(optarg);
        break;
      default:
        usage();
    }
  }

  in_fd = open(input_file, O_RDWR);
  if(output_file)
  {
    out_fd = open(output_file, O_CREAT| O_RDWR, 0640);
  } else {
    out_fd = open("/dev/tty", O_WRONLY);
  }

  struct timespec start, end;

  double bytes = 0.0;
  double time =0.0;
  double packets =0.0;
  int i = 20000;
  while(1) {
    int len = 0;


    char * data = read_packet(in_fd,&len);


    // subtract time-stamps and
    // multiply to get elapsed
    // time in ns
    int j;
    struct iphdr * ip = (struct iphdr*)(data);
    char proto = ip->protocol;

    ipt_add(protocols, &proto,1,1,1);
    ipt_add(s_ips, (char*)&ip->saddr, 4, 1,1);
    ipt_add(d_ips, (char*)&ip->daddr, 4, 1,1);

    switch (ip->protocol) {
    case IPPROTO_TCP:
      printf("tcp packet\n");
      break;
    case IPPROTO_UDP:
      printf("udp packet\n");
      break;
    case IPPROTO_ICMP:
      printf("icmp packet\n");
      break;
    }
    //struct tcphdr *tcp = (void *) ip + ip->ihl*4;

    //printf("tcp->src = %d, tcp->dst = %d\n",htons(tcp->source), htons(tcp->dest));
    free(data);
  }

  return 0;
}
