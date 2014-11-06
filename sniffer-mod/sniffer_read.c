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
#include <getopt.h>
#include "hp_ioctl.h"

static char * program_name;
static char * dev_file = "/dev/sniffer";

void usage()
{
    fprintf(stderr, "Usage: %s [-i input_file] [-o output_file]\n", program_name);
    exit(EXIT_FAILURE);
}

int print_packet(char * pkt, int len, int out_fd)
{
    /* print format is :
     * src_ip:src_port -> dst_ip:dst_port
     * pkt[0] pkt[1] ...    pkt[64] \n
     * ...
     * where pkt[i] is a hex byte */
    uint32_t src_ip, dst_ip;
    uint16_t src_p, dst_p;
    uint8_t * data;
    int i;
    struct in_addr saddr;
    struct in_addr daddr;

    src_ip = ((uint32_t*)(pkt))[0];
    dst_ip = ((uint32_t*)(pkt))[1];
    src_p = ((uint16_t*)(pkt+8))[0];
    dst_p = ((uint16_t*)(pkt+8))[1];

    data = (uint8_t*)(pkt+12);


    saddr.s_addr = src_ip;
    daddr.s_addr = dst_ip;
    dprintf(out_fd,"%s:%u -> %s:%u\n", inet_ntoa(saddr),src_p,inet_ntoa(daddr),dst_p);
    for (i =0; i < len-12; i++) {
      if(i!=0 && i%64==0) dprintf(out_fd,"\n");
      dprintf(out_fd,"%02X ",data[i]);
    }
    dprintf(out_fd,"\n");
    free(pkt);
    return 0;
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

int main(int argc, char **argv)
{
    int c;
    char *input_file, *output_file = NULL;
    int out_fd = stdout;
    int in_fd;
    program_name = argv[0];

    input_file= dev_file;

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


    while(1) {
      int len;
      char * data = read_packet(in_fd,&len);
      if(!data) break;
      print_packet(data,len,out_fd);
    }

    return 0;
}
