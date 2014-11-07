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
#include "hp_ioctl.h"

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

  struct timespec start, end;

  double bytes = 0.0;
  double time =0.0;
  double packets =0.0;
  int i = 20000;
  while(1) {
    int len = 0;

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start); // get initial time-stamp

    char * data = read_packet(in_fd,&len);

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);   // get final time-stamp

    double t_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
      (double)(end.tv_nsec - start.tv_nsec);
    time+=t_ns;
    packets += 1.0;
    bytes+=(double)len;
    // subtract time-stamps and
    // multiply to get elapsed
    // time in ns
    free(data);
    if (!(i--)) {
      printf("packets/second = %f\n",(packets/(time*(1e-9))));
      printf("Mbytes/second = %f\n",((bytes*1e-6)/(time*(1e-9))));
      bytes = 0.0;
      packets = 0.0;
      time = 0.0;
      i = 20000;
    }
  }

  return 0;
}
