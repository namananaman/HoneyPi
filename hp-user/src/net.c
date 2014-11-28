
#include "net.h"
#include  <config_honeypi.h>

static int recv_fd;
static int send_fd;
static char * config_file = "honeypi.config";

static uint32_t ips[MAX_NUM_IPS];
static uint16_t ports[MAX_NUM_IPS];

static int local_index = -1;
static int num_ips;


int net_init(void) {


  int ret = read_ips(ips,ports, MAX_NUM_IPS);
  int i;
  recv_fd = -1;
  for (i = 0; i < ret; i++) {
    recv_fd = create_socket(ports[i],ips[i]);
    if (recv_fd > 0) {
      break;
    }
  }

  if (recv_fd < 0) {
    return -1;
  }

  local_index = i;
  num_ips = ret;
  #if DEBUG
  printf("Found %d IP addresses\n",ret);
  printf("Bound to address at index %d\n", i);
  printf ("IP is ");
  print_my_addr(recv_fd);
  printf ("Port is %d\n", ports[i]);
  #endif

  send_fd = create_send_socket();

  return 0;
}

int read_ips(uint32_t * ips, uint16_t * ports, int n)
{
  FILE * file = fopen(config_file,"r");
  static uint32_t a,b,c,d,e;
  int i;
  for (i= 0; i < n; i++) {
    int ret = fscanf(file, "%u.%u.%u.%u:%u\n",&a,&b,&c,&d, &e);
    if (ret == -1) {
      break;
    }
    ips[i] = a << 24 | b << 16 | c << 8 | d;
    ports[i] = (uint16_t)e;
  }
  return i;
}

int create_send_socket(void) {
  return socket(AF_INET, SOCK_DGRAM, 0);
}


void
bcast_cmd(int send_fd, char * data, int len) {
  int i;
  for (i = 0; i < num_ips; i++) {
    if ( i == local_index) {
      continue;
    }
    send_cmd(send_fd, ports[i], ips[i], data, len);
  }
}

int send_cmd(int fd, int16_t port, int16_t addr, char * data, int len) {

  struct sockaddr_in sin;

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = SOCK_DGRAM;
  sin.sin_addr.s_addr = htonl(port);
  sin.sin_port = htons(addr);

  return sendto(fd, data, len , 0, (struct sockaddr *)&sin, sizeof(sin));
}

void print_my_addr(int sockfd) {

  struct sockaddr_in localAddress;
  socklen_t addressLength =sizeof(struct sockaddr_in);
  getsockname(sockfd, (struct sockaddr*)&localAddress,
      &addressLength);
  printf("%s\n", inet_ntoa( localAddress.sin_addr));

}
int create_socket(int16_t port, int32_t addr) {

  struct sockaddr_in sin;

  int udp_s = socket(AF_INET,SOCK_DGRAM,0);
  if (udp_s < 0) {
    return -1;
  }
  fcntl(udp_s, F_SETFL, O_NONBLOCK);
  sin.sin_family = SOCK_DGRAM;
  sin.sin_addr.s_addr = htonl(addr);
  sin.sin_port = htons(port);
  if (bind(udp_s, (struct sockaddr *) &sin,
        sizeof(sin)) < 0)  {
    return -1;
    printf ("bind error\n");
  }

  return udp_s;
}

int read_cmd(int fd, char * data, int len)
{
  struct sockaddr_in addr;
  int fromlen = sizeof(struct sockaddr_in);

  len = recvfrom(fd, data, len, 0,
      (struct sockaddr*)&addr, (socklen_t *)&fromlen);


  return len;
}

