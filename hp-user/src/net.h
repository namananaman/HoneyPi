#ifndef _NET_H_
#define _NET_H_
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>
#include <fcntl.h>
#include <inttypes.h>
#define LISTEN_BACKLOG 10

int net_init(void);
int read_ips(uint32_t*,uint16_t*,int);
void print_my_addr(int);
int create_send_socket(void);

int send_cmd(int fd, int16_t port, int16_t addr, char * data, int len);

int create_socket(int16_t port, int32_t addr);

int read_cmd(int fd, char * data, int len);

void
bcast_cmd(int send_fd, char * data, int len);
#endif
