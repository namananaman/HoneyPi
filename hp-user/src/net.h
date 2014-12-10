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

int create_socket(int16_t port, int32_t addr);

int read_cmd(char * data, int len);

void
bcast_cmd(char * data, int len);

void setup_agg_addr(uint16_t port, uint32_t addr);

int create_agg_socket();
void connect_agg();

void close_agg();

int write_agg(void * buff, size_t len);

void write_clear(void);
#endif
