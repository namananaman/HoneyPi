//#define _GNU_SOURCE 1
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <stropts.h>
#include <math.h>
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "sim.h"

#define _NET_MAXPKT 1024

unsigned char* pkt = malloc(_NET_MAXPKT);
int pkt_len;
static time_t last_print_t;
int opt_verbose_net;

// let's aim for about N_LO<r<N_HI elements in each of the three lists
// with M_LO=5%<r<30%=M_HI of packets matching each list
// if the current list is too small, add with high probability
// else add or subtract with 
/*
#define N_LO 40 // lists are around 50 +/- 10 elements long
#define N_HI 60
#define M_LO 10 // packet match rates are around 20 +/ 10 percent
#define M_LO 30
*/

struct evilpkt {
  unsigned int len;
  unsigned char data[0];
};

struct elt {
  unsigned int key;
  struct evilpkt *pkt;
  unsigned int count;
  unsigned char* sha_hash;
};

struct vec {
  unsigned int m_spam, m_evil, m_vuln;
  int count, capacity, target, probk;
  struct elt *elt;
};

volatile struct vec v_spam;
volatile struct vec v_vuln;
volatile struct vec v_evil;
unsigned int npkts, nbytes;

unsigned long djb2(unsigned char *str, int n)
{
  unsigned long hash = 5381;
  int c;
  for (int i = 0; i < n; i++) {
    c = str[i];
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  }
  return hash;
}
//takes a string and an output buffer of length SHA256_DIGEST_LENGTH
void sha256_hash(unsigned char* str, int len, unsigned char* obuf) {
    //unsigned char digest[SHA256_DIGEST_LENGTH];
    //SHA256(str, strlen(str), digest);
    SHA256(str, len, obuf);
    return 0;
}
//initializes a vector used to track the statistics
void vec_init(volatile struct vec *v, int n, int target, int probk)
{
  v->elt = malloc(sizeof(struct elt) * n);
  v->count = 0;
  v->capacity = n;
  v->target = target;
  v->probk = probk;
}
//adds a new key to the vec, inserting if possible otherwise doubling 
void vec_add(volatile struct vec *v, unsigned int key, struct evilpkt *pkt)
{
  if (v->count < v->capacity) {
    v->elt[v->count].key = key;
    v->elt[v->count].pkt = pkt;
    if (pkt != NULL) {
      unsigned char* sha_hash = malloc(SHA256_DIGEST_LENGTH);
      sha256_hash(pkt->data, pkt->len, sha_hash);
      v->elt[v->count].sha_hash = sha_hash;
    }
    v->elt[v->count].count = 0;
    v->count = v->count + 1;
    if (v->count > 1) {
      int j = v->count - 1;
      int i = rand() % v->count;
      struct elt e = v->elt[i];
      v->elt[i] = v->elt[j];
      v->elt[j] = e;
    }
    return;
  }

  struct elt *e = malloc(sizeof(struct elt) * v->capacity * 2);
  int n = v->count;
  for (int i = 0; i < n; i++) {
    e[i].key = v->elt[i].key;
    e[i].pkt = v->elt[i].pkt;
    e[i].sha_hash = v->elt[i].sha_hash;
  }
  e[v->count].key = key;
  e[v->count].pkt = pkt;
  if (pkt != NULL) {
      unsigned char* sha_hash = malloc(SHA256_DIGEST_LENGTH);
      sha256_hash(pkt->data, pkt->len, sha_hash);
      v->elt[v->count].sha_hash = sha_hash;
  }
  e[v->count].count = 0;
  for (int i = 0; i < n; i++)
    e[i].count = v->elt[i].count;
  struct elt *old = v->elt;
  v->elt = e;
  v->capacity = v->capacity * 2;
  v->count = v->count + 1;
  free(old);
  
  if (v->count > 1) {
    int j = v->count - 1;
    int i = rand() % v->count;
    struct elt e = v->elt[i];
    v->elt[i] = v->elt[j];
    v->elt[j] = e;
  }
}

// safe for core 0 to call while concurrent updates to counts
//removes a key from the vec and moves the packet there
void vec_del(volatile struct vec *v, unsigned int key)
{
  int n = v->count;
  for (int i = 0; i < n; i++) {
    if (v->elt[i].key != key) continue;
    void *old = v->elt[i].pkt;
    if (old) free(old);
    unsigned char* hash = v->elt[i].sha_hash;
    if (hash) free(hash);
    v->elt[i].sha_hash = NULL;
    v->elt[i].pkt = NULL;
    if (i != n-1) {
      // deleting from middle of list
      v->elt[i].key = v->elt[n - 1].key;
      v->elt[i].pkt = v->elt[n - 1].pkt;
      v->elt[i].count = v->elt[n - 1].count;
      v->elt[i].sha_hash = v->elt[n-1].sha_hash;
    }
    v->count = v->count - 1;
    return;
  }
}

// safe for any to call
// increments the count for the specified key
void vec_inc(volatile struct vec *v, unsigned int key)
{
  int n = v->count;
  for (int i = 0; i < n; i++) {
    if (v->elt[i].key != key) continue;
    v->elt[i].count++;
    break;
  }
}


#define NET_S_CE 1
#define NET_S_IE 2
#define NET_S_RX 4
#define NET_S_TX 8
//generates a random number
unsigned int exp_rand(double mean) {
  double r = (double)rand()/(double)RAND_MAX;
  double t = -mean * log(1-r);
  return (unsigned int)(t - 0.5);
}
//picks a random key from a vec
unsigned int pick_rand(volatile struct vec *v)
{
  if (v->count == 0) return 0;
  int r = exp_rand(v->count / 4.0);
  if (r < 0) r = 0;
  else if (r >= v->count) r = v->count;
  return v->elt[r].key;
}
//picks a random evil packet from a vec
struct evilpkt *pick_randp(volatile struct vec *v)
{
  if (v->count == 0) return 0;
  int r = exp_rand(v->count / 4.0);
  if (r < 0) r = 0;
  else if (r >= v->count) r = v->count - 1;
  return v->elt[r].pkt;
}
//checks if a vec contains a key
unsigned int vec_has(volatile struct vec *v, unsigned int key)
{
  for (int i = 0; i < v->count; i++) 
    if (v->elt[i].key == key)
      return 1;
  return 0;
}

#define DATA_START sizeof(struct iphdr) + sizeof(struct udphdr)
//takes a pointer to a data buffer, and makes a packet full of random data
void fill_rand(unsigned char *data, unsigned int *net_len, unsigned int src_addr, unsigned short dst_port) {

    // pick a random packet length
    double r = (double)rand()/(double)RAND_MAX;
    unsigned int len = NET_MINPKT + (unsigned int)(r*(_NET_MAXPKT-NET_MINPKT));
    if (len < NET_MINPKT) len = NET_MINPKT;
    else if (len > _NET_MAXPKT) len = _NET_MAXPKT;
    *net_len = len;

    struct iphdr *p = (void *)data;
    p->version = 0x4;
    p->ihl = 0x5;
    p->tos = 16;
    p->tot_len = htons(len);
    p->id = htons((unsigned short)rand());
    p->frag_off = 0;
    p->ttl = 125;
    p->protocol = 0x11;
    p->checksum = 0;
    p->saddr = htonl(src_addr);
    p->daddr = htonl(rand());

    struct udphdr *u = (struct udphdr *) (((void*) buffer) + sizeof(struct iphdr));
    u->source = htons((unsigned short)rand());
    u->dest = htons(dst_port);
    u->len = htons(len - sizeof(struct iphdr);
    u->check = 0;

    for (int i = DATA_START; i < len; i++)
      data[i] = (unsigned char)rand();

    if (len >= 28 + 4) {
      if (*(unsigned short *)(data+28) == ntohs(HONEYPOT_SECRET)
    || *(unsigned short *)(data+28) == HONEYPOT_SECRET)
  *(unsigned short *)(data+28) = 0;
    }
}

struct evilpkt *fill_cmd(unsigned short cmd_id) {

    // pick a random packet length
    double r = (double)rand()/(double)RAND_MAX;
    unsigned int len = NET_MINPKT + (unsigned int)(r*(_NET_MAXPKT-NET_MINPKT));
    if (len < sizeof(struct honeypot_command_packet)) len = sizeof(struct honeypot_command_packet);
    else if (len > _NET_MAXPKT) len = _NET_MAXPKT;
    pkt_len = len;

    struct packet_header *p = (void *)pkt;
    p->ip_version = 0x45;
    p->ip_qos = 0;
    p->ip_len = htons(len);
    p->ip_id = htons((unsigned short)rand());
    p->ip_flags = 0;
    p->ip_ttl = 125;
    p->ip_protocol = 0x11;
    p->ip_checksum = 0;
    p->ip_source_address_big_endian = htonl(rand());
    p->ip_dest_address_big_endian = htonl(0x0a0a0a0a);

    p->udp_source_port_big_endian = htons((unsigned short)rand());
    p->udp_dest_port_big_endian = htons(0x3410);
    p->udp_len = htons(len - 20);
    p->udp_checksum = 0;

    for (int i = sizeof(struct honeypot_command_packet); i < len; i++)
      pkt[i] = (unsigned char)rand();

    struct honeypot_command_packet *cmd = (void *)p;
    cmd->secret_big_endian = htons(HONEYPOT_SECRET);
    cmd->cmd_big_endian = htons(cmd_id);
    unsigned int data = 0;
    struct evilpkt *evil = NULL;
    switch(cmd_id) {
      case HONEYPOT_PRINT:
        data = 0;
        break;
      case HONEYPOT_ADD_SPAMMER: 
        do {
          data = rand();
        } while (vec_has(&v_spam, data));
        break;
      case HONEYPOT_ADD_EVIL: 
        evil = malloc(4096);
        do {
          fill_rand(evil->data, &evil->len, rand(), (unsigned short)(0xffff & rand()));
          data = djb2(evil->data, evil->len);
        } while (vec_has(&v_evil, data));
      case HONEYPOT_ADD_VULNERABLE: 
        do {
          data = rand() & 0xffff;
        } while (vec_has(&v_vuln, data));
        break;
      case HONEYPOT_DEL_SPAMMER:
        data = pick_rand(&v_spam);
        vec_del(&v_spam, data);
        break;
      case HONEYPOT_DEL_EVIL:
        data = pick_rand(&v_evil);
        vec_del(&v_evil, data);
        break;
      case HONEYPOT_DEL_VULNERABLE:
        data = pick_rand(&v_vuln);
        vec_del(&v_vuln, data);
        break;
    }
    //TODO: change command packet so that it can take a sha hash
    if (evil != NULL) {
      unsigned char sha_hash[SHA256_DIGEST_LENGTH];
      sha256_hash(evil->data, evil->len, sha_hash);
      memcpy(&(cmd->sha_hash), sha_hash, SHA256_DIGEST_LENGTH);
      free(sha_hash);
    }
    cmd->data_big_endian = htonl(data);

    return evil;
}

struct honeypot_command_packet *get_cmd()
{
  if (len < sizeof(struct honeypot_command_packet))
    return 0;
  struct honeypot_command_packet *cmd = (void *)pkt;
  if (cmd->secret_big_endian != htons(HONEYPOT_SECRET))
    return 0;
  return cmd;
}

void vec_print(volatile struct vec *v, char *title, char *col)
{
  printf("[net: %s statistics]\n", title);
  int n = v->count;
  if (!n) printf("   empty");
  else printf("     count  %s\n", col);
  for (int i = 0; i < n; i++) 
    printf("   %12d  0x%x \n", v->elt[i].count, v->elt[i].key);
}


void do_print()
{
  //TODO: make sure this is correct
  last_print = time(0);
}

void do_cmd(struct honeypot_command_packet *cmd, struct evilpkt *evil)
{
  unsigned int data = ntohl(cmd->data_big_endian);
  switch(ntohs(cmd->cmd_big_endian)) {
    case HONEYPOT_ADD_SPAMMER: 
      if (opt_verbose_net > 1) printf("[net: honeypot add spammer: %x]\n", data);
      vec_add(&v_spam, data, NULL);
      break;
    case HONEYPOT_ADD_EVIL:
      if (opt_verbose_net > 1) printf("[net: honeypot add evil: %x]\n", data);
      if (!evil) printf("simulator warning: internal error 0xeb11\n");
      else vec_add(&v_evil, data, evil);
      break;
    case HONEYPOT_ADD_VULNERABLE:
      if (opt_verbose_net > 1) printf("[net: honeypot add vulnerable: %x]\n", data);
      vec_add(&v_vuln, data, NULL);
      break;
    case HONEYPOT_DEL_SPAMMER:
      if (opt_verbose_net > 1) printf("[net: honeypot delete spammer: %x]\n", data);
      vec_del(&v_spam, data);
      break;
    case HONEYPOT_DEL_EVIL:
      if (opt_verbose_net > 1) printf("[net: honeypot delete evil: %x]\n", data);
      vec_del(&v_evil, data);
      break;
    case HONEYPOT_DEL_VULNERABLE:
      if (opt_verbose_net > 1) printf("[net: honeypot delete vulnerable: %x]\n", data);
      vec_del(&v_vuln, data);
      break;
    case HONEYPOT_PRINT:
      if (opt_verbose_net > 1) printf("[net: honeypot print request\n");
      do_print(m);
      break;
  }
}


void do_pkt()
{
  struct packet_header *hdr = (void *)pkt;
  vec_inc(&v_spam, ntohl(hdr->ip_source_address_big_endian));
  vec_inc(&v_vuln, ntohs(hdr->udp_dest_port_big_endian));
  vec_inc(&v_evil, djb2(pkt, pkt_len));
  npkts++;
  nbytes += len;
}

void process(struct evilpkt *evil)
{
  struct honeypot_command_packet *cmd = get_cmd();
  if (cmd)
    do_cmd(cmd, evil);
  else
    do_pkt();
}

int hit_comp(const void *p1, const void *p2) {
  const struct elt *e1 = p1;
  const struct elt *e2 = p2;
  return (e2->count - e1->count);
}

struct elt *do_sort(volatile struct vec *v)
{
  if (v->count == 0) return malloc(100);
  struct elt *e = malloc(v->count * sizeof(struct elt));
  memcpy(e, v->elt, v->count * sizeof(struct elt));
  qsort(e, v->count, sizeof(struct elt), hit_comp);
  return e;
}

void print_stats(unsigned int t_end)
{
  struct elt *es = do_sort(&v_spam);
  struct elt *ev = do_sort(&v_vuln);
  struct elt *ee = do_sort(&v_evil);
  int n = v_spam.count;
  if (n < v_vuln.count) n = v_vuln.count;
  if (n < v_evil.count) n = v_evil.count;
  printf("[net: actual honeypot statistics (assuming in-order packet processing)]\n");
  printf("%12s %11s   |  %12s %10s    |  %12s %s\n", "count", "spam_source", "count", "evil_hash", "count", "vuln_port");
  for (int i = 0; i < n; i++) {
    if (i >= v_spam.count) printf("%23s", i == v_spam.count && i == 0 ? "        empty        " : "");
    else printf("%12d 0x%08x", es[i].count, es[i].key);
    printf("    |  ");
    if (i >= v_evil.count) printf("%23s", i == v_evil.count && i == 0 ? "        empty        " : "");
    else printf("%12d 0x%08x", ee[i].count, ee[i].key);
    printf("    |  ");
    if (i >= v_vuln.count) printf("%23s", i == v_vuln.count && i == 0 ? "        empty        " : "");
    else printf("%12d 0x%04x", ev[i].count, ev[i].key);
    printf("\n");
  }
  free(es);
  free(ev);
  free(ee);
  unsigned int p = npkts;
  unsigned int b = nbytes;
  printf("[net: total packets: %d (%g pkts/sec)]\n", p, p * 1000000.0 / (t_start - t_end));
  printf("[net: total bytes: %d (%g Mbit/sec)]\n", b, b * 8.0 / (t_start - t_end));
}

void net_send_pkt() {

    //TODO: wait until you have to send the next packet



    //pick what kind of packet you want to send

    //check whether the count for spammer/evil/vulnerable is under our target

    int need_spam = (v_spam.count < v_spam.target) ? 1 : 0; 
    int need_evil = (v_evil.count < v_evil.target) ? 1 : 0; 
    int need_vuln = (v_vuln.count < v_vuln.target) ? 1 : 0; 

    //200 is our magic number
    int p_spam = need_spam ? 200 : 1;
    int p_evil = need_evil ? 200 : 1;
    int p_vuln = need_vuln ? 200 : 1;

    //p is a random number between 0 and 1023
    int rr = rand();
    int p = rr % 1024;
    rr /= 1024;
    struct evilpkt *evil = NULL;

    //if its time to print, send a print command
    time_t now = time(0);
    //TODO: need to define last_print somewhere 
    //print every ten seconds could also print every x packets
    if(difftime(now, *last_print) > 10) {
        //send HONEYPOT_PRINT 
        last_print = now; 
    } else if (p < p_spam) {
      if (need_spam || (rr & 1))
        fill_cmd(HONEYPOT_ADD_SPAMMER);
      else
        fill_cmd(HONEYPOT_DEL_SPAMMER);
    }  else if (p < p_spam + p_evil) {
      if (need_evil || (rr & 1))
        evil = fill_cmd(HONEYPOT_ADD_EVIL);
      else
        fill_cmd(HONEYPOT_DEL_EVIL);
    } else if (p < p_spam + p_evil + p_vuln) {
      if (need_vuln || (rr & 1))
        fill_cmd(HONEYPOT_ADD_VULNERABLE);
      else
        fill_cmd(HONEYPOT_DEL_VULNERABLE);
    } else {
      //not a command packet, try to match rates
      p = rand() % 1024;
      if (p < v_spam.probk) {
        //send a spam packet
        fill_rand(pkt, pkt_len, pick_rand(&v_spam), (unsigned short)(0xffff & rand()));
      } else if (p < v_spam.probk + v_evil.probk) {
        //send a evil packet
        struct evilpkt *evil = pick_randp(&v_evil);
        if (!evil) {
          //if there are no evil packets right now
          fill_rand(pkt, pkt_len, rand(), (unsigned short)(0xffff & rand()));
        } else {
          //send the evil packet
          pkt_len = evil->len;
          memcpy(pkt, evil->data, evil->len);
        }
      } else if (p < v_spam.probk + v_evil.probk + v_vuln.probk) {
        //send to a vulnerable port
        fill_rand(pkt, pkt_len, rand(), (unsigned short)pick_rand(&v_vuln));
      } else {
        //send a normal packet
        fill_rand(pkt, pkt_len, rand(), (unsigned short)(0xffff & rand()));
      }
    }
    process(evil);

    //TODO: send the packet over a raw socket
}

void net_advance(struct mips_machine *m)
{
  static int was_dropping;
  int wait;
  if (!(m->net_status & NET_S_CE) || !(m->net_status & NET_S_RX) || !m->net_dev->rx_capacity)
    return;
  t_start = m->core[0].data.COP[0].CPR[C0_CYCLES];
  if (m->net_next == 0) {
    wait = exp_rand(m->net_mean);
    if (m->opt_verbose_net > 4) printf("net: next packet will arrive in %d usec (mean inter-arrival is %g usec = %g sec)\n", wait, m->net_mean, m->net_mean/1000000);
    m->net_next = m->core[0].data.COP[0].CPR[C0_CYCLES] + wait * CPU_CYCLES_PER_USEC;
  } 
  while (m->core[0].data.COP[0].CPR[C0_CYCLES] >= m->net_next) {

    if (m->net_dev->rx_head != m->net_dev->rx_tail && 
  (m->net_dev->rx_head & (m->net_dev->rx_capacity-1)) == (m->net_dev->rx_tail & (m->net_dev->rx_capacity-1))) {
      // rx ring is full
      if (!was_dropping && m->opt_verbose_net)
  printf("net: rx ring is full: capacity=%d head=%d tail=%d\n", m->net_dev->rx_capacity, m->net_dev->rx_head, m->net_dev->rx_tail);

drop:
      if (!was_dropping && m->opt_verbose_net)
  printf("net: dropping packets\n");
      m->net_drops++;
      was_dropping = 1;
      goto out;
    }
    was_dropping = 0;

    // pick random packet contents
    int need_spam = (v_spam.count < v_spam.target) ? 1 : 0; 
    int need_evil = (v_evil.count < v_evil.target) ? 1 : 0; 
    int need_vuln = (v_vuln.count < v_vuln.target) ? 1 : 0; 

    int p_spam = need_spam ? 200 : 1;
    int p_evil = need_evil ? 200 : 1;
    int p_vuln = need_vuln ? 200 : 1;

    int rr = rand();
    int p = rr % 1024;
    rr /= 1024;
    struct evilpkt *evil = NULL;
    if (m->net_pkts - last_print_c > 1000 && m->core[0].data.COP[0].CPR[C0_CYCLES] - last_print_t > 10*1000000) {
      fill_cmd(m, HONEYPOT_PRINT);
    } else if (p < p_spam) {
      if (need_spam || (rr & 1)) fill_cmd(m, HONEYPOT_ADD_SPAMMER);
      else fill_cmd(m, HONEYPOT_DEL_SPAMMER);
    }  else if (p < p_spam + p_evil) {
      if (need_evil || (rr & 1)) evil = fill_cmd(m, HONEYPOT_ADD_EVIL);
      else fill_cmd(m, HONEYPOT_DEL_EVIL);
    } else if (p < p_spam + p_evil + p_vuln) {
      if (need_vuln || (rr & 1)) fill_cmd(m, HONEYPOT_ADD_VULNERABLE);
      else fill_cmd(m, HONEYPOT_DEL_VULNERABLE);
    } else {
      // not a control packet, try to match rates
      p = rand() % 1024;
      if (p < v_spam.probk) {
  fill_rand(m->net_pkt, &m->net_len, pick_rand(&v_spam), (unsigned short)(0xffff & rand()));
      } else if (p < v_spam.probk + v_evil.probk) {
  struct evilpkt *evil = pick_randp(&v_evil);
  if (!evil) {
    fill_rand(m->net_pkt, &m->net_len, rand(), (unsigned short)(0xffff & rand()));
  } else {
    m->net_len = evil->len;
    memcpy(m->net_pkt, evil->data, evil->len);
  }
      } else if (p < v_spam.probk + v_evil.probk + v_vuln.probk) {
  fill_rand(m->net_pkt, &m->net_len, rand(), (unsigned short)pick_rand(&v_vuln));
      } else {
  fill_rand(m->net_pkt, &m->net_len, rand(), (unsigned short)(0xffff & rand()));
      }
    }

    // try to put into ring
    unsigned int slot_paddr = m->net_dev->rx_base + 8*(m->net_dev->rx_head & (m->net_dev->rx_capacity-1));
    if (slot_paddr & 3 || pmem_type(m, slot_paddr) != DEV_TYPE_RAM ||
  pmem_type(m, slot_paddr+4) != DEV_TYPE_RAM) {
      if (m->opt_verbose_net)
  printf("network card: bus error for ring buffer physical address 0x%08x\n", slot_paddr);
      goto drop;
    }

    int err = 0;
    unsigned int *slot = (dereference_ram_page(&m->core[0], slot_paddr>>12, &err) + (slot_paddr & 0xfff));
    if (err) {
      if (m->opt_verbose_net)
  printf("network card: bus error for ring buffer slot physical address 0x%08x\n", slot_paddr);
      goto drop;
    }
    unsigned int dma_base = slot[0];
    unsigned int dma_len = slot[1];
    if (dma_len < m->net_len) {
      if (m->opt_verbose_net)
  printf("network card: packet truncation error (pkt is %d bytes, buffer is %d bytes)\n", m->net_len, dma_len);
      goto drop;
    }
    if (pmem_type(m, dma_base) != DEV_TYPE_RAM ||
  pmem_type(m, dma_base+m->net_len) != DEV_TYPE_RAM) {
      if (m->opt_verbose_net)
  printf("network card: bus error for packet physical address 0x%08x\n", dma_base);
      goto drop;
    }
    unsigned char *pmem = (dereference_ram_page(&m->core[0], dma_base>>12, &err) + (dma_base & 0xfff));
    if (err) {
      if (m->opt_verbose_net)
  printf("network card: bus error for packet physical address 0x%08x\n", dma_base);
      goto drop;
    }
    if (m->net_len > 4000) printf("ack!\n");
    memcpy(pmem, m->net_pkt, m->net_len);
    slot[1] = m->net_len;
    m->net_dev->rx_head++;
    m->net_pkts++;
    m->net_bytes += m->net_len;

    process(m, evil);

    unsigned int t_end = m->core[0].data.COP[0].CPR[C0_CYCLES];
    if (m->opt_verbose_net > 0 && m->opt_status && t_end - last_realprint_t >= m->opt_status) {
      print_stats(t_end);
      last_realprint_t = t_end;
    }

out:
    wait = exp_rand(m->net_mean);
    if (m->opt_verbose_net > 2) printf("net: next packet will arrive in %d usec (mean inter-arrival is %g usec = %g sec)\n", wait, m->net_mean, m->net_mean/1000000);
    m->net_next = m->core[0].data.COP[0].CPR[C0_CYCLES] + wait * CPU_CYCLES_PER_USEC;

  }
}

void network_init(struct mips_machine *m)
{
  m->net_dev = calloc(sizeof(struct dev_net), 1);
  m->net_avgsize = (_NET_MAXPKT-NET_MINPKT)/2;
  m->net_mean = 8*m->net_avgsize/(double)m->opt_mbps;
  m->net_pkt = calloc(NET_MAXPKT, 1);
  m->net_next = 0;
  m->net_status = 0;
  if (m->opt_verbose_net) printf("net: mean packet size is %d bytes (uniform)\n", m->net_avgsize);
  if (m->opt_verbose_net) printf("net: target throughput is %g Mbit/s\n", m->opt_mbps);
  if (m->opt_verbose_net) printf("net: mean packet inter-arrival time is %g usec (exponential)\n", m->net_mean);
  vec_init(&v_evil, 100, 20, 50);
  vec_init(&v_spam, 100, 30, 300);
  vec_init(&v_vuln, 100, 10, 100);
}
