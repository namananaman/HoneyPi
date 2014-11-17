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

#include "sim.h"

void kbd_init(struct mips_machine *m)
{
  struct termios term;
  tcgetattr(fileno(m->opt_input), &term);
  term.c_lflag &= ~ICANON;
  tcsetattr(fileno(m->opt_input), TCSANOW, &term);
  setbuf(m->opt_input, NULL);
}

int kbd_has_input(struct mips_machine *m)
{
    int n;
    ioctl(fileno(m->opt_input), FIONREAD, &n);
    return n;
}

unsigned int kbd_read(struct mips_machine *m, unsigned int offset, int len)
{
  // offset 0 is the keyboard status port
  // offset 4 is the keyboard input port
  if (offset == 0) {
    // word read at 0 gets data from offset 3, 2, 1, 0,
    // half read at 0 gets data from offset 1, 0,
    // byte read at 0 gets data from offset 0
    return (kbd_has_input(m) ? 1 : 0); 
  } else if (offset == 4) {
    return (kbd_has_input(m) ? fgetc(m->opt_input) : 0);
  }

  return 0;
}

void console_init(struct mips_machine *m)
{

}

void console_write(struct mips_machine *m, unsigned int offset, int len, unsigned int value)
{
  // offset 0 is the console output port
  if (offset == 0) {
    // word write at 0 sends data to offset 3, 2, 1, 0,
    // half write at 0 sends data to offset 1, 0,
    // byte write at 0 sends data to offset 0
    putc(value & 0xff, m->opt_output);
    fflush(m->opt_output);
  }
}

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


void vec_init(volatile struct vec *v, int n, int target, int probk)
{
  v->elt = malloc(sizeof(struct elt) * n);
  v->count = 0;
  v->capacity = n;
  v->target = target;
  v->probk = probk;
}

void vec_add(volatile struct vec *v, unsigned int key, struct evilpkt *pkt)
{
  if (v->count < v->capacity) {
    v->elt[v->count].key = key;
    v->elt[v->count].pkt = pkt;
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
  }
  e[v->count].key = key;
  e[v->count].pkt = pkt;
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
void vec_del(volatile struct vec *v, unsigned int key)
{
  int n = v->count;
  for (int i = 0; i < n; i++) {
    if (v->elt[i].key != key) continue;
    void *old = v->elt[i].pkt;
    if (old) free(old);
    v->elt[i].pkt = NULL;
    if (i != n-1) {
      // deleting from middle of list
      v->elt[i].key = v->elt[n - 1].key;
      v->elt[i].pkt = v->elt[n - 1].pkt;
      v->elt[i].count = v->elt[n - 1].count;
    }
    v->count = v->count - 1;
    return;
  }
}

// safe for any to call
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

unsigned int exp_rand(double mean) {
  double r = (double)rand()/(double)RAND_MAX;
  double t = -mean * log(1-r);
  return (unsigned int)(t - 0.5);
}

unsigned int pick_rand(volatile struct vec *v)
{
  if (v->count == 0) return 0;
  int r = exp_rand(v->count / 4.0);
  if (r < 0) r = 0;
  else if (r >= v->count) r = v->count;
  return v->elt[r].key;
}

struct evilpkt *pick_randp(volatile struct vec *v)
{
  if (v->count == 0) return 0;
  int r = exp_rand(v->count / 4.0);
  if (r < 0) r = 0;
  else if (r >= v->count) r = v->count - 1;
  return v->elt[r].pkt;
}

unsigned int vec_has(volatile struct vec *v, unsigned int key)
{
  for (int i = 0; i < v->count; i++) 
    if (v->elt[i].key == key)
      return 1;
  return 0;
}

#define _NET_MAXPKT 2000

void fill_rand(unsigned char *data, unsigned int *net_len, unsigned int src_addr, unsigned short dst_port) {

    // pick a random packet length
    double r = (double)rand()/(double)RAND_MAX;
    unsigned int len = NET_MINPKT + (unsigned int)(r*(_NET_MAXPKT-NET_MINPKT));
    if (len < NET_MINPKT) len = NET_MINPKT;
    else if (len > _NET_MAXPKT) len = _NET_MAXPKT;
    *net_len = len;

    struct packet_header *p = (void *)data;
    p->ip_version = 0x45;
    p->ip_qos = 0;
    p->ip_len = htons(len);
    p->ip_id = htons((unsigned short)rand());
    p->ip_flags = 0;
    p->ip_ttl = 125;
    p->ip_protocol = 0x11;
    p->ip_checksum = 0;
    p->ip_source_address_big_endian = htonl(src_addr);
    p->ip_dest_address_big_endian = htonl(rand());

    p->udp_source_port_big_endian = htons((unsigned short)rand());
    p->udp_dest_port_big_endian = htons(dst_port);
    p->udp_len = htons(len - 20);
    p->udp_checksum = 0;

    for (int i = 28; i < len; i++)
      data[i] = (unsigned char)rand();

    if (len >= 28 + 4) {
      if (*(unsigned short *)(data+28) == ntohs(HONEYPOT_SECRET)
	  || *(unsigned short *)(data+28) == HONEYPOT_SECRET)
	*(unsigned short *)(data+28) = 0;
    }
}

struct evilpkt *fill_cmd(struct mips_machine *m, unsigned short cmd_id) {

    // pick a random packet length
    double r = (double)rand()/(double)RAND_MAX;
    unsigned int len = NET_MINPKT + (unsigned int)(r*(_NET_MAXPKT-NET_MINPKT));
    if (len < sizeof(struct honeypot_command_packet)) len = sizeof(struct honeypot_command_packet);
    else if (len > _NET_MAXPKT) len = _NET_MAXPKT;
    m->net_len = len;

    struct packet_header *p = (void *)m->net_pkt;
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
      m->net_pkt[i] = (unsigned char)rand();

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
	break;
      case HONEYPOT_ADD_VULNERABLE: 
	do {
	  data = rand() & 0xffff;
	} while (vec_has(&v_vuln, data));
	break;
      case HONEYPOT_DEL_SPAMMER:
	data = pick_rand(&v_spam);
	break;
      case HONEYPOT_DEL_EVIL:
	data = pick_rand(&v_evil);
	break;
      case HONEYPOT_DEL_VULNERABLE:
	data = pick_rand(&v_vuln);
	break;
    }
    cmd->data_big_endian = htonl(data);

    return evil;
}

struct honeypot_command_packet *get_cmd(struct mips_machine *m)
{
  if (m->net_len < sizeof(struct honeypot_command_packet))
    return 0;
  struct honeypot_command_packet *cmd = (void *)m->net_pkt;
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

static int last_print_t;
static int last_print_c;
static int last_realprint_t;
static int t_start;

void do_print(struct mips_machine *m)
{
  last_print_t = m->core[0].data.COP[0].CPR[C0_CYCLES];
  last_print_c = m->net_pkts;
}

void do_cmd(struct mips_machine *m, struct honeypot_command_packet *cmd, struct evilpkt *evil)
{
  unsigned int data = ntohl(cmd->data_big_endian);
  switch(ntohs(cmd->cmd_big_endian)) {
    case HONEYPOT_ADD_SPAMMER: 
      if (m->opt_verbose_net > 1) printf("[net: honeypot add spammer: %x]\n", data);
      vec_add(&v_spam, data, NULL);
      break;
    case HONEYPOT_ADD_EVIL:
      if (m->opt_verbose_net > 1) printf("[net: honeypot add evil: %x]\n", data);
      if (!evil) printf("simulator warning: internal error 0xeb11\n");
      else vec_add(&v_evil, data, evil);
      break;
    case HONEYPOT_ADD_VULNERABLE:
      if (m->opt_verbose_net > 1) printf("[net: honeypot add vulnerable: %x]\n", data);
      vec_add(&v_vuln, data, NULL);
      break;
    case HONEYPOT_DEL_SPAMMER:
      if (m->opt_verbose_net > 1) printf("[net: honeypot delete spammer: %x]\n", data);
      vec_del(&v_spam, data);
      break;
    case HONEYPOT_DEL_EVIL:
      if (m->opt_verbose_net > 1) printf("[net: honeypot delete evil: %x]\n", data);
      vec_del(&v_evil, data);
      break;
    case HONEYPOT_DEL_VULNERABLE:
      if (m->opt_verbose_net > 1) printf("[net: honeypot delete vulnerable: %x]\n", data);
      vec_del(&v_vuln, data);
      break;
    case HONEYPOT_PRINT:
      if (m->opt_verbose_net > 1) printf("[net: honeypot print request\n");
      do_print(m);
      break;
  }
}


void do_pkt(struct mips_machine *m)
{
  struct packet_header *hdr = (void *)m->net_pkt;
  vec_inc(&v_spam, ntohl(hdr->ip_source_address_big_endian));
  vec_inc(&v_vuln, ntohs(hdr->udp_dest_port_big_endian));
  vec_inc(&v_evil, djb2(m->net_pkt, m->net_len));
  npkts++;
  nbytes += m->net_len;
}

void process(struct mips_machine *m, struct evilpkt *evil)
{
  struct honeypot_command_packet *cmd = get_cmd(m);
  if (cmd)
    do_cmd(m, cmd, evil);
  else
    do_pkt(m);
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

int net_has_input(struct mips_machine *m)
{
  if (!(m->net_status & NET_S_CE)) return 0;
  net_advance(m);
  if (!(m->net_status & NET_S_IE)) return 0;
  int non_empty = (m->net_dev->rx_head != m->net_dev->rx_tail);
  static int prev = -1;
  if (non_empty != prev && m->opt_verbose_net > 4) {
    printf("net: interrupt pending? %s\n", non_empty ? "yes" : "no");
    prev = non_empty;
  }
  return non_empty;
}


unsigned int network_read(struct mips_machine *m, unsigned int offset, int len)
{
  if (offset >= sizeof(struct dev_net)) {
    if (m->opt_verbose_net) printf("net: invalid read address\n");
    return 0;
  }
  switch(len) {
    case 4: return ((unsigned int *)m->net_dev)[offset>>2];
    case 2: return ((unsigned short *)m->net_dev)[offset>>1];
    case 1: return ((unsigned char *)m->net_dev)[offset>>0];
  }
  return 0;
}

void network_write(struct mips_machine *m, unsigned int offset, int len, unsigned int value)
{
  if (offset >= sizeof(struct dev_net)) {
    if (m->opt_verbose_net) printf("net: invalid write address\n");
    return;
  }
  switch(len) {
    case 4: ((unsigned int *)m->net_dev)[offset>>2] = value; break;
    case 2: ((unsigned short *)m->net_dev)[offset>>1] = (unsigned short)value; break;
    case 1: ((unsigned char *)m->net_dev)[offset>>0] = (unsigned char)value; break;
  }
  if (offset == offsetof(struct dev_net, cmd)) {
    switch(m->net_dev->cmd) {
      case NET_GET_POWER: m->net_dev->data = (m->net_status & NET_S_CE) ? 1 : 0; break;
      case NET_GET_RECEIVE: m->net_dev->data = (m->net_status & NET_S_RX) ? 1 : 0; break;
      //case NET_GET_TRANSMIT: m->net_dev->data = (m->net_status & NET_S_TX) ? 1 : 0; break;
      case NET_GET_INTERRUPTS: m->net_dev->data = (m->net_status & NET_S_IE) ? 1 : 0; break;
      case NET_GET_DROPCOUNT: m->net_dev->data = m->net_drops; break;
      case NET_SET_POWER:
      case NET_SET_RECEIVE:
      case NET_SET_INTERRUPTS:
	break;
      default:
	m->net_dev->data = 0;
	if (m->opt_verbose_net) printf("net: invalid command\n");
	break;
    }
  } else if (offset == offsetof(struct dev_net, data)) {
    switch(m->net_dev->cmd) {
      case NET_SET_POWER:
	if (m->net_dev->data) {
	  if (m->opt_verbose_net > 1) printf("net: power on\n");
	  m->net_status |= NET_S_CE;
	} else {
	  m->net_next = 0;
	  m->net_status &= ~NET_S_CE;
	  if (m->opt_verbose_net > 1) printf("net: power off\n");
	}
	break;
      case NET_SET_RECEIVE:
	if (m->net_dev->data) {
	  if (m->opt_verbose_net > 1) printf("net: receive on\n");
	  m->net_next = 0;
	  m->net_status |= NET_S_RX;
	} else {
	  m->net_next = 0;
	  m->net_status &= ~NET_S_RX;
	  if (m->opt_verbose_net > 1) printf("net: receive off\n");
	}
	break;
      /*case NET_SET_TRANSMIT:
	if (m->net_dev->data) m->net_status |= NET_S_TX; else m->net_status &= ~NET_S_TX;
	break; */
      case NET_SET_INTERRUPTS:
	if (m->net_dev->data) {
	  if (m->opt_verbose_net > 1) printf("net: interrupts on\n");
	  m->net_status |= NET_S_IE;
	} else {
	  m->net_status &= ~NET_S_IE;
	  if (m->opt_verbose_net > 1) printf("net: interrupts off\n");
	}
	break;
      default:
	if (m->opt_verbose_net) printf("net: ignoring write after read-only command\n");
	break;
    }
  } else if (offset == offsetof(struct dev_net, rx_capacity)) {
    // round down to power of 2, at most 16
    int i;
    for (i = 1; i <= NET_MAX_RING_CAPACITY; i *= 2)
      if (m->net_dev->rx_capacity < i) break;
    m->net_dev->rx_capacity = i/2;
    if (m->opt_verbose_net > 2) printf("net: rx_capacity set to %d\n", m->net_dev->rx_capacity);
  } else if (offset == offsetof(struct dev_net, rx_head)) {
    if (m->opt_verbose_net > 2) printf("net: rx_head set to %d\n", m->net_dev->rx_head);
  } else if (offset == offsetof(struct dev_net, rx_tail)) {
    if (m->opt_verbose_net > 2) printf("net: rx_tail set to %d\n", m->net_dev->rx_tail);
  } else if (offset == offsetof(struct dev_net, rx_base)) {
    if (m->opt_verbose_net > 2) printf("net: rx_base set to 0x%08x\n", m->net_dev->rx_base);
  }
}

void check_devices(struct mips_machine *m)
{
  int pending = 0;
  if (kbd_has_input(m))
    pending |= (1 << INTR_KEYBOARD);
  if (net_has_input(m))
    pending |= (1 << INTR_NETWORK);

  int cause = m->core[0].data.COP[0].CPR[C0_CAUSE];
  m->core[0].data.COP[0].CPR[C0_CAUSE] = (cause & ~0xff00) | (pending << 8);
}

