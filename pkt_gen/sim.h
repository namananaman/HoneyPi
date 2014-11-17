#ifndef SIM_H
#define SIM_H

#include <stdio.h>
#include <setjmp.h>
#include <openssl/sha.h>


/* beginning of student-visible */

/* Kernel entry point has the following signature. It should never return. */
void __boot();

/* We are simulating a 1 MHz machine,
 * so 1,000,000 cycles per second,
 * or 1 cycle per usec,
 * or 1 usec per cycle.
 */
#define CPU_MHZ 1
#define CPU_CYCLES_PER_SECOND 1000000
#define CPU_CYCLES_PER_USEC 1
#define CPU_USEC_PER_CYCLES 1

/* Everything uses a 4k page size */
#define PAGE_SIZE 4096

/* Physical Address Space Layout 
 * =============================================================================
 *
 * The first page of the physical address space (physical address 0x00000000)
 * contains a block of boot parameters.  These consist of:
 *  - the device table, showing the layout of the physical address space
 *  - a count of RAM pages used by the bootloader
 *  - boot parameters passed on the simulator command line
 *
 * The boot parameters is just a list of fixed-length strings.
 *
 * The device table is a list of up to 16 entries. Each entry specifies a range
 * of physical addresses, and a type and model code indicating what lives at those
 * addresses. By default, 128 MB of RAM is simulated, but this can be changed on
 * the command line (up to 1GB). The default device table specifies a physical address space
 * layout that looks like this:
 *
 *  +--------------------+ 
 *  |                    | 0x00004000 + N * 4096 - 1
 *  |                    |
 *  |                    |
 *  |                    |
 *  |   RAM              | 0x00004000
 *  +--------------------+ 
 *  |                    | 0x00003FFF
 *  |                    |
 *  |                    | 
 *  |   network I/O      | 0x00003000
 *  +--------------------+ 
 *  |                    | 0x00002FFF
 *  |                    |
 *  |                    |
 *  |   console I/O      | 0x00002000
 *  +--------------------+ 
 *  |                    | 0x00001FFF
 *  |                    |
 *  |                    |
 *  |   keyboard I/O     | 0x00001000
 *  +--------------------+ 
 *  |                    | 0x00000FFF
 *  |   ROM (boot        |
 *  |      parameters)   | 
 *  |                    | 0x00000000
 *  +--------------------+ 
 *
 */
struct device_table_entry {
#define DEV_TYPE_EMPTY	   0x0000
#define DEV_TYPE_ROM	   0x0001
#define DEV_TYPE_RAM	   0x0003
#define DEV_TYPE_KEYBOARD  0x2210
#define DEV_TYPE_CONSOLE   0x1610
#define DEV_TYPE_NETWORK   0x3410
  unsigned int type;
  unsigned int model;
  unsigned int start; // inclusive
  unsigned int end;   // exclusive
};

struct bootparams {
  struct device_table_entry devtable[16]; // up to 16 device table entries
  unsigned int bootpages; // count of pages used by bootloader
  char argdata[16][128]; // up to 16 arguments, 127 characters each
};


/* Keyboard Device
 * =============================================================================
 */

struct dev_kbd {
  char status, pad1, pad2, pad3;
  char data, pad4, pad5, pad6;
};


/* Console Device
 * =============================================================================
 */

struct dev_console {
  char data, pad1, pad2, pad3;
};


/* Network Device
 * =============================================================================
 */

struct dev_net {
  unsigned int cmd;
  unsigned int data;
  unsigned int rx_base;
  unsigned int rx_capacity;
  unsigned int rx_head;
  unsigned int rx_tail;
  // tx ring omitted (you don't need it anyway)
};

struct dma_ring_slot {
  unsigned int dma_base;
  unsigned int dma_len;
};

#define NET_MAX_RING_CAPACITY 16 // ring capacity must be a power of 2, at most 16

#define NET_MINPKT 28   // the smallest packet contains only IP/UDP headers
#define NET_MAXPKT 4000 // the largest packet easily fits within a single page

#define NET_SET_POWER      0x101 /* 1 to data turns on card, 0 turns off */
#define NET_SET_RECEIVE    0x102 /* 1 to data turns on reception DMA, 0 turns off */
//#define NET_SET_TRANSMIT   0x103 /* 1 to data turns on transmission DMA, 0 turns off */
#define NET_SET_INTERRUPTS 0x104 /* 1 to data turns on receive interrupts, 0 turns off */

#define NET_GET_POWER      0x201 /* 1 from data means card is turned on */
#define NET_GET_RECEIVE    0x202 /* 1 from data means reception is turned on */
//#define NET_GET_TRANSMIT   0x203 /* 1 from data means transmission is turned on */
#define NET_GET_INTERRUPTS 0x204 /* 1 from data means receive interrupts are turned on */
#define NET_GET_DROPCOUNT  0x205 /* <n> from data means <n> received packets were dropped */


/* Virtual Address Space Layout 
 * =============================================================================
 *
 * The simulator implements a hardware virtual memory system that is a mix
 * of MIPS and a classic x86 system, with some modifications and simplifications. 
 *
 * The hardware uses a two level page table structure, as follows:
 * The Context Register (c0r4) contains a pointer to a 4096-byte page directory.
 * Each of the 4-byte page directory entries (PDEs) points to a 4096-byte page table.
 * Each of the 4-byte page table entries (PTEs) points to a 4096-byte page of data.
 * 
 * And address space is denoted by a 32-bit value suitable for writing into the
 * Context Register, which has the following format:
 * +----------------------------------------+---------------------+
 * |    physical page number                |     reserved        |
 * +----------------------------------------+---------------------+
 *    The upper 20 bits contain the physical page number of the page directory.
 *    The lower bits are reserved, and must be always be zero.
 *
 * A PDE has the following format:
 * +----------------------------------------+-----------------+---+
 * |    physical page number                |     unused      | V |
 * +----------------------------------------+-----------------+---+
 *    The upper 20 bits contain the physical page number of the page table.
 *    The low bit is 1 for "valid", or 0 for "invalid" .
 *    Other bits are ignored by the hardware, and so can be used for anything you like.
 *
 * A PTE has the following format:
 * +----------------------------------------+------+---+---+---+---+
 * |    physical page number                |unused| C | X | W | V |
 * +----------------------------------------+------+---+---+---+---+
 *    The upper 20 bits contain the physical page number of the page containing data.
 *    The low bits indicate "cache-disable", "executable", "writable", and
 *    "valid", respectively.
 *    Other bits are ignored by the hardware, and so can be used for anything you like.
 *
 * For sanity's sake, the simulator enforces a few additional restriction: all
 * pagetables must reside in RAM; the stack should reside in RAM; execution
 * should never happen on non-RAM pages; etc. The simulator will halt with an
 * error message if any of these restrictions are broken, e.g. if the Context
 * Register or any of the PDEs points at a non-RAM physical page.
 *
 * The simulator sets up some page tables for you before invoking the kernel's
 * entry point.  The default mappings are reasonable, but you can modify the
 * page tables however you like at any time (so long as you are careful about
 * modifying mappings that are being used, e.g. the ones that used to map the
 * kernel's code segment).
 *
 * The default mappings are created as follows. Every physically addressable
 * page mapped into the virtual address space starting at address 0xC0000000.
 * There is at most 1GB of physical addressable memory, so all of physical
 * memory fits in the range 0xC0000000 to 0xFFFFFFFF.  All of these pages
 * are created with W=1, X=0 permissions, except the ROM page, which has W=0,
 * X=0. Device pages have C=1, all others have C=0.
 *
 * Additional mappings are created for the kernel code, data, as specified in
 * the kernel ELF file. For instance, the kernel ELF file has a code segment
 * near virtual 0x80000000, so a few RAM pages are mapped a second time at this
 * address. 
 *
 * A few more pages are mapped somewhere below 0xC0000000 for a kernel stack
 * for each core. Each core will need to allocate its own trap stack.
 *
 * The total number of physical RAM pages used for this is written into the boot
 * parameter block. This count includes some number of pages for the kernel
 * code, data, and stack, plus additional pages for the pagetables.
 */


/* TLB Organization
 * =============================================================================
 *
 * The simulator does not implement a TLB. 
 */


/* Cache Organization
 * =============================================================================
 *
 * Both instruction fetch and data are assumed to use an infinitely large cache
 * with zero latency and perfect hardware cache coherence. Thus for this project,
 * you need not think about cache issues, with one exception: pages used for
 * memory-mapped device I/O should be marked as "cache-disable".
 */

enum {
  ECODE_INT = 0,  /* external interrupt */
  ECODE_MOD,	  /* attempt to write to a non-writable page */
  ECODE_TLBL,	  /* page fault during load or instruction fetch */
  ECODE_TLBS,	  /* page fault during store */
  ECODE_ADDRL,	  /* unaligned address during load or instruction fetch */
  ECODE_ADDRS,	  /* unaligned address during store */
  ECODE_IBUS,	  /* instruction fetch bus error */
  ECODE_DBUS,	  /* data load/store bus error */
  ECODE_SYSCALL,  /* system call */
  ECODE_BKPT,	  /* breakpoint */
  ECODE_RI,	  /* reserved opcode */
  ECODE_OVF,	  /* arithmetic overflow */
  ECODE_NOEX,	  /* attempt to execute to a non-executable page */
};

enum {
  INTR_SW0 = 0,
  INTR_SW1,
  INTR_HW0,
  INTR_HW1,
  INTR_HW2,
  INTR_NETWORK,
  INTR_KEYBOARD,
  INTR_TIMER,
};

/* end of student-visible */

enum {
  ECODE_FATAL = -1/* internal to simulator */
};


struct mips_coprocessor_data {
  union {
    /* Coprocessor General Purpose Registers for COP0, COP2, and COP3 */
    unsigned int CPR[32];
    /* Floating-point Registers for COP1 */
    union {
      float FGR[16]; /* seen as 16 single-precision numbers */
      double FPR[8]; /* seen as 8 double-precision numbers */
      int FWR[16];   /* seen as 16 integers */
    };
  };
  /* Coprocessor Control Registers */
  unsigned int CCR[32];
  /* Coprocessor Condition Code */
  unsigned int CpCond;
  /* padding to make the entire struct 8-byte aligned */
  unsigned int padding; 
};

struct mips_core_data {
  /* General Purpose Registers */
  unsigned int R[32];
  /* Registers used by integer multiplication and division */
  unsigned int LO, HI;
  /* Current and next program counter */
  unsigned int PC, nPC;
  /* Coprocessor state */
  struct mips_coprocessor_data COP[4];
}; // __attribute__ ((packed));

/* for debugging */
struct segment {
  unsigned int vaddr, size;
  char *type;
  void *data;
};
#define MAX_SEGMENTS 40
#define STACK_SIZE (4*4096)
#define RAM_START_PAGE 10

enum {
  REG_0,  REG_AT, REG_V0, REG_V1, REG_A0, REG_A1, REG_A2, REG_A3,
  REG_T0, REG_T1, REG_T2, REG_T3, REG_T4, REG_T5, REG_T6, REG_T7,
  REG_S0, REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
  REG_T8, REG_T9, REG_K0, REG_K1, REG_GP, REG_SP, REG_FP, REG_RA
};

enum {
  C0_CONTEXT = 4, C0_BADVADDR = 8, C0_CYCLES, C0_STATUS = 13, C0_CAUSE, C0_EPC
};

enum {
  C2_ID = 16, C2_CE, C2_CX
};


struct breakpoint {
  int id;
  unsigned int vaddr;
  struct breakpoint *next;
};

struct mips_machine;

struct mips_core {
  int id;
  struct breakpoint *breakpoints;
  int break_skip;
  int opt_disassemble;

  struct mips_machine *mach;

  struct segment *stack;

  int LLbit;
  unsigned int LLvaddr, LLpaddr;
  struct mips_core_data data;
};

struct mips_machine {
  // debug
  int opt_verbose_boot;
  int opt_verbose_mmu;
  int opt_verbose_llsc;
  int opt_verbose_net;
  int opt_verbose_trap;
  int opt_dumpreg;
  int opt_printstack;
  int opt_status;
  int opt_fatal;
  struct breakpoint *breakpoints;
  // multi-core
  int opt_cores;
  int cores_mask;
  // mem
  int opt_pages;
  // kbd and console i/o
  char *opt_input_file, *opt_output_file;
  FILE *opt_input, *opt_output;
  // net i/o
  double opt_mbps;
  double net_mean; /* mean inter-arrival time in usec */
  unsigned char *net_pkt;
  int net_next;
  unsigned int net_len, net_avgsize;
  struct dev_net *net_dev;
  unsigned int net_status, net_drops, net_pkts, net_bytes;
  // bootparams
  int opt_ac;
  char **opt_av;

  char *elf_filename;

  unsigned long long elapsed; // elapsed time in nanoseconds
 
  unsigned char *pmem;
  struct segment mem[MAX_SEGMENTS]; // debug, mostly
  unsigned int entry_point, gp, default_context;
  struct bootparams *boot;

  struct mips_core *core;
  int current_core;
};


struct mips_machine *create_mips_machine(void);

void allocate_stack(struct mips_core *m);
void reset_core(struct mips_core *m);
void free_segments(struct mips_machine *m);
struct segment *allocate_segment(struct mips_machine *m, unsigned int vaddr, unsigned int size, int writeable, int executable, char *type);

void mmu_xlate(struct mips_core *m, unsigned int vaddr, int alignment, int write, int exec, unsigned int *_type, unsigned int *_ppn, unsigned int *_offset);

void dump_segments(struct mips_machine *m);
void dump_registers(struct mips_core *m);
void dump_stack(struct mips_core *m, int count);
void dump_disassembly(FILE *out, unsigned int pc, unsigned int inst);
void dump_mem(struct mips_core *m, unsigned int addr, int count, int size, int phys);

unsigned int mem_read_word(struct mips_core *m, unsigned int vaddr);
unsigned int mem_read_word_x(struct mips_core *m, unsigned int vaddr);
unsigned short mem_read_half(struct mips_core *m, unsigned int vaddr);
unsigned char mem_read_byte(struct mips_core *m, unsigned int vaddr);

void mem_write_word(struct mips_core *m, unsigned int vaddr, unsigned int value);
void mem_write_half(struct mips_core *m, unsigned int vaddr, unsigned short value);
void mem_write_byte(struct mips_core *m, unsigned int vaddr, unsigned char value);

void readelf(struct mips_machine *m, char *filename);

void multicore_init(struct mips_machine *m);

void pmem_init(struct mips_machine *m);
void pmem_reset(struct mips_machine *m);
unsigned int pmem_type(struct mips_machine *m, unsigned int paddr);

void vmem_init(struct mips_machine *m);

// these do not trap, they generate fatal errors instead
void _mem_write(struct mips_machine *m, unsigned int vaddr, char *buf, int len, int *err);
unsigned int _mem_read_word(struct mips_core *m, unsigned int vaddr, int *err);
unsigned short _mem_read_half(struct mips_core *m, unsigned int vaddr, int *err);
unsigned char _mem_read_byte(struct mips_core *m, unsigned int vaddr, int *err);

void *dereference_ram_page(struct mips_core *m, unsigned int ppn, int *err);

enum { RUN_OK=0, RUN_BREAK=1, RUN_BREAKPOINT=2, RUN_TRAP=3, RUN_FATAL=4, RUN_EXIT=5 };
int run(struct mips_machine *m, int count);
void interactive_debug(struct mips_machine *m);
int is_breakpoint(struct mips_core *m, unsigned int vaddr);

void set_bootparams(struct mips_machine *m);

void kbd_init(struct mips_machine *m);
unsigned int kbd_read(struct mips_machine *m, unsigned int offset, int len);
void console_init(struct mips_machine *m);
void console_write(struct mips_machine *m, unsigned int offset, int len, unsigned int value);
void network_init(struct mips_machine *m);
unsigned int network_read(struct mips_machine *m, unsigned int offset, int len);
void network_write(struct mips_machine *m, unsigned int offset, int len, unsigned int value);
void check_devices(struct mips_machine *m);

void trap(struct mips_core *m, unsigned int ecode, unsigned int badvaddr, char *msg, ...) __attribute__ ((noreturn));
extern jmp_buf err_handler;

void show_exit_status(struct mips_machine *m, int err);

#define SIGNEX(X) (((X) & 0x8000) ? ((X) | 0xffff0000) : (X))
#define NEG(X) (((X) & 0x80000000) != 0)

enum { /* MIPS R2000/3000 Instructions */
  SPECIAL, REGIMM, J, JAL, BEQ, BNE, BLEZ, BGTZ, ADDI, ADDIU, SLTI,
  SLTIU, ANDI, ORI, XORI, LUI, COP0, COP1, COP2, COP3,
  LB=32, LH, LWL, LW, LBU, LHU, LWR,
  SB=40, SH, SWL, SW, SWR=46,
  LL=48, LWC1, LWC2, LWC3,
  SC=56, SWC1, SWC2, SWC3
};

enum { /* SPECIAL function */
  SLL, SRL=2, SRA, SLLV, SRLV=6, SRAV,
  JR, JALR, SYSCALL=12, BREAK,
  MFHI=16, MTHI, MFLO, MTLO,
  MULT=24, MULTU, DIV, DIVU,
  ADD=32, ADDU, SUB, SUBU, AND, OR, XOR, NOR,
  SLT=42, SLTU
};

enum { BLTZ, BGEZ, BLTZAL=16, BGEZAL}; /* REGIMM rt */
enum { MF=0, CF=2, MT=4, CT=6, BC=8, COa=16, COb=24, FF_S=16, FF_D, FF_W=20 }; /* COPz rs */
enum { ERET=24, WAIT=32 }; /* COPz CO function */
enum { S = 0, D, DUMMY1, DUMMY2, W }; /* COPz res */
enum { BCF, BCT }; /* COPz rt */

enum { /* MIPS R2010/3010 Floating Point Unit */
  FADD, FSUB, FMUL, FDIV, FABS=5, FMOV, FNEG,
  FCVTS=32, FCVTD, FCVTW=36,
  C_F=48, CUN, CEQ, CUEQ, COLT, CULT, COLE, CULE,
  CSF, CNGLE, CSEQ, CNGL,  CLT, CNGE,  CLE, CNGT
};

#define STATUS_IE  0x00000001
#define STATUS_EXL 0x00000002
#define STATUS_IM  0x0000ff00

#define CAUSE_ECODE 0x0000007c
#define CAUSE_IP    0x0000ff00
#define CAUSE_BD    0x80000000

#define E_VECTOR 0x80000180

enum {COND_UN=0x1, COND_EQ=0x2, COND_LT=0x4, COND_IN=0x8}; /* FP cond */

// Layout of network packet IP and UDP headers
struct packet_header {
  // IP layer headers: 20 bytes
  // You only care about 'source address'.
  unsigned char ip_version;
  unsigned char ip_qos;
  unsigned short ip_len;
  unsigned short ip_id;
  unsigned short ip_flags;
  unsigned char ip_ttl;
  unsigned char ip_protocol;
  unsigned short ip_checksum;
  unsigned int ip_source_address_big_endian; // 'source address' in big-endian order
  unsigned int ip_dest_address_big_endian;

  // UDP layer headers: 8 bytes
  // You only care about 'destination port'.
  unsigned short udp_source_port_big_endian;
  unsigned short udp_dest_port_big_endian; // 'destination port' in big-endian order
  unsigned short udp_len;
  unsigned short udp_checksum;
};

// Layout of a honeypot command packet
struct honeypot_command_packet {
  struct packet_header headers;

  unsigned short secret_big_endian;
  unsigned short cmd_big_endian;
  unsigned int data_big_endian;
  unsigned char sha_hash[SHA256_DIGEST_LENGTH];
};

#define HONEYPOT_SECRET 0x3410

#define HONEYPOT_ADD_SPAMMER    0x101
#define HONEYPOT_ADD_EVIL       0x102
#define HONEYPOT_ADD_VULNERABLE 0x103

#define HONEYPOT_DEL_SPAMMER    0x201
#define HONEYPOT_DEL_EVIL       0x202
#define HONEYPOT_DEL_VULNERABLE 0x203

#define HONEYPOT_PRINT		0x301

#endif // SIM_H
