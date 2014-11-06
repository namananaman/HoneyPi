#ifndef __SNIFFER_IOCTL_
#define __SNIFFER_IOCTL__


#define SRC_IP (0x01)
#define DST_IP (0x02)
#define SRC_P  (0x04)
#define DST_P  (0x08)
#define ENABLE_FLOW (0x10)
#define ACTION_DPI (0x20)
#define ACTION_CAP (0x40)
#define DPI_DROP_ON (0x80)

#define FLAG_IS_SET(x,y) (0 != (x & y))

struct sniffer_flow_entry {
  int32_t src_ip;
  int32_t dst_ip;
  int32_t src_port;
  int32_t dst_port;
  char flags;
};

#define SNIFFER_IOC_MAGIC       'p'

#define SNIFFER_FLOW_ENABLE     _IOW(SNIFFER_IOC_MAGIC, 0x1, struct sniffer_flow_entry)
#define SNIFFER_FLOW_DISABLE    _IOW(SNIFFER_IOC_MAGIC, 0x2, struct sniffer_flow_entry)

#define SNIFFER_IOC_MAXNR   0x3


#define SNIFFER_ACTION_NULL     0x0
#define SNIFFER_ACTION_CAPTURE  0x1
#define SNIFFER_ACTION_DPI      0x2

#endif /* __SNIFFER_IOCTL__ */
