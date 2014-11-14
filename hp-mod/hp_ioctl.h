#ifndef __HP_IOCTL_
#define __HP_IOCTL__


#define SRC_IP (0x01)
#define DST_IP (0x02)
#define SRC_P  (0x04)
#define DST_P  (0x08)
#define ENABLE_FLOW (0x10)
#define ACTION_DPI (0x20)
#define ACTION_CAP (0x40)
#define DPI_DROP_ON (0x80)

#define FLAG_IS_SET(x,y) (0 != (x & y))

#define HP_IOC_MAGIC       'p'

#define HP_FLOW_ENABLE     _IOW(HP_IOC_MAGIC, 0x1, struct sniffer_flow_entry)
#define HP_GET_RING        _IOW(HP_IOC_MAGIC, 0x1, struct sk_buff **)

#define HP_IOC_MAXNR   0x3

#define HP_ACTION_NULL     0x0
#define HP_ACTION_CAPTURE  0x1
#define HP_ACTION_DPI      0x2

#define HP_BUFFER_SIZE 4096

struct hp_pkt {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint8_t[64] hash;
};

#endif /* __SNIFFER_IOCTL__ */
