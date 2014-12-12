/*
 * sniffer skeleton (Linux kernel module)
 *
 * Copyright (C) 2014 Ki Suh Lee <kslee@cs.cornell.edu>
 * based on netslice implementation of Tudor Marian <tudorm@cs.cornell.edu>
 */
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/seq_file.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/textsearch.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

#include <hp_ioctl.h>
#include "sha256.h"

MODULE_AUTHOR("Maxwell Dergosits, Naman Agarwal, Rob McGuinness");
MODULE_DESCRIPTION("HoneyPi - A Distributed Honeypot for Raspberry Pis");
MODULE_LICENSE("Dual BSD/GPL");

static dev_t hp_dev;
static struct cdev hp_cdev;
static int hp_minor = 1;
atomic_t max_refcnt;

atomic_t refcnt;

static int hook_chain = NF_INET_PRE_ROUTING;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;

static spinlock_t buffer_lock;
static DECLARE_WAIT_QUEUE_HEAD(wait_for_pkt);

static struct hp_pkt pkt_buffer[HP_BUFFER_SIZE];
static unsigned long buf_head;
static unsigned long buf_tail;
static uint32_t ndropped = 0;


static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
  struct tcphdr *tcph = (void *) iph + iph->ihl*4;
  return tcph;
}

static inline struct udphdr * ip_udp_hdr(struct iphdr *iph)
{
  struct udphdr *udph = (void *) iph + iph->ihl*4;
  return udph;
}

static ssize_t
hp_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
  unsigned int index, to_copy;
  unsigned long flags;
  size_t remaining;
  ssize_t copied;

  if (!atomic_dec_and_test(&max_refcnt)){
    printk(KERN_ERR "Attempted to read honeypot when it was already being read\n");
    atomic_inc(&max_refcnt);
    return -EBUSY;
  }
  if (count < sizeof(struct hp_pkt)){
    printk(KERN_ERR "Buffer passed to hp_fs_read is too small\n");
    atomic_inc(&max_refcnt);
    return -EFAULT;  // Not sure what error to return here.
  }
  if (!access_ok(VERIFY_WRITE, buf, count)){
    printk(KERN_ERR "Buffer passed to hp_fs_read would segfault\n");
    atomic_inc(&max_refcnt);
    return -EFAULT;
  }
  if(wait_event_interruptible(wait_for_pkt, (buf_head-buf_tail) > 0)){
    atomic_inc(&max_refcnt);
    return -ERESTARTSYS;
  }

  copied = 0;
  spin_lock_irqsave(&buffer_lock, flags);
  if(buf_head - buf_tail > 0){
    remaining = count / sizeof(struct hp_pkt); // # of pkt_buffers we can give
    if(buf_head - buf_tail < remaining){
      remaining = buf_head - buf_tail;
    }

    index = buf_tail % HP_BUFFER_SIZE;

    while(remaining > 0){
      if(remaining > (HP_BUFFER_SIZE - index)){
        to_copy = HP_BUFFER_SIZE - index;
      }
      else{
        to_copy = remaining;
      }
      if(__copy_to_user(buf+copied, &pkt_buffer[index], to_copy * sizeof(struct hp_pkt))){
        spin_unlock_irqrestore(&buffer_lock, flags);
        atomic_inc(&max_refcnt);
        return -EFAULT;
      }
      buf_tail += to_copy;
      copied += to_copy * sizeof(struct hp_pkt);
      remaining -= to_copy;
    }
  }
  spin_unlock_irqrestore(&buffer_lock, flags);
  atomic_inc(&max_refcnt);
  return copied;
}

static int hp_fs_open(struct inode *inode, struct file *file)
{
  struct cdev *cdev = inode->i_cdev;
  int cindex = iminor(inode);

  if (!cdev) {
    printk(KERN_ERR "cdev error\n");
    return -ENODEV;
  }

  if (cindex != 0) {
    printk(KERN_ERR "Invalid cindex number %d\n", cindex);
    return -ENODEV;
  }

  return 0;
}

static int hp_fs_release(struct inode *inode, struct file *file)
{
  return 0;
}

static long hp_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  long err =0 ;
  if (_IOC_TYPE(cmd) != HP_IOC_MAGIC)
    return -ENOTTY;
  if (_IOC_NR(cmd) > HP_IOC_MAXNR)
    return -ENOTTY;
  if (_IOC_DIR(cmd) & _IOC_READ)
    err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
  if (_IOC_DIR(cmd) & _IOC_WRITE)
    err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
  if (err)
    return -EFAULT;

  return err;
}

static struct file_operations hp_fops = {
  .open = hp_fs_open,
  .release = hp_fs_release,
  .read = hp_fs_read,
  .unlocked_ioctl = hp_fs_ioctl,
  .owner = THIS_MODULE,
};

unsigned long djb2(unsigned char *str, int n)
{
  unsigned long hash = 5381;
  int c,i;
  for (i = 0; i < n; i++) {
    c = str[i];
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  }
  return hash;
}


static unsigned int hp_nf_hook(const struct nf_hook_ops *ops, struct sk_buff* skb,
    const struct net_device *indev, const struct net_device *outdev,
    int (*okfn) (struct sk_buff*))
{

  unsigned long flags;
  struct  honeypot_command_packet *cmd_hdr;
  size_t offset;
  struct tcphdr *tcph = NULL;
  struct udphdr *udph = NULL;
  struct iphdr  *iph = NULL;
  if (skb->data_len != 0){
    printk(KERN_ERR "sk_buff has paged data! dropping\n");
    return NF_DROP;
  }

  iph = ip_hdr(skb);
  if (iph->protocol == IPPROTO_TCP) {
    tcph = ip_tcp_hdr(iph);
  }
  if (iph->protocol == IPPROTO_UDP) {
    udph = ip_udp_hdr(iph);
  }

  spin_lock_irqsave(&buffer_lock, flags);
  if (buf_head-buf_tail != HP_BUFFER_SIZE){
    unsigned int index = buf_head % HP_BUFFER_SIZE;

    #ifdef DEBUG
      memset(&pkt_buffer[index],0x55,sizeof(struct hp_pkt));
    #endif
    cmd_hdr = (struct honeypot_command_packet*)(skb->data + sizeof(struct iphdr) + sizeof(struct udphdr));
    if ((skb->len >= sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct honeypot_command_packet))
      && (cmd_hdr->secret_big_endian == SECRET_BIGENDIAN)) {
        // we have a command packet unless the data is a hash put it in the source
        pkt_buffer[index].cmd = cmd_hdr->cmd_big_endian;
        if (cmd_hdr->cmd_big_endian == HONEYPOT_ADD_SPAMMER_BE ||
            cmd_hdr->cmd_big_endian == HONEYPOT_DEL_SPAMMER_BE) {
          pkt_buffer[index].src_ip = cmd_hdr->data_big_endian;
        } else if (cmd_hdr->cmd_big_endian == HONEYPOT_ADD_EVIL_BE
            || cmd_hdr->cmd_big_endian == HONEYPOT_DEL_EVIL_BE) {
          pkt_buffer[index].djb2_hash = cmd_hdr->data_big_endian;
          memcpy(&(pkt_buffer[index].hash),&(cmd_hdr->sha_hash),SHA_DIGEST_LENGTH);
        } else if (cmd_hdr->cmd_big_endian == HONEYPOT_ADD_VULNERABLE_BE
            || cmd_hdr->cmd_big_endian == HONEYPOT_DEL_VULNERABLE_BE) {
          pkt_buffer[index].src_ip = cmd_hdr->data_big_endian;
        }
    } else {
      pkt_buffer[index].src_ip = iph->saddr;
      pkt_buffer[index].dst_ip = iph->daddr;
      if(tcph != NULL){
        pkt_buffer[index].src_port = tcph->source;
        pkt_buffer[index].dst_port = tcph->dest;
      }
      if(udph != NULL){
        pkt_buffer[index].src_port = udph->source;
        pkt_buffer[index].dst_port = udph->dest;
      }
      pkt_buffer[index].protocol = iph->protocol;
      pkt_buffer[index].cmd = 0;
      offset = sizeof(struct iphdr) + sizeof(struct udphdr);
      pkt_buffer[index].djb2_hash = djb2(skb->data+offset,skb->len-offset);
      pkt_buffer[index].ndropped = ndropped;
      pkt_buffer[index].bytes = skb->len;
      //SHA256((unsigned char*)skb->data, (size_t)skb->len, (unsigned char *)&(pkt_buffer[index].hash));
    }
    buf_head++;
    wake_up_interruptible(&wait_for_pkt);
  } else {
    ndropped ++;
  }
  spin_unlock_irqrestore(&buffer_lock, flags);
  if ((udph != NULL && udph->dest == 0xA00F) || (tcph != NULL)) {
    return NF_ACCEPT;
  } else {
    return NF_DROP;
  }
}

static int __init hp_init(void)
{
  int status = 0;
  atomic_set(&refcnt,0);

  printk(KERN_DEBUG "hp_init\n");

  status = alloc_chrdev_region(&hp_dev, 0, hp_minor, "honeypi");
  if (status <0) {
    printk(KERN_ERR "alloc_chrdev_retion failed %d\n", status);
    goto out;
  }

  cdev_init(&hp_cdev, &hp_fops);
  status = cdev_add(&hp_cdev, hp_dev, hp_minor);
  if (status < 0) {
    printk(KERN_ERR "cdev_add failed %d\n", status);
    goto out_cdev;
  }
  spin_lock_init(&buffer_lock);
  atomic_set(&max_refcnt, 1);

  buf_head =0;
  buf_tail =0;
  /* register netfilter hook */
  memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
  nf_hook_ops.hook = hp_nf_hook;
  nf_hook_ops.pf = PF_INET;
  nf_hook_ops.hooknum = hook_chain;
  nf_hook_ops.priority = hook_prio;
  status = nf_register_hook(&nf_hook_ops);
  if (status < 0) {
    printk(KERN_ERR "nf_register_hook failed\n");
    goto out_add;
  }

  return 0;

out_add:
  cdev_del(&hp_cdev);
out_cdev:
  unregister_chrdev_region(hp_dev, hp_minor);
out:
  return status;
}

static void __exit hp_exit(void)
{

  if (nf_hook_ops.hook) {
    nf_unregister_hook(&nf_hook_ops);
    memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
  }
  cdev_del(&hp_cdev);
  unregister_chrdev_region(hp_dev, hp_minor);
}

module_init(hp_init);
module_exit(hp_exit);
