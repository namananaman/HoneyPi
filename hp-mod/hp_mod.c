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
#include <linux/proc_fs.h>
#include<linux/sched.h>
#include <asm/uaccess.h>

#include <hp_ioctl.h>

DECLARE_WAIT_QUEUE_HEAD(wq);
MODULE_AUTHOR("Maxwell Dergosits, Naman Agarwal, Rob McGuinness");
MODULE_DESCRIPTION("HoneyPi - A Distributed Honeypot for Raspberry Pis");
MODULE_LICENSE("Dual BSD/GPL");


static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
atomic_t refcnt;

static int hook_chain = NF_INET_LOCAL_IN;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;


// skb buffer between kernel and user space
struct list_head skbs;

// skb wrapper for buffering
struct skb_list
{
  struct list_head list;
  struct sk_buff *skb;
  int offset;
};



static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
  struct tcphdr *tcph = (void *) iph + iph->ihl*4;
  return tcph;
}

char * packet_data =NULL;
size_t packet_size;
int packet_offset;
char packet_availble;

char buffer_is_empty(void) {
  char empty;
  unsigned long flags;
  local_irq_save(flags);
  empty = list_empty(&skbs);
  if(empty) packet_availble = 0;
  local_irq_restore(flags);
  return empty;
}

/* From kernel to userspace */
/* this will only work if there if buf is large enough to hold all the packe information*/
  static ssize_t
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
  struct skb_list * first;
  struct sk_buff *skb;
  struct tcphdr *tcph;
  struct iphdr *iph;
  int left;
  int len; unsigned long flags;

  if(atomic_read(&refcnt) > 0) { return -EBUSY; }
  atomic_add(1,&refcnt);

  while(buffer_is_empty() && !packet_data) {
    wait_event_interruptible(wq,packet_availble!=0);
    len = 0;
  }
  if (!packet_data) {
    //spin_lock(&buffer_lock); {
    packet_offset = 0;
    local_irq_save(flags);
    first  = list_first_entry(&skbs, struct skb_list, list);
    skb = first->skb;
    iph = ip_hdr(skb);
    tcph = ip_tcp_hdr(iph);
    packet_size = skb->len;
    packet_data =kmalloc(packet_size,GFP_ATOMIC);

    if(skb_copy_bits(skb,0,packet_data,packet_size)) {
    }
    list_del(&first->list);
    local_irq_restore(flags);
    kfree_skb(skb);
    kfree(first);
  }

  if (packet_size == packet_offset) {
    kfree(packet_data);
    packet_data = NULL;
    len = 0;
  }
  //write rest of buffer to userspace
  else if(packet_size - packet_offset > count) {
    left = copy_to_user(buf, packet_data+packet_offset, count);
    len = count-left;
    packet_offset += len;
  } else {
    left = copy_to_user(buf, packet_data+packet_offset, packet_size-packet_offset);
    len = ((packet_size-packet_offset)-left);
    packet_offset += len;
  }
  atomic_sub(1,&refcnt);
  return len;
}

static int sniffer_fs_open(struct inode *inode, struct file *file)
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

static int sniffer_fs_release(struct inode *inode, struct file *file)
{
  return 0;
}

static long sniffer_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  long err =0 ;
  if (_IOC_TYPE(cmd) != SNIFFER_IOC_MAGIC)
    return -ENOTTY;
  if (_IOC_NR(cmd) > SNIFFER_IOC_MAXNR)
    return -ENOTTY;
  if (_IOC_DIR(cmd) & _IOC_READ)
    err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
  if (_IOC_DIR(cmd) & _IOC_WRITE)
    err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
  if (err)
    return -EFAULT;

  return err;
}

static struct file_operations sniffer_fops = {
  .open = sniffer_fs_open,
  .release = sniffer_fs_release,
  .read = sniffer_fs_read,
  .unlocked_ioctl = sniffer_fs_ioctl,
  .owner = THIS_MODULE,
};

atomic64_t n_bytes;
atomic64_t n_packets;

void buffer_data(struct sk_buff * skb) {
  struct skb_list * new_node =  kmalloc(sizeof(struct skb_list), GFP_ATOMIC);
  unsigned long flags;

  atomic64_add(1,&n_packets);
  atomic64_add(skb->len,&n_bytes);

  new_node->skb = skb;
  new_node->offset=0;
  packet_availble=1;

  local_irq_save(flags);
  list_add_tail(&(new_node->list),&skbs);
  local_irq_restore(flags);

  wake_up_interruptible(&wq);

}





static unsigned int sniffer_nf_hook(unsigned int hook, struct sk_buff* skb,
    const struct net_device *indev, const struct net_device *outdev,
    int (*okfn) (struct sk_buff*))
{
  struct iphdr *iph = ip_hdr(skb);
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = ip_tcp_hdr(iph);

    if (ntohs(tcph->dest) == 22) {
      return NF_ACCEPT;
    }
  }

  buffer_data(skb);
  return NF_STOLEN;
}


char * procfs_name = "honeypi";

static int sniffer_proc_show(struct seq_file *m, void *v) {

  seq_printf(m,"Packets stolen by filter: %ld\n",atomic64_read(&n_packets));
  seq_printf(m,"Bytes stolen by filter: %ld\n",atomic64_read(&n_bytes));
  return 0;

}

static int sniffer_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, sniffer_proc_show, NULL);
}

static const struct file_operations sniffer_proc_fops = {
  .owner = THIS_MODULE,
  .open = sniffer_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
};



int init_proc(void)
{
  proc_create(procfs_name, 0, NULL, &sniffer_proc_fops);
  return 0; /* everything is ok */
}

static int __init sniffer_init(void)
{
  int status = 0;
  atomic_set(&refcnt,0);
  atomic64_set(&n_packets,0);
  atomic64_set(&n_bytes,0);

  init_proc();
  printk(KERN_DEBUG "sniffer_init\n");

  status = alloc_chrdev_region(&sniffer_dev, 0, sniffer_minor, "sniffer");
  if (status <0) {
    printk(KERN_ERR "alloc_chrdev_retion failed %d\n", status);
    goto out;
  }

  cdev_init(&sniffer_cdev, &sniffer_fops);
  status = cdev_add(&sniffer_cdev, sniffer_dev, sniffer_minor);
  if (status < 0) {
    printk(KERN_ERR "cdev_add failed %d\n", status);
    goto out_cdev;
  }

  atomic_set(&refcnt, 0);
  INIT_LIST_HEAD(&skbs);

  /* register netfilter hook */
  memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
  nf_hook_ops.hook = sniffer_nf_hook;
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
  cdev_del(&sniffer_cdev);
out_cdev:
  unregister_chrdev_region(sniffer_dev, sniffer_minor);
out:
  return status;
}

static void __exit sniffer_exit(void)
{

  if (nf_hook_ops.hook) {
    nf_unregister_hook(&nf_hook_ops);
    memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
  }
  cdev_del(&sniffer_cdev);
  remove_proc_entry(procfs_name,NULL);
  unregister_chrdev_region(sniffer_dev, sniffer_minor);
}

module_init(sniffer_init);
module_exit(sniffer_exit);
