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

MODULE_AUTHOR("Maxwell Dergosits, Naman Agarwal, Rob McGuinness");
MODULE_DESCRIPTION("HoneyPi - A Distributed Honeypot for Raspberry Pis");
MODULE_LICENSE("Dual BSD/GPL");

static dev_t hp_dev;
static struct cdev hp_cdev;
static int hp_minor = 1;
atomic_t max_refcnt;

static DEFINE_RWLOCK(flows_rwlock);

static int hook_chain = NF_INET_PRE_ROUTING;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;

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
  if (!atomic_dec_and_test(&max_refcnt)){
    printk(KERN_ERR "Attempted to read hp when it was already being read\n");
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
  // Wait for packets
  if(wait_event_interruptible(wait_for_skbs, !list_empty(&skbs))){
    atomic_inc(&max_refcnt);
    return -ERESTARTSYS;
  }

  atomic_inc(&max_refcnt);
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


static unsigned int hp_nf_hook(const struct nf_hook_ops *ops, struct sk_buff* skb,
    const struct net_device *indev, const struct net_device *outdev,
    int (*okfn) (struct sk_buff*))
{
  struct iphdr *iph = ip_hdr(skb);
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = ip_tcp_hdr(iph);
  }
  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = ip_udp_hdr(iph);
  }

  return NF_ACCEPT;
}

static int __init hp_init(void)
{
  int status = 0;
  atomic_set(&refcnt,0);

  printk(KERN_DEBUG "hp_init\n");

  status = alloc_chrdev_region(&hp_dev, 0, hp_minor, "honeypot");
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

  atomic_set(&max_refcnt, 1);

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
