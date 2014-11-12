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

static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
atomic_t refcnt;

static int hook_chain = NF_INET_PRE_ROUTING;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;

static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
  struct tcphdr *tcph = (void *) iph + iph->ihl*4;
  return tcph;
}

static ssize_t
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
  return 0;
}

static int sniffer_fs_open(struct inode *inode, struct file *file)
{
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


static unsigned int sniffer_nf_hook(const struct nf_hook_ops *ops, struct sk_buff* skb,
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

  return NF_QUEUE;
}

static int __init sniffer_init(void)
{
  int status = 0;
  atomic_set(&refcnt,0);

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
  unregister_chrdev_region(sniffer_dev, sniffer_minor);
}

module_init(sniffer_init);
module_exit(sniffer_exit);
