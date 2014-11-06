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


#include "hp_ioctl.h"

DECLARE_WAIT_QUEUE_HEAD(wq);
MODULE_AUTHOR("Maxwell Dergosits");
MODULE_DESCRIPTION("CS5413 Packet Filter / Sniffer Framework");
MODULE_LICENSE("Dual BSD/GPL");

#define TEXT_SIGNATURE "hello"

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

struct flow_list {
  struct list_head list; /* kernel's list structure */
  struct sniffer_flow_entry entry;
};

struct flow_list filter_list;
struct flow_list block_list;

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
    printk("skb->users =%d\n",sizeof(struct sk_buff));
    iph = ip_hdr(skb);
    tcph = ip_tcp_hdr(iph);
    packet_size = skb->len+(12);
    packet_data =kmalloc(packet_size,GFP_ATOMIC);
    ((uint32_t*)packet_data)[0] = iph->saddr;
    ((uint32_t*)packet_data)[1] = iph->daddr;
    ((uint16_t*)(packet_data+8))[0] = htons(tcph->source);
    ((uint16_t*)(packet_data+8))[1] = htons(tcph->dest);

    if(skb_copy_bits(skb,0,packet_data+12,packet_size-12)) {
    }
    list_del(&first->list);
    local_irq_restore(flags);
    kfree_skb(skb);
    kfree(first);
    //} spin_unlock(&buffer_lock);
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


char flow_entry_compare(struct sniffer_flow_entry *a,struct sniffer_flow_entry*b) {
  return
    (a->src_ip == b->src_ip || (!FLAG_IS_SET(a->flags,SRC_IP)&&!FLAG_IS_SET(b->flags,SRC_IP))) &&
    (a->dst_ip == b->dst_ip || (!FLAG_IS_SET(a->flags,DST_IP)&&!FLAG_IS_SET(b->flags,DST_IP))) &&
    (a->src_port == b->src_port || (!FLAG_IS_SET(a->flags,SRC_P)&&!FLAG_IS_SET(b->flags,SRC_P))) &&
    (a->dst_port == b->dst_port || (!FLAG_IS_SET(a->flags,DST_P)&&!FLAG_IS_SET(b->flags,DST_P)));
}

void add_to_list(struct flow_list * entry) {
  struct flow_list *tmp;
  list_for_each_entry(tmp, &filter_list.list, list){
    if (flow_entry_compare(&entry->entry,&tmp->entry))
    {
      tmp->entry.flags = entry->entry.flags;
      kfree(entry);
      return;
    }
  }
  list_add(&(entry->list), &(filter_list.list));
}

static long sniffer_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  long err =0 ;
  struct flow_list * new_entry;
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
  new_entry = kmalloc(sizeof(struct flow_list),GFP_KERNEL);
  if (!new_entry) return -EFAULT;
  if(copy_from_user(&new_entry->entry,(char __user *)arg,sizeof(struct sniffer_flow_entry))) {
    return -EFAULT;
  }


  switch(cmd) {
    case SNIFFER_FLOW_ENABLE:
    case SNIFFER_FLOW_DISABLE:
      add_to_list(new_entry);
      break;
    default:
      printk(KERN_DEBUG "Unknown command\n");
      kfree(new_entry);
      err = -EINVAL;
  }

  return err;
}

static struct file_operations sniffer_fops = {
  .open = sniffer_fs_open,
  .release = sniffer_fs_release,
  .read = sniffer_fs_read,
  .unlocked_ioctl = sniffer_fs_ioctl,
  .owner = THIS_MODULE,
};

char check_flows(struct iphdr * iph,  struct flow_list ** entry) {
  struct flow_list * tmp;
  char ret = NF_DROP;
  if (iph->protocol != IPPROTO_TCP) {
    return NF_ACCEPT;
  }
  list_for_each_entry(tmp, &filter_list.list, list) {
    if((FLAG_IS_SET(tmp->entry.flags,SRC_IP) && tmp->entry.src_ip != ntohl(iph->saddr)) ||
        (FLAG_IS_SET(tmp->entry.flags,SRC_P) && tmp->entry.src_port != ntohs(ip_tcp_hdr(iph)->source)) ||
        (FLAG_IS_SET(tmp->entry.flags,DST_IP) && tmp->entry.dst_ip != ntohl(iph->daddr)) ||
        (FLAG_IS_SET(tmp->entry.flags,DST_P) && tmp->entry.dst_port != ntohs(ip_tcp_hdr(iph)->dest)) ||
        (FLAG_IS_SET(tmp->entry.flags,ACTION_DPI) && FLAG_IS_SET(tmp->entry.flags,DPI_DROP_ON))) {
      continue;
    }
    *entry = tmp;
    if (FLAG_IS_SET(tmp->entry.flags,ENABLE_FLOW)) {
      ret = NF_ACCEPT;
    }
  }
  return ret;
}


void buffer_data(struct sk_buff * skb) {
  struct skb_list * new_node =  kmalloc(sizeof(struct skb_list), GFP_ATOMIC);
  unsigned long flags;
  new_node->skb = skb;
  new_node->offset=0;
  packet_availble=1;

  local_irq_save(flags);
  list_add_tail(&(new_node->list),&skbs);
  local_irq_restore(flags);

  wake_up_interruptible(&wq);

}
struct ts_config *conf;

char do_dpi(struct sk_buff * skb)
{
  int pos;
  int found = 0;
  struct ts_state state;

  for (pos = skb_find_text(skb, 0, UINT_MAX, conf, &state);
      pos >= 0;
      pos = textsearch_next(conf, &state))
  { found = 1; break;}

  kfree_skb(skb);
  return found;
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
/*
  ret =check_flows(iph,&action);
  if (action) {
    if(FLAG_IS_SET(action->entry.flags,ACTION_CAP)) {
      buffer_data(skb_copy(skb,GFP_ATOMIC));
    } else if(FLAG_IS_SET(action->entry.flags,ACTION_DPI)) {
      if (do_dpi(skb_copy(skb,GFP_ATOMIC))) {
        action->entry.flags |= DPI_DROP_ON;
        ret = NF_DROP;
      }
    }
  }
  if (ret == NF_DROP) {
    printk(KERN_DEBUG "Rejected %x:%d -> %x:%d\n", ntohl(iph->saddr), ntohs(tcph->source), ntohl(iph->daddr), ntohs(tcph->dest));
    return NF_DROP;
  }
*/

  buffer_data(skb);
  return NF_STOLEN;
}


char * procfs_name = "sniffer";

static int sniffer_proc_show(struct seq_file *m, void *v) {
  int src;
  int dst;
  int src_ipn;
  int dst_ipn;
  char src_port[10];
  char dst_port[10];
  char src_ip[32];
  char dst_ip[32];
  char *action;

  struct flow_list * tmp;
  struct sniffer_flow_entry * en;
  char flags;
  int count = 0;
  list_for_each_entry(tmp, &filter_list.list, list){
    en = &tmp->entry;
    flags  = en->flags;
    src = en->src_port;
    dst = en->dst_port;
    src_ipn = htonl(en->src_ip);
    dst_ipn = htonl(en->dst_ip);


    /*
       1    enable     any             any      127.0.0.1         4000      None
       2    enable   128.84.154.162     80         any            any        DPI
     */
    action = "None";
    if(FLAG_IS_SET(flags,ACTION_DPI)) {
      action = "DPI";
    }
    if (FLAG_IS_SET(flags,ACTION_CAP)) {
      action = "Capture";
    }

    snprintf(src_port,10,"%d",src);
    snprintf(dst_port,10,"%d",dst);
    snprintf(src_ip,32,"%pI4",&src_ipn);
    snprintf(dst_ip,32,"%pI4",&dst_ipn);

    seq_printf(m, "%d %s %s %s %s %s %s\n",
        ++count,
        FLAG_IS_SET(flags,ENABLE_FLOW) ? "enable" : "disable",
        FLAG_IS_SET(flags,SRC_IP) ?  src_ip: "any",
        FLAG_IS_SET(flags,SRC_P) ?  src_port: "any",
        FLAG_IS_SET(flags,DST_IP) ?  dst_ip: "any",
        FLAG_IS_SET(flags,DST_P) ?  dst_port: "any",
        action
        );
  }
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
  struct flow_list *ssh = kmalloc(sizeof(struct flow_list),GFP_KERNEL);
  atomic_set(&refcnt,0);

  init_proc();
  INIT_LIST_HEAD(&filter_list.list);
  conf= textsearch_prepare("kmp", TEXT_SIGNATURE, 5, GFP_KERNEL, 1);
  printk(KERN_DEBUG "sniffer_init\n");



  ssh->entry.flags = (DST_P | ENABLE_FLOW);
  ssh->entry.dst_port = 22;
  add_to_list(ssh);

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















