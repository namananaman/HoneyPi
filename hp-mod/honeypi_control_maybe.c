#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_queue.h>

static char * program_name;
static char * dev_file = "/dev/sniffer";

int honeypi_handle_packet(struct nf_queue_entry *entry, unsigned int queuenum){
    // This printf might cause horrible things... might have to use a counter
    // instead (if globals even work either...)
    printf("I got a packet!\n");
    // We MUST reinject EVERY packet we get. We don't NF_QUEUE SSH packets, so
    // we're good to drop 'em
    nf_reinject(entry, NF_DROP);
    // We want to return traditional error codes, like -EINVAL, -ENOBUFS, etc
    // if we get any errors
    return 0;
}

static const struct nf_queue_entry hp_queue = {
    .outfn = honeypi_handle_packet,
};


void stop_capture(int signum){
    signal(signum, SIG_IGN);
    nf_unregister_queue_handler();
    exit(0);
}


int main(int argc, char **argv)
{
    nf_register_queue_handler(&hp_queue);
    signal(SIGINT, stop_capture);
    while(1)
        pause();
}
