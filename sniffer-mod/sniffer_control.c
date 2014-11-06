#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include "hp_ioctl.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static char * program_name;
static char * dev_file = "/dev/sniffer";

void usage() 
{
    fprintf(stderr, "Usage: %s [parameters]\n"
                "semantics:\n"
                "   in the case of conflicting filters the more permissive on is chosen\n"
                "parameters: \n"
                "    --mode [enable|disable]\n"
                "    --src_ip [url|any] : default is any \n"
                "    --src_port [XXX|any] : default is any \n"
                "    --dst_ip [url|any] : default is any \n" 
                "    --dst_port [XXX|any] : default is any \n"
                "    --action [capture|dpi] : default is null\n", program_name);
    exit(EXIT_FAILURE);
}

int sniffer_send_command(struct sniffer_flow_entry *flow)
{
    int dev = open(dev_file, O_RDWR);
    if (FLAG_IS_SET(flow->flags,ENABLE_FLOW)) {
      return ioctl(dev,SNIFFER_FLOW_ENABLE,(char*)flow);
    } else {
      return ioctl(dev,SNIFFER_FLOW_DISABLE,(char*)flow);
    }
}

int main(int argc, char **argv)
{
    int c;
    int case0set = 0;
    program_name = argv[0];
    struct sniffer_flow_entry new_flow;
    memset(&new_flow,0,sizeof(struct sniffer_flow_entry));
    while(1) {
        static struct option long_options[] = 
        {
            {"mode", required_argument, 0, 0},
            {"src_ip", required_argument, 0, 0},
            {"src_port", required_argument, 0, 0},
            {"dst_ip", required_argument, 0, 0},
            {"dst_port", required_argument, 0, 0},
            {"action", required_argument, 0, 0},
            {"dev", required_argument, 0, 0},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        struct hostent * h;
        c = getopt_long (argc, argv, "", long_options, &option_index);

        if (c == -1)
            break;
        switch (c) {
        case 0:
            switch(option_index) {
            case 0:     // mode
                if(!(strcmp(optarg,"enable"))) {
                  new_flow.flags |= ENABLE_FLOW;
                } else {
                  new_flow.flags &= ~ENABLE_FLOW;
                }
                case0set =1;
                break;
            case 1:     // src_ip
                if ((h = gethostbyname(optarg)) == NULL) exit(1);
                new_flow.src_ip = htonl(((int32_t*)h->h_addr_list[0])[0]);
                new_flow.flags |= SRC_IP;
                break;
            case 2:     // src_port
                new_flow.src_port = atoi(optarg);
                new_flow.flags |= SRC_P;
                break;
            case 3:     // dst_ip
                if ((h = gethostbyname(optarg)) == NULL) exit(1);
                new_flow.dst_ip = htonl(((int32_t*)h->h_addr_list[0])[0]);
                new_flow.flags |= DST_IP;
                break;
            case 4:     // dst_port
                new_flow.dst_port = atoi(optarg);
                new_flow.flags |= DST_P;
                break;
            case 5:     // action
                if(!(strcmp(optarg,"capture"))) {
                  new_flow.flags |= ACTION_CAP;
                } else if(!(strcmp(optarg,"dpi"))) {
                  new_flow.flags |= ACTION_DPI;
                }
                break;
            case 6:     // dev
                break;
            }
            break;
        default:
            usage();
        }
    }
    if(!case0set) {
      usage();
      return -1;
    }
    return sniffer_send_command(&new_flow);
}
