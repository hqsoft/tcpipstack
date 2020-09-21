#ifndef ARP_H
#define ARP_H
#include <stdint.h>


#define ARP_ETHERNET    0x0001
#define ARP_IPV4        0x0800
#define ARP_REQUEST     0x0001
#define ARP_REPLY       0x0002

#define ETH_HDR_LEN sizeof(ether_t)
#define ARP_HDR_LEN sizeof(arp_hdr_t)
#define ARP_DATA_LEN sizeof(arp_ipv4_t)

#define ARP_CACHE_LEN   32
#define ARP_FREE        0
#define ARP_WAITING     1
#define ARP_RESOLVED    2


#endif
