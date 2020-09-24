#ifndef __TCPIP_STACK_HEADER__
#define __TCPIP_STACK_HEADER__
#include <stdint.h>
#include "uthash.h"
#include "utstack.h"
#include "ringbuffer.h"
#include "rbtree.h"
#include "list.h"
#pragma pack(push,1)
#define IP_PROTO_ICMP  1
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP   17
#define IP_PROTO_ICMP6 58
/*
* The number of bytes in an Ethernet (MAC) address.
*/
#define	ETHER_ADDR_LEN		6

/*
* The number of bytes in the type field.
*/
#define	ETHER_TYPE_LEN		2

/*
* The length of the combined header.
*/
#define	ETHER_HDR_LEN		(ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)


/*
*	TCP option
*/

#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG		19	/* MD5 Signature (RFC2385) */

/*
*     TCP option lengths
*/

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_MD5SIG         18


typedef struct 
{
	uint16_t hwtype;
	uint16_t protype;
	uint8_t hwsize;
	uint8_t prosize;
	uint16_t opcode;
	uint8_t data[0];
}arp_hdr_t;

typedef struct 
{
	uint8_t smac[6];
	uint32_t sip;
	uint8_t dmac[6];
	uint32_t dip;
}arp_ipv4_t;



typedef struct 
{
	uint8_t	ether_dhost[ETHER_ADDR_LEN];
	uint8_t	ether_shost[ETHER_ADDR_LEN];
	uint16_t	ether_type;
} ether_t;

typedef struct {

	unsigned char	ihl : 4;
	unsigned char	version : 4;
	uint8_t	tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t	ttl;
	uint8_t	protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
	/*The options start here. */
}iphdr_t;
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/


typedef struct udphdr {
	/*	__u16 uh_sport;
	*       __u16 uh_dport; */
	uint16_t source;
	uint16_t dest;
	uint16_t uh_ulen;
	uint16_t check;
}udphdr_t;


typedef struct {
	uint16_t	source;
	uint16_t	dest;
	uint32_t	seq;
	uint32_t	ack_seq;
	uint8_t	res1 : 4;
	uint8_t	doff : 4;
	uint8_t	fin : 1;
	uint8_t	syn : 1;
	uint8_t	rst : 1;
	uint8_t	psh : 1;
	uint8_t	ack : 1;
	uint8_t	urg : 1;
	uint8_t	ece : 1;
	uint8_t	cwr : 1;
	uint16_t	window;
	uint16_t	check;
	uint16_t	urg_ptr;
}tcphdr_t;

typedef struct  {
	union
	{
		struct
		{
			uint8_t byte1;
			uint8_t byte2;
			uint8_t byte3;
			uint8_t byte4;
		}ipbyte;
		uint32_t iplong;
	};
}ip_address_t;

#define TCP_CONNECTION_CLOSED      0
#define TCP_CONNECTION_SYN_RCVD    1
#define TCP_CONNECTION_SYN_SENT    2
#define TCP_CONNECTION_ESTABLISHED 3
#define TCP_CONNECTION_FIN_WAIT_1  4
#define TCP_CONNECTION_FIN_WAIT_2  5
#define TCP_CONNECTION_CLOSING     6
#define TCP_CONNECTION_TIME_WAIT   7
#define TCP_CONNECTION_LAST_ACK    8
#define TCP_CONNECTION_TS_MASK     15
#define TCP_CONNECTION_STOPPED      16
typedef struct
{
	union
	{
		struct
		{
			uint8_t s1;
			uint8_t s2;
			uint8_t s3;
			uint8_t s4;
		}byte_value;
		uint32_t integer_value;
	}u;
}tcp_seq_t;
typedef struct
{
	uint32_t src;
	uint32_t dst;
	uint16_t srcport;
	uint16_t dstport;
	uint8_t  state;
	tcp_seq_t send_next;
	tcp_seq_t recv_next;
	uint16_t len;          /**< Length of the data that was previously sent. */
	uint16_t initialmss;
	uint16_t mss;          /**< Current maximum segment size for the
						connection. */
	uint8_t sa;            /**< Retransmission time-out calculation state
						variable. */
	uint8_t sv;            /**< Retransmission time-out calculation state
						variable. */
	uint8_t rto;           /**< Retransmission time-out. */
	uint8_t timer;         /**< The retransmission timer. */
	uint8_t nrtx;          /**< The number of retransmissions for the last
						segment sent. */
	uint16_t wndsize;
	uint8_t use_window_scale : 1;
	uint8_t saw_tstamp : 1;
	uint8_t reserve2 : 1;
	uint8_t reserve3 : 1;
	uint8_t reserve4 : 1;
	uint8_t reserve5 : 1;
	uint8_t reserve6 : 1;
	uint8_t reserve7 : 1;
	uint8_t send_window_scale;
	uint32_t rcv_tsval;
	uint32_t rcv_tsecr;
	uint8_t *snd_buf;
	uint8_t *rcv_buf;
}tcp_connection_info_t;

typedef struct tcp_session_hash_header_s
{
	rbtree_node_t timernode;
	uint8_t timer_set;
	volatile uint8_t refcnt;
	int (*on_reset)(struct tcp_session_hash_header_s  *fd);
	void(*on_establish)(struct tcp_session_hash_header_s * fd, struct tcp_session_hash_header_s  *client);
	int(*on_data)(struct tcp_session_hash_header_s  *fd, void * data, int data_size);
	tcp_connection_info_t info;
	void* key;
	UT_hash_handle hh;
}tcp_session_hash_header_t;


typedef struct
{
	tcp_session_hash_header_t *tcp_half_connections;
	uint16_t listener_backlog;
	void*	key;
	int(*pre_accept)(struct tcp_session_hash_header_s * fd, uint32_t sip, uint16_t sport, uint16_t dport);
	int(*on_accept)(struct tcp_session_hash_header_s * fd, uint32_t sip, uint16_t sport, uint16_t dport);
	int(*on_reset)(struct tcp_session_hash_header_s  *fd);
	void(*on_establish)(struct tcp_session_hash_header_s * fd, struct tcp_session_hash_header_s  *client);
	int (*on_data)(struct tcp_session_hash_header_s  *fd, void * data, int data_size);
	UT_hash_handle hh;
}tcp_listener_hash_header_t;

typedef struct packet_s
{
	list_t link;
	volatile uint8_t refcnt;
	int8_t *pos;
	int8_t * end;
	int8_t start[0];
}packet_t;

typedef struct
{
	uint64_t rexmit;
	uint64_t xmit;
}stack_state_t;
typedef struct
{
	uint32_t (*dev_lookup)(uint32_t, uint8_t*);
	uint16_t(*dev_read)(void *, uint16_t);
	uint16_t(*dev_write)(void *, uint16_t);
	void* (*st_malloc)(uint16_t);
	void(*st_free)(void*);
	uint32_t(*timetick)();
	void(*verbose)(uint16_t level, const char*);
	list_t out_stack;
	list_t lookaside_list;
	uint8_t	ether_addr[ETHER_ADDR_LEN];
	ip_address_t ip_addr;
	uint16_t	max_packet_size;
	uint16_t	rto;
	uint16_t	rcvbuf;
	uint16_t	sndbuf;
	tcp_session_hash_header_t * tcp_sessions;
	tcp_listener_hash_header_t * tcp_listeners;
	tcp_seq_t iss;
	uint8_t ttl;
	uint16_t ipid;
	stack_state_t state;
	rbtree_t timer;
	rbtree_node_t sentinel;
	uint32_t current_msec;
}stack_t;

typedef enum
{
	stack_warning_level_1, //very low,this level will output all warning string
	stack_warning_level_2,
	stack_warning_level_3,
	stack_warning_level_4 // very high,it's critical level,only output string while entercounted a fatal 
}verbose_e;



void * create_listener(stack_t * stack, uint16_t port, \
	int(*pre_accept)(tcp_session_hash_header_t * fd, uint32_t sip, uint16_t sport, uint16_t dport), \
	int(*on_accept)(tcp_session_hash_header_t * fd, uint32_t sip, uint16_t sport, uint16_t dport), \
	int(*on_reset)(struct tcp_session_hash_header_s  *fd), \
	void(*on_establish)(struct tcp_session_hash_header_s * fd, struct tcp_session_hash_header_s  *client),\
	int (*on_data)(struct tcp_session_hash_header_s  *fd, void * data, int data_size));
 

void stack_init(stack_t * stack, char * hwaddr, unsigned int ip, uint32_t(*dev_lookup)(uint32_t ip, uint8_t* macbuf), \
	uint16_t(*dev_read)(void *, uint16_t), \
	uint16_t(*dev_write)(void *, uint16_t), void* (*st_malloc)(uint16_t), void(*st_free)(void*), \
	void(*verbose)(uint16_t level, const char*), uint32_t(*timetick)());

int32_t stack_input(stack_t * stack, int8_t * data, uint16_t data_len);
uint32_t stack_output(stack_t * stack);


int32_t stack_send(stack_t * stack, void * sock, void * data, int data_len);
int32_t stack_close(stack_t * stack, void * conn);
#pragma pack(pop)

#endif