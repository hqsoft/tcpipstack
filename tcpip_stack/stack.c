#include "stack.h"
#include "ethernet.h"
#include "arp.h"
#include <stdint.h>
#include <stdio.h>

#define packet_arp_hdr(x)((arp_hdr_t*)(x->start + ETH_HDR_LEN))
#define packet_ip_hdr(x)((iphdr_t*)(x->start + ETH_HDR_LEN))
#define packet_ip_hdr_size(x)((packet_ip_hdr(x)->ihl * 4))
#define packet_tcp_hdr(x) ((tcphdr_t*)((char*)packet_ip_hdr(x) + packet_ip_hdr_size(x)))
#define packet_tcp_hdr_size(x)((packet_tcp_hdr(x)->doff * 4))

#define packet_tcp_opt(x) (tcphdr_t*)((char*)x->start + (packet_ip_hdr(x))->ihl * 4 + sizeof(tcphdr_t))
#define packet_tcp_payload(x)((char*)packet_tcp_hdr(x) + packet_tcp_hdr_size(x))
#define packet_tcp_payload_size(x)(uint16_t)(htons((packet_ip_hdr(x))->tot_len) - sizeof(iphdr_t) - packet_tcp_hdr(x)->doff * 4)
#define packet_udp_hdr(x) (udphdr_t*)((char*)x + (packet_ip_hdr(x))->ihl * 4)
#define packet_eth_hdr(x)(ether_t*)(x->start)
#define tcp_mss(stack)(stack->max_packet_size - 40)
#define __bswap_16(x) (uint16_t)((((uint16_t)(x) & 0x00ff) << 8) | (((uint16_t)(x) & 0xff00) >> 8))


#define __bswap_32(x)(uint32_t)((((uint32_t)(x) & 0xff000000) >> 24) |(((uint32_t)(x) & 0x00ff0000) >> 8) | \
(((uint32_t)(x) & 0x0000ff00) << 8) | \
(((uint32_t)(x) & 0x000000ff) << 24) \
)
 

#ifdef BIG_ENDIAN
#define ntohl(x)    (x)
#define ntohs(x)    (x)
#define htonl(x)    (x)
#define htons(x)    (x)
#else
#define ntohl(x)    __bswap_32 (x)
#define ntohs(x)    __bswap_16 (x)
#define htonl(x)    __bswap_32 (x)
#define htons(x)    __bswap_16 (x)
#endif
#define tcp_recv_next_add( connection,  n)connection->info.recv_next.u.integer_value = htonl(htonl(connection->info.recv_next.u.integer_value) + n)
#define tcp_send_next_add( connection,  n)connection->info.send_next.u.integer_value = htonl(htonl(connection->info.send_next.u.integer_value) + n)
#define rev_seq(connection)htonl(connection->info.recv_next.u.integer_value)
#define send_seq(connection)htonl(connection->info.send_next.u.integer_value)

#define get_unaligned_be32(x)htonl(*(uint32_t*)x)
#define get_unaligned_be16(x)htons(*(uint16_t*)x)



uint16_t chksum(uint16_t sum, const uint8_t *data, uint16_t len)
{
	uint16_t t;
	const uint8_t *dataptr;
	const uint8_t *last_byte;

	dataptr = data;
	last_byte = data + len - 1;

	while (dataptr < last_byte) {	/* At least two more bytes */
		t = (dataptr[0] << 8) + dataptr[1];
		sum += t;
		if (sum < t) {
			sum++;		/* carry */
		}
		dataptr += 2;
	}

	if (dataptr == last_byte) {
		t = (dataptr[0] << 8) + 0;
		sum += t;
		if (sum < t) {
			sum++;		/* carry */
		}
	}

	/* Return sum in host byte order. */
	return sum;
}

uint16_t ipchksum(iphdr_t* iphdr)
{
	uint16_t sum;

	sum = chksum(0, iphdr, sizeof(iphdr_t));
	return (sum == 0) ? 0xffff : htons(sum);
}

/*---------------------------------------------------------------------------*/
uint16_t upper_layer_chksum(iphdr_t* iphdr,uint8_t proto)
{
	uint16_t upper_layer_len;
	uint16_t sum;

	upper_layer_len = htons(iphdr->tot_len) - sizeof(iphdr_t);
	/* First sum pseudoheader. */

	/* IP protocol and length fields. This addition cannot carry. */
	sum = upper_layer_len + proto;
	/* Sum IP source and destination addresses. */
	sum = chksum(sum, (uint8_t *)&iphdr->saddr, 2 * sizeof(uint32_t));

	/* Sum TCP header and data. */
	sum = chksum(sum,(const uint8_t*)(iphdr + 1),upper_layer_len);

	return (sum == 0) ? 0xffff : htons(sum);
}
packet_t * alloc_packet(stack_t * stack)
{
	packet_t* dummy = NULL;
	if (!ministack_list_empty(&stack->lookaside_list))
	{
		dummy = CONTAINING_RECORD(stack->lookaside_list.next, packet_t, link);
		ministack_list_del(dummy);
	}
		
	if (dummy)
	{
		dummy->end = dummy->start;
		dummy->pos = dummy->start;
		dummy->refcnt = 0;
		return dummy;
	}
	else
	{
		dummy = (packet_t *)(stack->st_malloc(sizeof(packet_t) + stack->max_packet_size));
		if (dummy)
		{
			ministack_list_init(&dummy->link);
			dummy->end = dummy->start;
			dummy->pos = dummy->start;
			dummy->refcnt = 0;
			return dummy;
		}

	}
	return NULL;
}
int32_t construct_packet(stack_t * stack,packet_t * packet,int8_t* data, uint16_t len)
{
	if (packet->end + len > packet->start + stack->max_packet_size)
	{
		return -1;
	}
	packet->pos = packet->start + len;
	packet->end = packet->start + len;
	if(data != NULL)
		memcpy(packet->start, data, len);
	return 0;
}
void free_packet(stack_t * stack, packet_t * packet)
{
	if(packet->refcnt < 1)
		ministack_list_add(&stack->lookaside_list, packet);
}

char* packet_push(packet_t * packet,uint16_t size)
{
	if (packet->pos - size >= packet->start)
	{
		packet->pos -= size;
		return packet->pos;
	}
	return NULL;
}
int32_t packet_reserve(stack_t * stack,packet_t * packet, uint16_t size)
{
	if (packet->pos + size > packet->start + stack->max_packet_size)
	{
		return -1;
	}

	construct_packet(stack, packet, NULL, size);
	return 0;
}
packet_t * packet_ref(packet_t * packet)
{
	if (packet->refcnt < 255)
	{
		packet->refcnt++;
		return packet;
	}
	return NULL;
}
void packet_deref(packet_t * packet)
{
	if (packet->refcnt > 0)
	{
		packet->refcnt--;
	}
}
void send_packet(stack_t * stack, packet_t * packet, uint8_t *dst_hw, uint16_t ethertype)
{
	packet_t * old;
	ether_t *hdr;
	int ret = 0;

	hdr = (ether_t *)packet_push(packet, ETH_HDR_LEN);

	 

	memcpy(hdr->ether_dhost, dst_hw, ETHER_ADDR_LEN);
	memcpy(hdr->ether_shost, stack->ether_addr, ETHER_ADDR_LEN);

	hdr->ether_type = htons(ethertype);

	ministack_list_add_tail(&packet->link,&stack->out_stack);
	packet_ref(packet);
}

void arp_reply(stack_t * stack, packet_t * packet)
{
	arp_hdr_t *arphdr;
	arp_ipv4_t *arpdata;
	
	packet_reserve(stack, packet, ETH_HDR_LEN + ARP_HDR_LEN + ARP_DATA_LEN);
	packet_push(packet, ARP_HDR_LEN + ARP_DATA_LEN);

	arphdr = packet_arp_hdr(packet);

	arpdata = (struct arp_ipv4 *) arphdr->data;

	memcpy(arpdata->dmac, arpdata->smac, 6);
	arpdata->dip = arpdata->sip;

	memcpy(arpdata->smac, stack->ether_addr, 6);
	arpdata->sip = stack->ip_addr.iplong;

	arphdr->opcode = ARP_REPLY;
	 
	arphdr->opcode = htons(arphdr->opcode);
	arphdr->hwtype = htons(arphdr->hwtype);
	arphdr->protype = htons(arphdr->protype);
 
	//arpdata->sip = htonl(arpdata->sip);
	arpdata->dip = htonl(arpdata->dip);

	stack->verbose(stack_warning_level_1, "send arp_reply ");

	send_packet(stack, packet, arpdata->dmac, ETH_P_ARP);
	free_packet(stack, packet);
}
void arp_rcv(stack_t * stack, packet_t * packet)
{
	arp_hdr_t *arphdr;
	arp_ipv4_t *arpdata;
	arphdr = packet_arp_hdr(packet);

	arphdr->hwtype = ntohs(arphdr->hwtype);
	arphdr->protype = ntohs(arphdr->protype);
	arphdr->opcode = ntohs(arphdr->opcode);

	if (arphdr->hwtype != ARP_ETHERNET) {
		return;
	}

	if (arphdr->protype != ARP_IPV4) {
		return;
	}


	arpdata = (arp_ipv4_t *) arphdr->data;
	ip_address_t ip;
	ip.iplong = arpdata->dip;
	if (arpdata->dip != stack->ip_addr.iplong)
	{
		return;
	}
	
	arpdata->sip = ntohl(arpdata->sip);
	arpdata->dip = ntohl(arpdata->dip);


	switch (arphdr->opcode) {
	case ARP_REQUEST:
		arp_reply(stack, packet);
		return;
	default:
		return;
	}

	return;
}
/* reference to Linux */
unsigned int tcp_hash(iphdr_t * iphdr, tcphdr_t * tcphdr)
{
	unsigned int hash;
	hash = (iphdr->saddr ^ tcphdr->source) ^ (tcphdr->dest);
	/* make all bits xor to lowest 8 bit */
	hash ^= hash >> 16;
	hash ^= hash >> 8;
	return hash;
}
unsigned int tcp_hash2(uint32_t daddr, uint32_t dport,uint32_t sport)
{
	unsigned int hash;
	hash = (daddr ^ dport) ^ (sport);
	/* make all bits xor to lowest 8 bit */
	hash ^= hash >> 16;
	hash ^= hash >> 8;
	return hash;
}

void tcp_parse_options(stack_t * stack, tcp_session_hash_header_t * connection, tcphdr_t * th)
{
	const unsigned char *optptr;
	int length = (th->doff * 4) - sizeof(tcphdr_t);

	optptr = (const unsigned char *)(th + 1);

	while (length > 0)
	{
		int opcode = *optptr++;
		int opsize;

		switch (opcode)
		{
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *optptr++;
			if (opsize < 2) /* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			switch (opcode) {
			case TCPOPT_MSS:
				if (opsize == TCPOLEN_MSS && connection && connection->info.state == TCP_CONNECTION_SYN_RCVD)
				{
					uint16_t in_mss = get_unaligned_be16(optptr);
					if (in_mss)
					{
						connection->info.mss = in_mss > tcp_mss(stack) ? tcp_mss(stack) : in_mss;
					}
				}
				break;
			case TCPOPT_WINDOW:
				if (opsize == TCPOLEN_WINDOW && connection && connection->info.state == TCP_CONNECTION_SYN_RCVD)
				{
					uint8_t snd_wscale = *(uint8_t *)optptr;
					connection->info.use_window_scale = 1;
					if (snd_wscale > 14)
					{
						stack->verbose(stack_warning_level_2, "Illegal window scaling value >14 received");
						snd_wscale = 14;
					}
					connection->info.send_window_scale = snd_wscale;
				}
				break;
			case TCPOPT_TIMESTAMP:
				if (opsize == TCPOLEN_TIMESTAMP)
				{
					connection->info.saw_tstamp = 1;
					connection->info.rcv_tsval = get_unaligned_be32(optptr);
					connection->info.rcv_tsecr = get_unaligned_be32((char*)optptr + 4);
				}
				break;

				optptr += opsize - 2;
				length -= opsize;
			}
		}
	}
}

int tcp_establish(stack_t * stack, uint32_t tcphash, packet_t * packet, tcp_listener_hash_header_t * listener,tcp_session_hash_header_t * connection)
{
	ether_t * ethhdr = packet_eth_hdr(packet);
	iphdr_t * iphdr = packet_ip_hdr(packet);
	tcphdr_t * tcphdr = packet_tcp_hdr(packet);
	if (listener)
	{
		HASH_DEL(listener->tcp_half_connections, connection);
		HASH_ADD_PTR(stack->tcp_sessions, key, connection);
		listener->on_accept(connection, iphdr->saddr, tcphdr->source, tcphdr->dest);
	}
	
	connection->on_establish(listener, connection);
	connection->info.state = TCP_CONNECTION_ESTABLISHED;
	

	return 0;

}
void add_timer(stack_t * stack, tcp_session_hash_header_t * connection, int msec)
{
	uint32_t diff;
	uint32_t key;
	key = stack->current_msec + msec;

	if (connection->timer_set)
	{
		diff = abs(key - (uint32_t)connection->timernode.key);
		if (diff < 5)
		{
			return;
		}
	}
	else
	{
		connection->refcnt++;
	}
	connection->timernode.key = key;
	rbtree_insert(&stack->timer, &connection->timernode);

	connection->timer_set = 1;
}
void reset_timer(stack_t * stack, tcp_session_hash_header_t * connection)
{
	if (connection->timer_set)
	{
		rbtree_delete(&stack->timer, &connection->timernode);
		connection->refcnt--;
		connection->timer_set = 0;
	}
}
void connection_timeout(stack_t * stack,tcp_session_hash_header_t * connection)
{
	reset_timer(stack, connection);

}
void timer_check(stack_t * stack)
{
	tcp_session_hash_header_t * connection;
	do
	{
		stack->current_msec = stack->timetick();
		connection = (tcp_session_hash_header_t*)rbtree_min(&stack->timer, &stack->sentinel);

		if (!connection || connection->timernode.key > stack->current_msec)
		{
			return;
		}
		if (!connection->timer_set)
		{
			break;
		}
		connection_timeout(stack,connection);
	} while (1);

}
tcp_session_hash_header_t * alloc_connection(stack_t * stack)
{
	tcp_session_hash_header_t * connection = (tcp_session_hash_header_t*)stack->st_malloc(sizeof(tcp_session_hash_header_t));
	if (!connection)
	{
		return NULL;
	}
	memset(connection, 0, sizeof(tcp_session_hash_header_t));
	return connection;
}
void free_connection(stack_t * stack, tcp_session_hash_header_t * connection)
{
	if (!connection->refcnt)
	{
		stack->st_free((void*)connection);
	}
	else
	{
		connection->refcnt--;
	}
}
int send_synack(stack_t * stack, uint32_t tcphash,packet_t * packet, tcp_listener_hash_header_t * listener)
{
	ether_t * ethhdr = packet_eth_hdr(packet);
	iphdr_t * iphdr = packet_ip_hdr(packet);
	tcphdr_t * tcphdr = packet_tcp_hdr(packet);
	tcp_session_hash_header_t * connection;
	void * key = (void*)tcphash;
	HASH_FIND_PTR(listener->tcp_half_connections, &key, connection);
	if (!connection)
	{
		if (listener->pre_accept(listener, iphdr->saddr, tcphdr->source, tcphdr->dest))
		{
			connection = alloc_connection(stack);
			if (connection)
			{
				connection->key = (void*)tcphash;
				HASH_ADD_PTR(listener->tcp_half_connections, key, connection);
				memset(&connection->info, 0, sizeof(tcp_connection_info_t));
				connection->info.state = TCP_CONNECTION_SYN_RCVD;
				connection->info.dst = iphdr->daddr;
				connection->info.src = iphdr->saddr;
				connection->info.dstport = tcphdr->dest;
				connection->info.srcport = tcphdr->source;
				connection->info.initialmss = stack->max_packet_size - sizeof(ether_t) - sizeof(iphdr_t) - sizeof(tcphdr_t);
				connection->info.len = 1;
				connection->info.rto = stack->rto;
				connection->info.timer = stack->rto;
				connection->info.sv = 4;
				connection->info.wndsize = htons(tcp_mss(stack));
				connection->info.send_next.u.integer_value = stack->iss.u.integer_value;
				connection->info.recv_next.u.integer_value = tcphdr->seq;
				connection->on_establish = stack->tcp_listeners->on_establish;
				connection->on_reset = stack->tcp_listeners->on_reset;
				connection->on_data = stack->tcp_listeners->on_data;
				tcp_recv_next_add(connection, 1);

				add_timer(stack, connection, 2000);
				if (tcphdr->doff > 5)
				{
					//parse the tcp option
					tcp_parse_options(stack, connection, tcphdr);
				}
			}
			else
			{
				stack->verbose(stack_warning_level_4, "could not allocate new connection while send_synack ");
				return -1;
			}
		}
		else
		{
			stack->verbose(stack_warning_level_1, "decline the syn request ");
			return -1;
		}
	}

	packet_reserve(stack, packet, ETH_HDR_LEN + sizeof(iphdr_t) + sizeof(tcphdr_t) + TCPOLEN_MSS + TCPOPT_NOP + TCPOLEN_WINDOW );
	char * opt = NULL;



	opt = packet_push(packet, TCPOLEN_WINDOW);
	opt[0] = TCPOPT_WINDOW;
	opt[1] = TCPOLEN_WINDOW;
	opt[2] = 0;

	opt = packet_push(packet, TCPOPT_NOP);
	opt[0] = TCPOPT_NOP;

	opt = packet_push(packet, TCPOLEN_MSS);
	opt[0] = TCPOPT_MSS;
	opt[1] = TCPOLEN_MSS;
	*(uint16_t*)&opt[2] = htons(stack->max_packet_size - sizeof(ether_t) - sizeof(iphdr_t) - sizeof(tcphdr_t));



	tcphdr_t * new_tcphdr = (tcphdr_t*)packet_push(packet, sizeof(tcphdr_t));
	memset(new_tcphdr, 0, sizeof(tcphdr_t));
	new_tcphdr->ack_seq = connection->info.recv_next.u.integer_value;
	new_tcphdr->seq = connection->info.send_next.u.integer_value;
	printf("send  ack+syn 1  send seq : %d \n", send_seq(connection));

	tcp_send_next_add(connection, 1);
	printf("send  ack+syn 2  send seq : %d \n", send_seq(connection));

	new_tcphdr->source = connection->info.dstport;
	new_tcphdr->dest = connection->info.srcport;
	new_tcphdr->ack = 1;
	new_tcphdr->syn = 1;
	new_tcphdr->window = 0;// connection->info.wndsize;
	new_tcphdr->doff = ((sizeof(tcphdr_t) + TCPOLEN_MSS + TCPOPT_NOP + TCPOLEN_WINDOW)) / 4;
	iphdr_t * new_iphdr = packet_push(packet, sizeof(iphdr_t));
	memset(new_iphdr, 0, sizeof(iphdr_t));
	new_iphdr->saddr = connection->info.dst;
	new_iphdr->daddr = connection->info.src;
	new_iphdr->ttl = stack->ttl;
	new_iphdr->tot_len = htons(sizeof(iphdr_t) + sizeof(tcphdr_t) + TCPOLEN_MSS + TCPOPT_NOP + TCPOLEN_WINDOW );
	new_iphdr->protocol = IP_PROTO_TCP;
	new_iphdr->id = stack->ipid++;
	new_iphdr->ihl = 5;
	new_iphdr->version = 4;
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_tcphdr->check = ~upper_layer_chksum(new_iphdr, IP_PROTO_TCP);

	stack->verbose(stack_warning_level_1, "send tcp syn ack ");

	send_packet(stack, packet, ethhdr->ether_shost, ETH_P_IP);
	return 0;
}

void send_reset(stack_t * stack, tcp_session_hash_header_t * connection,packet_t * packet)
{
	ether_t * ethhdr = packet_eth_hdr(packet);
	iphdr_t * iphdr = packet_ip_hdr(packet);
	tcphdr_t * tcphdr = packet_tcp_hdr(packet);
	packet_reserve(stack, packet, ETH_HDR_LEN + sizeof(iphdr_t) + sizeof(tcphdr_t));
	tcphdr_t * new_tcphdr = (tcphdr_t*)packet_push(packet, sizeof(tcphdr_t));
	memset(new_tcphdr, 0, sizeof(tcphdr_t));
	new_tcphdr->ack_seq = connection->info.recv_next.u.integer_value;
	new_tcphdr->seq = connection->info.send_next.u.integer_value;
	tcp_send_next_add(connection, 1);
	new_tcphdr->source = connection->info.dstport;
	new_tcphdr->dest = connection->info.srcport;
	new_tcphdr->window = 0;
	new_tcphdr->rst = 1;
	new_tcphdr->doff = ((sizeof(tcphdr_t)) / 4);
	iphdr_t * new_iphdr = packet_push(packet, sizeof(iphdr_t));
	memset(new_iphdr, 0, sizeof(iphdr_t));
	new_iphdr->saddr = connection->info.dst;
	new_iphdr->daddr = connection->info.src;
	new_iphdr->ttl = stack->ttl;
	new_iphdr->tot_len = htons(sizeof(iphdr_t) + sizeof(tcphdr_t));
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_iphdr->id = stack->ipid++;
	new_iphdr->ihl = 5;
	new_iphdr->version = 4;
	new_iphdr->protocol = IP_PROTO_TCP;
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_tcphdr->check = ~upper_layer_chksum(new_iphdr, IP_PROTO_TCP);


	stack->verbose(stack_warning_level_1, "send tcp rst ");

	send_packet(stack, packet, ethhdr->ether_shost, ETH_P_IP);

}

void send_ack(stack_t * stack, tcp_session_hash_header_t * connection, packet_t * packet)
{
	ether_t * ethhdr = packet_eth_hdr(packet);
	iphdr_t * iphdr = packet_ip_hdr(packet);
	tcphdr_t * tcphdr = packet_tcp_hdr(packet);
	
	packet_reserve(stack, packet, ETH_HDR_LEN + sizeof(iphdr_t) + sizeof(tcphdr_t));
	tcphdr_t * new_tcphdr = (tcphdr_t*)packet_push(packet, sizeof(tcphdr_t));
	memset(new_tcphdr, 0, sizeof(tcphdr_t));
	new_tcphdr->ack_seq = connection->info.recv_next.u.integer_value;
	new_tcphdr->seq = connection->info.send_next.u.integer_value;

	new_tcphdr->source = connection->info.dstport;
	new_tcphdr->dest = connection->info.srcport;
	new_tcphdr->ack = 1;
	new_tcphdr->window = 1;// connection->info.wndsize;
	new_tcphdr->doff = ((sizeof(tcphdr_t)) / 4);
	iphdr_t * new_iphdr = packet_push(packet, sizeof(iphdr_t));
	memset(new_iphdr, 0, sizeof(iphdr_t));
	new_iphdr->saddr = connection->info.dst;
	new_iphdr->daddr = connection->info.src;
	new_iphdr->ttl = stack->ttl;
	new_iphdr->tot_len = htons(sizeof(iphdr_t) + sizeof(tcphdr_t));
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_iphdr->id = stack->ipid++;
	new_iphdr->ihl = 5;
	new_iphdr->version = 4;
	new_iphdr->protocol = IP_PROTO_TCP;
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_tcphdr->check = ~upper_layer_chksum(new_iphdr, IP_PROTO_TCP);

	stack->verbose(stack_warning_level_1, "send tcp ack ");

	send_packet(stack, packet, ethhdr->ether_shost, ETH_P_IP);

}

void send_fin(stack_t * stack, tcp_session_hash_header_t * connection, packet_t * client_packet)
{
	ether_t * ethhdr = packet_eth_hdr(client_packet);
	iphdr_t * iphdr = packet_ip_hdr(client_packet);
	tcphdr_t * tcphdr = packet_tcp_hdr(client_packet);
	packet_t * packet = alloc_packet(stack);


	packet_reserve(stack, packet, ETH_HDR_LEN + sizeof(iphdr_t) + sizeof(tcphdr_t));
	tcphdr_t * new_tcphdr = (tcphdr_t*)packet_push(packet, sizeof(tcphdr_t));
	memset(new_tcphdr, 0, sizeof(tcphdr_t));
	new_tcphdr->ack_seq = connection->info.recv_next.u.integer_value;
	new_tcphdr->seq = connection->info.send_next.u.integer_value;
	//	tcp_send_next_add(connection, 1);
	new_tcphdr->source = connection->info.dstport;
	new_tcphdr->dest = connection->info.srcport;
	new_tcphdr->ack = 0;
	new_tcphdr->fin = 1;
	new_tcphdr->window = 0;// connection->info.wndsize;
	new_tcphdr->doff = ((sizeof(tcphdr_t)) / 4);
	iphdr_t * new_iphdr = packet_push(packet, sizeof(iphdr_t));
	memset(new_iphdr, 0, sizeof(iphdr_t));
	new_iphdr->saddr = connection->info.dst;
	new_iphdr->daddr = connection->info.src;
	new_iphdr->ttl = stack->ttl;
	new_iphdr->tot_len = htons(sizeof(iphdr_t) + sizeof(tcphdr_t));
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_iphdr->id = stack->ipid++;
	new_iphdr->ihl = 5;
	new_iphdr->version = 4;
	new_iphdr->protocol = IP_PROTO_TCP;
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_tcphdr->check = ~upper_layer_chksum(new_iphdr, IP_PROTO_TCP);

	stack->verbose(stack_warning_level_1, "send tcp fin ");

	send_packet(stack, packet, ethhdr->ether_shost, ETH_P_IP);

}
void increment_iss(stack_t * stack)
{
	if (stack->iss.u.byte_value.s1++ == 0)
	{
		if (stack->iss.u.byte_value.s2++ == 0)
		{
			if (stack->iss.u.byte_value.s3++ == 0)
			{
				stack->iss.u.byte_value.s4++;
			}
		}
	}
}
int tcp_inpput(stack_t * stack, packet_t * packet)
{
	iphdr_t * iphdr = packet_ip_hdr(packet);
	tcphdr_t * tcphdr = packet_tcp_hdr(packet);
	uint32_t tcphash = tcp_hash(iphdr, tcphdr);
	tcp_session_hash_header_t * connection = NULL;
	void * key;
	int n = 0;
	timer_check(stack);
	increment_iss(stack);
	
	if (tcphdr->syn && !tcphdr->ack)
	{
		//connect to our host
		tcp_listener_hash_header_t * listener;
		key = (void*)tcphdr->dest;
		HASH_FIND_PTR(stack->tcp_listeners, &key, listener);
		if (listener)
		{
			return send_synack(stack, tcphash,packet, listener);
		}
		return -1;
	}
	if (tcphdr->rst)
	{
		if (connection)
		{
			connection->on_reset(connection);
			reset_timer(stack, connection);
			HASH_DEL(stack->tcp_sessions, connection);
			connection->info.state = TCP_CONNECTION_CLOSED;
			free_connection(stack, connection);
		}

		return 0;
	}

	key = (void*)tcphash;
	HASH_FIND_PTR(stack->tcp_sessions, (void*)&key, connection);
	if (!connection)
	{
		if (tcphdr->ack)
		{
			//the connection to become established
			//connect to our host
			tcp_listener_hash_header_t * listener;
			key = (void*)tcphdr->dest;
			HASH_FIND_PTR(stack->tcp_listeners, &key, listener);

			if (listener)
			{
				key = (void*)tcphash;
				HASH_FIND_PTR(listener->tcp_half_connections, (void*)&key, connection);
				if (!connection)
				{
					stack->verbose(stack_warning_level_4, "the half-connection could not be found");
					return -1;
				}

				return tcp_establish(stack, tcphash, packet, listener, connection);
			}
		}

		return -1;
	}


	n = packet_tcp_payload_size(packet);
	//if (connection->info.recv_next.u.integer_value == htonl(htonl(tcphdr->seq) + n))
	//{
	//	//it is a retransmit packet , should be dropped
	//	return -1;
	//}
	switch (connection->info.state)
	{
	case TCP_CONNECTION_FIN_WAIT_1:
	{
		if (tcphdr->ack)
		{
			connection->info.state = TCP_CONNECTION_FIN_WAIT_2;
		}
		
	}
	break;
	case TCP_CONNECTION_FIN_WAIT_2:
	{
		
		if (tcphdr->fin)
		{
			//fixed me :  add timer to finalize this connection
			connection->info.state = TCP_CONNECTION_LAST_ACK;
			tcp_recv_next_add(connection, 1);

			if (tcphdr->psh)
			{
				tcp_recv_next_add(connection, n);
				if (n > 0)
				{
					connection->on_data(connection, packet_tcp_payload(packet), n);
				}
			}

			send_ack(stack, connection, packet);
		}
		
	}
	break;

	case TCP_CONNECTION_LAST_ACK:
	{

		send_ack(stack, connection, packet);
	}
	break;
	case TCP_CONNECTION_ESTABLISHED:
	{
		tcp_recv_next_add(connection, n);

		send_ack(stack, connection, packet);

		if (n > 0)
		{
			connection->on_data(connection, packet_tcp_payload(packet), n);
			
		}
		printf("TCP_CONNECTION_ESTABLISHED  send seq : %d \n", send_seq(connection));

		if (tcphdr->fin)
		{
			connection->info.state = TCP_CONNECTION_LAST_ACK;
			send_fin(stack, connection, packet);
		}
		
	}
	break;
	}
	return 0;

}
int ip_input(stack_t * stack, packet_t * packet)
{
	iphdr_t * iphdr = packet_ip_hdr(packet);
	if (iphdr->version != 4)
	{
		return -1;
	}
	if (iphdr->protocol == IP_PROTO_TCP)
	{
		tcp_inpput(stack, packet);
	}

	return 0;
}
void * create_client(stack_t * stack, uint32_t source_ip,uint16_t source_port,uint32_t target_ip,uint16_t target_port)
{
	tcp_session_hash_header_t * connection = alloc_connection(stack);
	if (connection)
	{
		connection->key = (void*)tcp_hash2(target_ip, target_port, source_port);
		HASH_ADD_PTR(stack->tcp_sessions, key, connection);
		memset(&connection->info, 0, sizeof(tcp_connection_info_t));
		connection->info.state = TCP_CONNECTION_SYN_SENT;
		connection->info.dst = target_ip;
		connection->info.src = source_ip;
		connection->info.dstport = target_port;
		connection->info.srcport = source_port;
		connection->info.initialmss = stack->max_packet_size - sizeof(ether_t) - sizeof(iphdr_t) - sizeof(tcphdr_t);
		connection->info.len = 1;
		connection->info.rto = stack->rto;
		connection->info.timer = stack->rto;
		connection->info.sv = 4;
		connection->info.wndsize = htons(tcp_mss(stack));
		connection->info.send_next.u.integer_value = stack->iss.u.integer_value;
		connection->info.recv_next.u.integer_value = 0;
		connection->on_establish = stack->tcp_listeners->on_establish;
		connection->on_reset = stack->tcp_listeners->on_reset;
		connection->on_data = stack->tcp_listeners->on_data;



	}
	else
	{
		stack->verbose(stack_warning_level_4, "could not allocate new connection while create_client ");
		return -1;
	}
	return connection;
}
void * create_listener(stack_t * stack, uint16_t port, \
	int(*pre_accept)(tcp_session_hash_header_t * fd, uint32_t sip, uint16_t sport, uint16_t dport), \
	int(*on_accept)(tcp_session_hash_header_t * fd, uint32_t sip, uint16_t sport, uint16_t dport),\
	int(*on_reset)(struct tcp_session_hash_header_s  *fd),\
	void(*on_establish)(struct tcp_session_hash_header_s * fd, struct tcp_session_hash_header_s  *client),\
	int (*on_data)(struct tcp_session_hash_header_s  *fd, void * data, int data_size))
{
	tcp_listener_hash_header_t * listener = stack->st_malloc(sizeof(tcp_listener_hash_header_t));
	memset(listener, 0, sizeof(tcp_listener_hash_header_t));
	listener->key = (void*)htons(port);
	listener->on_accept = on_accept;
	listener->pre_accept = pre_accept;
	listener->on_reset = on_reset;
	listener->on_establish = on_establish;
	listener->on_data = on_data;
	HASH_ADD_PTR(stack->tcp_listeners, key, listener);
	return listener;
}
int32_t stack_input(stack_t * stack, int8_t * data, uint16_t data_len)
{
	packet_t * packet = alloc_packet(stack);
	ether_t *hdr = packet_eth_hdr(packet);

	if (construct_packet(stack, packet, data, data_len) != 0)
	{
		return -1;
	}
	

	switch (htons(hdr->ether_type))
	{
	case ETH_P_ARP:
		arp_rcv(stack, packet);
		break;
	case ETH_P_IP:
		ip_input(stack, packet);
		break;
	case ETH_P_IPV6:
	default:
		
		break;
	}

	return 0;
}

uint32_t stack_output(stack_t * stack)
{
	packet_t *  packet = NULL;
	list_t * cur = stack->out_stack.next;
	while (!ministack_list_empty(&stack->out_stack))
	{
		 
		packet = list_first_entry(&stack->out_stack, packet_t, link);
		stack->dev_write(packet->pos, packet->end - packet->pos);
		
		ministack_list_del(stack->out_stack.next);
		free_packet(stack, packet);
	}

	return 0;
}

void stack_init(stack_t * stack, char * hwaddr, unsigned int ip, uint32_t (*dev_lookup)(uint32_t ip, uint8_t* macbuf),\
	uint16_t(*dev_read)(void *, uint16_t), \
	uint16_t(*dev_write)(void *, uint16_t), void* (*st_malloc)(uint16_t), void(*st_free)(void*), \
	void(*verbose)(uint16_t level, const char*), uint32_t(*timetick)())
{
	memset(stack , 0 , sizeof(stack_t));
	stack->dev_read = dev_read;
	stack->dev_write = dev_write;
	stack->st_malloc = st_malloc;
	stack->st_free = st_free;
	stack->verbose = verbose;
	stack->timetick = timetick;
	stack->dev_lookup = dev_lookup;
	stack->iss.u.integer_value = 0x10101010;
	stack->ipid = 0x1010;
	stack->ip_addr.iplong = ip;
	stack->max_packet_size = 1000;
	stack->rto = 3;
	stack->ttl = 64;
	ministack_list_init(&stack->out_stack);
	ministack_list_init(&stack->lookaside_list);
	memcpy(stack->ether_addr, hwaddr, 6);
	
	rbtree_init(&stack->timer, &stack->sentinel, rbtree_insert_value);
}
int32_t stack_close(stack_t * stack, void * conn)
{
	tcp_session_hash_header_t * connection = (tcp_session_hash_header_t *)conn;
	if (connection->info.state != TCP_CONNECTION_ESTABLISHED)
	{
		return -1;
	}
	packet_t *packet = alloc_packet(stack);
	uint8_t dstdev[6] = { 0 };
	packet_reserve(stack, packet, ETH_HDR_LEN + sizeof(iphdr_t) + sizeof(tcphdr_t));

	tcphdr_t * new_tcphdr = (tcphdr_t*)packet_push(packet, sizeof(tcphdr_t));
	memset(new_tcphdr, 0, sizeof(tcphdr_t));
	new_tcphdr->ack_seq = connection->info.recv_next.u.integer_value;
	new_tcphdr->seq = connection->info.send_next.u.integer_value;
	
	new_tcphdr->source = connection->info.dstport;
	new_tcphdr->dest = connection->info.srcport;
	new_tcphdr->fin = 1;
	new_tcphdr->ack = 1;
	new_tcphdr->window = 1;// connection->info.wndsize;
	new_tcphdr->doff = ((sizeof(tcphdr_t)) / 4);
	iphdr_t * new_iphdr = packet_push(packet, sizeof(iphdr_t));
	memset(new_iphdr, 0, sizeof(iphdr_t));
	new_iphdr->saddr = connection->info.dst;
	new_iphdr->daddr = connection->info.src;
	new_iphdr->ttl = stack->ttl;
	new_iphdr->tot_len = htons(sizeof(iphdr_t) + sizeof(tcphdr_t));
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_iphdr->id = stack->ipid++;
	new_iphdr->ihl = 5;
	new_iphdr->version = 4;
	new_iphdr->protocol = IP_PROTO_TCP;
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_tcphdr->check = ~upper_layer_chksum(new_iphdr, IP_PROTO_TCP);

	stack->dev_lookup(new_iphdr->daddr, dstdev);



	stack->verbose(stack_warning_level_1, "send tcp ack ");



	send_packet(stack, packet, dstdev, ETH_P_IP);

	tcp_send_next_add(connection, 1);

	connection->info.state = TCP_CONNECTION_FIN_WAIT_1;

	return 0;
}
int32_t stack_send(stack_t * stack, void * conn, void * data, int data_len)
{
	tcp_session_hash_header_t * connection = (tcp_session_hash_header_t *)conn;
	packet_t *packet = NULL;
	uint8_t dstdev[6] = { 0 };
	if (connection->info.state != TCP_CONNECTION_ESTABLISHED)
	{
		return -1;
	}
	packet = alloc_packet(stack);
	packet_reserve(stack, packet, ETH_HDR_LEN + sizeof(iphdr_t) + sizeof(tcphdr_t) + data_len);
	memcpy((void*)packet_push(packet, data_len), data, data_len);
	tcphdr_t * new_tcphdr = (tcphdr_t*)packet_push(packet, sizeof(tcphdr_t));
	memset(new_tcphdr, 0, sizeof(tcphdr_t));
	new_tcphdr->ack_seq = connection->info.recv_next.u.integer_value;
	new_tcphdr->seq = connection->info.send_next.u.integer_value;
	tcp_send_next_add(connection, data_len);
	new_tcphdr->source = connection->info.dstport;
	new_tcphdr->dest = connection->info.srcport;
	new_tcphdr->ack = 1;
	new_tcphdr->psh = 1;
	new_tcphdr->window = connection->info.wndsize;
	new_tcphdr->doff = ((sizeof(tcphdr_t)) / 4);
	iphdr_t * new_iphdr = packet_push(packet, sizeof(iphdr_t));
	memset(new_iphdr, 0, sizeof(iphdr_t));
	new_iphdr->saddr = connection->info.dst;
	new_iphdr->daddr = connection->info.src;
	new_iphdr->ttl = stack->ttl;
	new_iphdr->tot_len = htons(sizeof(iphdr_t) + sizeof(tcphdr_t) + data_len);
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_iphdr->id = stack->ipid++;
	new_iphdr->ihl = 5;
	new_iphdr->version = 4;
	new_iphdr->protocol = IP_PROTO_TCP;
	new_iphdr->check = 0;
	new_iphdr->check = ~ipchksum(new_iphdr);
	new_tcphdr->check = ~upper_layer_chksum(new_iphdr, IP_PROTO_TCP);

	stack->dev_lookup(new_iphdr->daddr, dstdev);



	stack->verbose(stack_warning_level_1, "send tcp ack ");



	send_packet(stack, packet, dstdev, ETH_P_IP);

	return data_len;
}