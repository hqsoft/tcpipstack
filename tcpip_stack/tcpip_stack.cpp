// tcpip_stack.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "pcapdev.hpp"
extern "C"
{
#include "stack.h"

}
pcapdev *dev = NULL;


uint16_t dev_read(void * p, uint16_t n)
{
	return dev->pcapdev_read(p, n,10000);
}
uint16_t dev_write(void * p, uint16_t n)
{
	return dev->pcapdev_send(p, n);
}	
void* st_malloc(uint16_t n)
{
	return malloc(n);
}
void st_free(void*p)
{
	free(p);
}
void verbose(uint16_t level, const char* s)
{
	printf("%s \n", s);
}
int pre_accept(tcp_session_hash_header_t * fd, uint32_t sip, uint16_t sport, uint16_t dport)
{
	return 1;
}
int on_accept(tcp_session_hash_header_t * fd, uint32_t sip, uint16_t sport, uint16_t dport)
{
	return 1;
}
int on_reset (struct tcp_session_hash_header_s  *fd)
{
	printf("on_reset \n");
	return 0;
}
void on_establish (struct tcp_session_hash_header_s * fd, struct tcp_session_hash_header_s  *client)
{
	printf("on_establish \n");
	return;
}
uint32_t dev_lookup(uint32_t ip, uint8_t* macbuf)
{
	uint8_t mac[] = { 00 ,0x0C , 0x29 , 0x9B , 0x73 , 00 };
	memcpy(macbuf, mac, 6);
	return 0;
}
stack_t * stack1;
int on_data(struct tcp_session_hash_header_s  *fd,void * data , int data_size)
{
	char * buf = new char[data_size + 1];
	memset(buf, 0, data_size + 1);
	memcpy(buf, data, data_size);
	printf("on %s\n",buf);
	delete[] buf;
	stack_send(stack1, fd, "b\n", 2);
	stack_close(stack1, fd);
	return data_size;
}
unsigned int get_timetick()
{
	return GetTickCount();
}
int main()
{
	stack_t stack = { 0 };
	stack1 = &stack;
	char ether_addr[6] = { 0x11,0x22,0x33,0x44,0x55,0x66 };
	stack_init(&stack, ether_addr, inet_addr("192.168.16.88"), dev_lookup, dev_read, dev_write, st_malloc, st_free, verbose, get_timetick);


	create_listener(&stack, 11, pre_accept, on_accept,on_reset, on_establish, on_data);

	dev = new pcapdev(inet_addr("192.168.16.134"), "arp or ip host 192.168.16.88");
	char buf[2048];
	while (true)
	{
		int n = dev->pcapdev_read(buf, 2048,40);
		if (n > 0)
		{
			stack_input(&stack, (int8_t*)buf, n);
			stack_output(&stack);
		}
		else if (n == 0)
		{
			//timeout
			stack_output(&stack);
		}
	}
	

    return 0;
}

