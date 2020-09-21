#pragma once
#include "stdafx.h"
#include <pcap.h>

#define DEVICE_NAMEW L"NPF"
#define DRIVER_SERVICE "NPF"

class pcapdev
{
public:

	pcapdev(unsigned int target_ip, char * filter)
	{
		char errbuf[PCAP_ERRBUF_SIZE + 1];
		char *source = NULL;
		char *ofilename = NULL;
		pcap_if_t *alldevs;
		pcap_if_t *d;
		pcap_if_t *target_dev = NULL;
		struct bpf_program fcode;
		bpf_u_int32 NetMask;
		unsigned long tid;

		NpfSetName(DEVICE_NAMEW, DRIVER_SERVICE);
		do
		{
			/* Retrieve the device list */
			if (pcap_findalldevs(&alldevs, errbuf) == -1)
			{
				throw  std::runtime_error("pcap_findalldevs err");
				break;
			}

			/* Scan the list printing every entry */
			for (d = alldevs; d; d = d->next)
			{
				for (pcap_addr_t * a = d->addresses; a; a = a->next)
				{
					if (((struct sockaddr_in *)a->addr)->sin_family == AF_INET && ((struct sockaddr_in *)a->addr)->sin_addr.s_addr == target_ip)
					{

						target_dev = d;
						break;
					}
				}
			}
			if (target_dev == NULL)
			{
				throw  std::runtime_error("target_dev == NULL");
				break;
			}


			// open a capture from the network

			if ((handle = pcap_open_live(target_dev->name,		// name of the device
				65536,								// portion of the packet to capture. 
													// 65536 grants that the whole packet will be captured on all the MACs.
				1,									// promiscuous mode (nonzero means promiscuous)
				1,								// read timeout
				errbuf								// error buffer
			)) == NULL)
			{
				/* Free the device list */
				pcap_freealldevs(alldevs);
				throw  std::runtime_error("pcap_open_live failed");
				break;
			}


			/* Free the device list */
			pcap_freealldevs(alldevs);
			if (filter)
			{
				// We should loop through the adapters returned by the pcap_findalldevs_ex()
				// in order to locate the correct one.
				//
				// Let's do things simpler: we suppose to be in a C class network ;-)
				NetMask = 0xffffff;

				//compile the filter
				if (pcap_compile((pcap_t *)handle, &fcode, filter, 1, NetMask) < 0)
				{
					pcap_close((pcap_t *)handle);
					handle = NULL;
					throw  std::runtime_error("pcap_compile failed");
					break;
				}

				//set the filter
				if (pcap_setfilter((pcap_t *)handle, &fcode) < 0)
				{
					pcap_close((pcap_t *)handle);
					handle = NULL;
					throw  std::runtime_error("pcap_setfilter failed");
					break;
				}
			}
			pcap_setmintocopy((pcap_t *)handle, 1);//to raise respond time

		} while (0);

	}
	~pcapdev()
	{
		if (handle != NULL)
		{
			pcap_close(handle);
		}
	}
	int pcapdev_read(void * buf, int bufsize,int timeout)
	{
		const u_char* packet;
		struct pcap_pkthdr* header;
		int res = 0;
		int  tick = GetTickCount();
		//debug("Waiting for ethernet packet\n");
		while (res <= 0)
		{
			res = pcap_next_ex(handle, &header, &packet);
			if (res == 0 && GetTickCount() - tick > timeout)
			{
				return 0;
			}
		}
		int readSize = (int)header->len >= bufsize ? bufsize : (int)header->len;

		memcpy(buf, packet, readSize);
		return readSize;
	}

	int pcapdev_send(void * buf, int bufsize)
	{
		if (pcap_sendpacket(handle, (const unsigned char*)buf, bufsize) == -1)
		{
			return 0;
		 }
		return bufsize;
	}

	private:
		pcap_t * handle = NULL;
};