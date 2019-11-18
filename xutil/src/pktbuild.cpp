/*
 * pktbuild.cpp
 *
 *  Created on: 2016年11月1日
 *      Author: cht
 */

#ifdef _RPS_LINUX
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "tcpip.h"
#include "utilstr.h"
#include "ipparser.h"
#include "rand.h"
#include "pktbuild.h"
#include "xtool.h"

//tcp的选项和填充
unsigned char g_tcp_options[] = {
		0x02, 0x04, 0x05, 0xb4,
		0x04, 0x02,
		0x08, 0x0a, 0x00, 0x0b, 0x4a, 0x5f, 0x00, 0x00, 0x00, 0x00,
		0x01,
		0x03, 0x03, 0x06
};
		
 
 

static inline uint16_t in_chksum_tcp(uint16_t *h, uint16_t *d, uint16_t dlen)
{
    unsigned int cksum;
    unsigned short answer = 0;

    // PseudoHeader must have 12 bytes
    cksum  = h[0];
    cksum += h[1];
    cksum += h[2];
    cksum += h[3];
    cksum += h[4];
    cksum += h[5];

    // TCP hdr must have 20 hdr bytes
    cksum += d[0];
    cksum += d[1];
    cksum += d[2];
    cksum += d[3];
    cksum += d[4];
    cksum += d[5];
    cksum += d[6];
    cksum += d[7];
    cksum += d[8];
    cksum += d[9];

    dlen  -= 20; // bytes
    d     += 10; // short's

    while(dlen >= 32)
    {
        cksum += d[0];
        cksum += d[1];
        cksum += d[2];
        cksum += d[3];
        cksum += d[4];
        cksum += d[5];
        cksum += d[6];
        cksum += d[7];
        cksum += d[8];
        cksum += d[9];
        cksum += d[10];
        cksum += d[11];
        cksum += d[12];
        cksum += d[13];
        cksum += d[14];
        cksum += d[15];
        d     += 16;
        dlen  -= 32;
    }

    while(dlen >= 8)
    {
        cksum += d[0];
        cksum += d[1];
        cksum += d[2];
        cksum += d[3];
        d     += 4;
        dlen  -= 8;
    }

    while(dlen > 1)
    {
        cksum += *d++;
        dlen  -= 2;
    }

    if( dlen == 1 )
    {
        *(unsigned char *)(&answer) = (*(unsigned char *)d);
        cksum += answer;
    }

    cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
    cksum += (cksum >> 16);

    return (unsigned short)(~cksum);
}

uint16_t compute_tcp_checksum(IP_HEADER_T *ip_header, TCP_HEADER_T *tcp_header, uint16_t tcp_len)
{
	PSD_HEADER_T ph = {ip_header->sourceIP,
    		ip_header->destIP,
    		0,
    		ip_header->proto,
    		htons(tcp_len)};

    return in_chksum_tcp((uint16_t *)&ph, (uint16_t *)tcp_header, tcp_len);
}

 



//构造报文存入buff中，如果buffer_len < ip头+udp头和负载信息的长度则构建失败
 