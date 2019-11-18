/*
 * pktbuild.h
 *
 *  Created on: 2016年11月1日
 *      Author: cht
 */

#ifndef PKTBUILD_H_
#define PKTBUILD_H_

#include "tcpip.h"
#include <libnet.h>



enum
{
	SEND_OK = 0,
	SEND_EAGAIN,
	SEND_FAILED,
};
	
enum ip_type
{
	IP_V4 = 0,
	IP_V6
};


extern unsigned char g_tcp_options[20];


typedef struct pdu_l3_descript{
    uint32_t vlanid;

    /*ip header info*/
    uint32_t dstaddr;
    uint32_t srcaddr;
	libnet_in6_addr dstaddr6;
	libnet_in6_addr srcaddr6;
    uint32_t identity;
    bool dont_frag;
    uint8_t ttl;

    /*tcp/udp/icmp head info*/
    uint16_t dport;
    uint16_t sport;
    uint8_t tcpflag;
	uint8_t tcpoptionflag; //tcp的可选项长度标志 0 无可选项 1 可选项默认  其他为长度
	uint8_t tcpoptions[40]; //可选项内容
	uint8_t icmptype;   //icmptype=0 表示reply, icmptype=8 表示request
	//uint8_t icmpcode;
    uint32_t seq;
    uint32_t ack;
    bool syn64; /*is syn packet without options*/
	uint8_t ip_type;//ipv4 or ipv6
	uint8_t iph_proto;
   
    uint32_t payload_len;
	uint32_t layer3_total_len;
}pdu_l3_desc_t;

typedef struct pdu_http_descript{
	uint8_t m_http_url[256];
	uint8_t m_http_path[256];
}pdu_http_desc_t;

uint16_t compute_tcp_checksum(IP_HEADER_T *ip_header, TCP_HEADER_T *tcp_header, uint16_t tcp_len);
uint16_t compute_udp_checksum(IP_HEADER_T *ip_header, UDP_HEADER_T *udp_header, uint16_t udp_len);
//uint16_t compute_icmp_checksum(ICMP_HEADER_T *icmp_header, uint16_t icmp_len);

extern uint32_t modify_tcp_syn(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload);
extern uint32_t build_tcp_syn(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload);

extern uint32_t modify_tcp_ack(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload);


extern uint32_t modify_udp(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload);

extern uint32_t modify_icmp(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload);





#endif /* PKTBUILD_H_ */
