/*
 * tcpip.h
 *
 *  Created on: 2016年7月18日
 *      Author: cht
 */

#ifndef TCPIP_H_
#define TCPIP_H_
#define IP6_HEADER_SIZE 40
#define IP4_HEADER_SIZE 20



#define FLAG_FIN  0x01  /* F : FIN - 结束; 结束会话 */
#define FLAG_SYN  0x02  /* S : SYN - 同步; 表示开始会话请求 */
#define FLAG_RST  0x04  /* R : RST - 复位;中断一个连接 */
#define FLAG_PSH  0x08  /* P : PUSH - 推送; 数据包立即发送 */
#define FLAG_ACK  0x10  /* A : ACK - 应答 */
#define FLAG_URG  0x20  /* U : URG - 紧急 */
#define FLAG_ECE  0x40  /* E : ECE - 显式拥塞提醒回应 */
#define FLAG_CWR  0x80  /* W : CWR - 拥塞窗口减少 */

typedef struct _IP_HEADER
{
	uint8_t    h_lenver;
	uint8_t   tos;
    uint16_t  total_len;
    uint16_t  ident;
    uint16_t  frag_and_flags;
    uint8_t   ttl;
    uint8_t   proto;
    uint16_t  checksum;
    uint32_t    sourceIP;
    uint32_t    destIP;
} IP_HEADER_T;




struct ip6_addr
{
    uint32_t addr[4];
};
typedef struct ip6_addr ip6_addr_t;




typedef struct _IP_V6_HEADER
{
    uint8_t priority: 4,   //ds字段和ecn(需要加上)
            version: 4;    //版本
    uint8_t flow_lbl[3];   //流标签 20位
    uint16_t payload_len; //负载长度 z指ipv6头部后面的
    uint8_t nexthdr;  //下一个头部 这里定义为layer3层的协议类型，暂时不支持其他路由扩展等
    uint8_t hop_limit; //下一跳限制
    ip6_addr_t sourceIP;
    ip6_addr_t destIP; //
} IP_V6_HEADER_T;


/*
//ipv6结构体 固定40字节
typedef struct _IP_V6_HEADER
{
	uint8_t   h_lenver;
	uint8_t   tos;
    uint16_t  total_len;
    uint16_t  ident;
    uint16_t  frag_and_flags;
    uint8_t   ttl;
    uint8_t   proto;
    uint16_t  checksum;
    uint32_t    sourceIP;
    uint32_t    destIP;
} IP_V6_HEADER_T;

*/

typedef struct _TCP_HEADER
{
	uint16_t th_sport;
	uint16_t th_dport;
	uint32_t th_seq;
	uint32_t th_ack;
    uint8_t th_lenres;
    uint8_t th_flag;
    uint16_t th_win;
    uint16_t th_sum;//检验和
    uint16_t th_urp;//紧急指针
} TCP_HEADER_T;

typedef struct _UDP_HEADER
{
    uint16_t th_sport;
    uint16_t th_dport;
    uint16_t th_len;
    uint16_t th_sum;
} UDP_HEADER_T;

typedef struct _ICMP_HEADER
{
	uint8_t icmp_type;    // 消息类型
	uint8_t icmp_code;		// 代码
	uint16_t icmp_sum;   // 校验和
	uint16_t icmp_Id;   // 用来唯一标识此请求的id号，通常设置为进程id
	uint16_t icmp_Seq;  // 序列号
						//icmp_header里的icmp_id,在libnet-headers.h里有同名的定义.所以id改为Id seq改为Seq
	//uint32_t icmp_timestamp; // 时间戳
} ICMP_HEADER_T;



typedef struct _PSD_HEADER
{
	uint32_t saddr;
	uint32_t daddr;
	uint8_t resv;
	uint8_t ptcl;
    uint16_t tcpl;
} PSD_HEADER_T;



struct dnshdr {
    uint16_t id, opts, qdcount, ancount, nscount, arcount;
};

struct dns_question {
    uint16_t qtype, qclass;
};

struct dns_resource {
    uint16_t type, _class;
    uint32_t ttl;
    uint16_t data_len;
} __attribute__((packed));

#endif /* TCPIP_H_ */
