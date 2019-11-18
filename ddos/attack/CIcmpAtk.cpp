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
#include "CIcmpAtk.h"

//CIcmpAtk::CIcmpAtk() : CAttack(){
//	strncpy(m_name, "udpflood", 31);
//}


/*
pdu_l3_desc_t CIcmpAtk::get_layer3_info(){
	pdu_l3_desc_t layer3;

	layer3.vlanid = m_params.m_vlan_id;
	layer3.dstaddr = get_cur_dstaddr();
	layer3.srcaddr = get_cur_srcaddr();
	layer3.identity = m_params.m_identity;
	layer3.ttl = m_params.m_ttl;

	layer3.dont_frag = m_params.m_dont_frag;
	layer3.dport = get_cur_dstport();
	layer3.sport = get_cur_srcport();
	layer3.payload_len = m_params.m_payload_len;
	layer3.icmptype = m_params.m_icmp_type;
	return pdu_l3_desc_t;

}


int32_t CIcmpAtk::attack_one_pkt(int thrd_index)
{
	pdu_l3_desc_t layer3 =get_layer3_info();


	RC_LOG_INFO("CIcmpAtk.h attack_one_pkt layer3.icmptype = %d \n", layer3.icmptype);


	int pkt_len = modify_icmp(&layer3, m_pkt_buf[thrd_index], ATTACK_BUF_LEN, NULL);

    sendpkt( layer3.dstaddr,  layer3.dport,  pkt_len, int thrd_index);

	return RC_OK;
}


int32_t CIcmpAtk::start()
{
	RC_LOG_INFO("CIcmpAtk.h start is called \n");

	uint32_t ii = 0;
 	pdu_l3_desc_t layer3 = get_layer3_info();
 

	RC_LOG_INFO("CIcmpAtk.h start layer3.icmptype = %d \n", layer3.icmptype);

	for (ii = 0; ii < g_thrd_cnt; ii++)
	{
		m_fd[ii] = init_raw_udp_socket();
		if (m_fd[ii] == -1)
		{
			return RC_ERROR;
		}

		m_pkt_buf[ii] = (char*)malloc(ATTACK_BUF_LEN);
		modify_icmp(&layer3, m_pkt_buf[ii], ATTACK_BUF_LEN, m_params.m_payload_data);
	}
	return RC_OK;
}

void CIcmpAtk::stop()
{
	common_free();
}
*/
