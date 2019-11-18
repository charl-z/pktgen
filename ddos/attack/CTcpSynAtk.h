#ifndef _TCP_SYN_ATK_H
#define _TCP_SYN_ATK_H

#include "pktbuild.h"

class CTcpSynAtk : public CAttack {
public:
	CTcpSynAtk():CAttack(){
		strncpy(m_name, "synflood", 31);
		m_params.m_iph_proto = IPPROTO_TCP;
	}
	CTcpSynAtk(const CDDoSParam& param) :CAttack(param){
		strncpy(m_name, "synflood", 31);
		m_params.m_iph_proto = IPPROTO_TCP;

		if(m_params.m_issyn64!=true){
			unsigned char tcp_options[20] = {
				0x02, 0x04, 0x05, 0xb4,
				0x04, 0x02,
				0x08, 0x0a, 0x00, 0x0b, 0x4a, 0x5f, 0x00, 0x00, 0x00, 0x00,
				0x01,
				0x03, 0x03, 0x06
			};	
			int len = sizeof(tcp_options);
			for(int i=0; i<len ; i++){
				m_params.m_tcp_options[i] = tcp_options[i];
			}
			m_params.m_tcpoptionflag = sizeof(tcp_options);		
		}else{
			m_params.m_tcpoptionflag=0;
		}
	}

	virtual ~CTcpSynAtk(){
	// TODO Auto-generated destructor stub
	}

	int32_t attack_one_pkt(int thrd_index);
	pdu_l3_desc_t get_layer3_info();

    int32_t start();
    void stop();
	uint32_t modify_tcp_syn(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload);
	uint32_t build_tcp_syn(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload);
};

#endif
