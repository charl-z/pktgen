#ifndef _DNS_ATK_H
#define _DNS_ATK_H

#include "pktbuild.h"


#define PROTO_DNS_QTYPE_A       1
#define PROTO_DNS_QCLASS_IP     1


class CDnsAtk : public CUdpAtk{
public:
	CDnsAtk() : CUdpAtk(){
		strncpy(m_name, "dnsflood", 31);
		m_params.m_iph_proto = IPPROTO_UDP;
	}
	
	CDnsAtk(const CDDoSParam& param) :CUdpAtk(param){

	   strncpy(m_name, "dnsflood", 31);	   
	   if(m_params.m_is_random_domain==false ){
	   	    char payload[DNS_PKT_MAX_LEN] = {0};
			//m_params.m_payload_len = sizeof(struct dnshdr) + domain_len + 2 + sizeof(struct dns_question);
			m_params.m_payload_len = build_dns_payload(payload);
	   
			m_params.set_payload_data(payload, m_params.m_payload_len);	
			
			RC_LOG_INFO("%d, %s %s", strlen(payload),payload+12,m_params.m_payload_data);
	   }
       m_params.m_iph_proto = IPPROTO_UDP;	
	}
	virtual ~CDnsAtk(){
	// TODO Auto-generated destructor stub
	}

	int32_t attack_one_pkt(int thrd_index);
	bool check_params();
    int32_t start();

private:
    int32_t build_dns_payload(char *payload);
};

#endif
