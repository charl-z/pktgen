#ifndef _UDP_ATK_H
#define _UDP_ATK_H

#include "pktbuild.h"

class CUdpAtk : public CAttack {
public:
	CUdpAtk() : CAttack(){
		strncpy(m_name, "udpflood", 31);
		// m_params.m_iph_proto = IPPROTO_UDP;
		//duid_time_stamp = 0;
		
	}
	CUdpAtk(const CDDoSParam& param) :CAttack(param){
	    if(m_params.m_type == ATK_VEC_UDP)
			strncpy(m_name, "udpflood", 31);
		m_params.m_iph_proto = IPPROTO_UDP;
		// duid_time_stamp = 0;
		
		if(m_params.m_type == ATK_VEC_UDP ){
		    
			if (m_params.m_sip_action == 0){
				char payload[] = 
					"INVITE sip:neighbour@test-virtual-matchine.local:5060 SIP/2.0\r\n"
					"CSeq: 1 INVITE\r\n"
					"v: SIP/2.0/UDP 10.66.250.50:5060;branch=z9hG4bK56c477fb-9df9-e711-8722-000c29389c8e;rport\r\n"
					"User-Agent: Ekiga/4.0.1\r\n"
					"f: <sip:client@119.6.3.75>;tag=7c8b3afb-9df9-e711-8722-000c29389c8e\r\n"
					"i: 7e8e3afb-9df9-e711-8722-000c29389c8e@client-virtual-machine\r\n"
					"k: 100rel,replaces\r\n"
					"t: <sip:neighbour@test-virtual-matchine.local>\r\n"
					"m: \"sip:client@119.6.3.75\" <sip:client@119.6.3.75>\r\n"
					"Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING,PRACK\r\n"
					"l: 857\r\n"
					"c: application/sdp\r\n"
					"Max-Forwards: 70\r\n\r\n"
					"v=0\r\n"
					"o=-1516157075 1 IN IP4 119.6.3.75\r\n"
					"s=Ekiga/4.0.1\r\n"
					"c=IN IP4 119.6.3.75\r\n"
					"t=0 0\r\n"
					"m=audio 5074 RTP/AVP 124 0 8 101\r\n"
					"a=sendrecv\r\n"
					"a=rtpmap:124 Speex/16000/1\r\n"
					"a=rtpmap:0 PCMU/8000/1\r\n"
					"a=rtpmap:8 PCMA/8000/1\r\n"
					"a=rtpmap:101 telephone=event/8000\r\n"
					"a=fmtp:101 0-16,32,36\r\n"
					"a=maxptime:20\r\n"
					"m=video 5076 RTP/AVP 94 31 34 126 89 92 95\r\n"
					"b=AS:4096\r\n"
					"b=TIAS:409600\r\n"
					"a=sendrecv\r\n"
					"a=rtpmap:94 theora/90000\r\n"
					"a=fmtp:94 height=576;width=704\r\n"
					"a=rtpmap:31 h261/90000\r\n"
					"a=fmtp:31 CIF=1;QCIF=1\r\n"
					"a=rtpmap:34 H263/90000\r\n"
					"a=fmtp:34 F=1;CIF=1;CIF4=1;QCIF=1\r\n"
					"a=rtpmap:126 H263-1998/90000\r\n"
					"a=fmtp:126 D=1;F=1;I=1;J=1;CIF=1;CIF4=1QCIF=1\r\n"
					"a=rtpmap:89 H264/90000\r\n"
					"a=fmtp:89 max-fs=6336;max-mbps=190080;profile-level-id=4280e\r\n"
					"a=rtpmap:92 H264/90000\r\n"
					"a=fmtp:82 packetization-model=1;max-fs=6336;max-mbps=190080;profile-level-id=4280e\r\n"
					"a=rtpmap:95 MP4V-ES/90000\r\n"
					"a=fmtp:95 profile-level-id=5\r\n";
				m_params.m_payload_len = strlen(payload);
				m_params.set_payload_data(payload, m_params.m_payload_len);

			}
			if (m_params.m_sip_action == 1){
				char payload1[] =
					"REGISTER sip:8.13.66.11 SIP/2.0\r\n"
					"CSeq: 1 REGISTER\r\n"
					"Via: SIP/2.0/UDP 10.66.250.13:5060;branch=z9hG4bK56c477fb-9df9-e711-8d75-000c29067f6c;rport\r\n"
					"User-Agent: Ekiga/4.0.1\r\n"
					"From: <sip:1009@8.13.66.11>;tag=128b8732-9df9-e711-8d75-000c29067f6c\r\n"
					"Call-ID: ce828732-9df9-e711-8d75-000c29067f6@test-virtual-matchine\r\n"
					"To: <sip:1009@8.13.66.11>"
					"Contact: <sip:1009@10.66.250.13:5080>;q=1, <sip:1009@11.13.66.11:5080>;q=0.500\r\n"
					"Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING,PRACK\r\n"
					"Expires: 600\r\n"
					"Content-Length: 0\r\n"
					"Max-Forwards: 70\r\n";
				m_params.m_payload_len = strlen(payload1);
				m_params.set_payload_data(payload1, m_params.m_payload_len);

			}
			else if(m_params.m_payload_len>0 && m_params.m_payload_data==NULL){
				char payload1[DNS_PKT_MAX_LEN] = { 0 };
				rand_str(payload1, m_params.m_payload_len);
				m_params.set_payload_data(payload1, m_params.m_payload_len);
			}
		}

	}
	virtual ~CUdpAtk(){
	// TODO Auto-generated destructor stub
	}

	int32_t attack_one_pkt(int thrd_index);
	// int32_t duid_time_stamp = 0;
	pdu_l3_desc_t get_layer3_info();
    virtual bool check_params();
    int32_t start();
    void stop();
	char* get_udp_payload();
	char* struct_solicit_packet(char* client_mac);
	char* struct_relay_solicit_packet(char* client_mac);
	char* struct_relay_rebind_packet(char* client_mac);
	char* struct_relay_renew_packet(char* client_mac);
	char* struct_renew_packet(char* client_mac);
	char* struct_rebind_packet(char* client_mac);
	char* struct_confirm_packet(char* client_mac);
	char* struct_relay_confirm_packet(char* client_mac);
	char* struct_relay_release_packet(char* client_mac);
	char* struct_release_packet(char* client_mac);
	char* struct_decline_packet(char* client_mac);
	char* struct_relay_decline_packet(char* client_mac);
	char* MsgTypeChoice();
	char* struct_discover_packet_v4(char* client_mac);
	char* struct_release_packet_v4(char* client_mac);
	char* struct_decline_packet_v4(char* client_mac);
	char* struct_renew_packet_v4(char* client_mac);
	char* struct_inform_packet_v4(char* client_mac);
	char* struct_forcerenew_packet_v4(char* client_mac);
	char* struct_nak_packet_v4(char* client_mac);
	char* struct_information_packet(char* client_mac);
	char* struct_relay_information_packet(char* client_mac);
	char* struct_request_packet(char* client_mac);
	char* struct_relay_request_packet(char* client_mac);
	char* struct_bootp_packet_v4(char* client_mac);
	char* MsgTypeChoiceV4();

public:
	void send_udp(pdu_l3_desc_t *layer3, char *layer4);
protected:
	uint32_t modify_udp(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload);
	uint16_t compute_udp_checksum(IP_HEADER_T *ip_header, UDP_HEADER_T *udp_header, uint16_t udp_len);
	uint16_t in_chksum_udp(uint16_t *h, uint16_t *d, uint16_t dlen);
};

#endif
