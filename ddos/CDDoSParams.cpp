

#include <arpa/inet.h>
#include <getopt.h>

#include "xtool.h"
#include "CDDoSParams.h"
#include "pktbuild.h" 


uint32_t g_cnc_addr = 0;
uint16_t g_cnc_port = 3000;

uint32_t g_thrd_cnt = 1;

CDDoSParam::CDDoSParam() 
{
    m_type = ATK_VEC_MAX;
    m_speed = NOLIMIT_SPEED;
    m_duration = NOLIMIT_DURATION;
    m_total_cnt = NOLIMIT_COUNT;

    memset(&m_srcnet, 0, sizeof(m_srcnet));
    memset(&m_dstnet, 0, sizeof(m_dstnet));
    memset(&m_srcnet6, 0, sizeof(m_srcnet6));
    memset(&m_dstnet6, 0, sizeof(m_dstnet6));

    memset(&m_srcport, 0, sizeof(m_srcport));
    memset(&m_dstport, 0, sizeof(m_dstport));

    m_identity = 0x01;
    m_tcpflag = 0x10;
	m_tcpoptionflag = 0;

    memset(&m_domain, 0, sizeof(m_domain));
    memset(&m_http_path, 0, sizeof(m_http_path));
	
	memset(&m_relay_ip, 0, sizeof(m_relay_ip));
	memset(&m_client_ip_mac, 0, sizeof(m_client_ip_mac));
	memset(&m_ipv4_address, 0, sizeof(m_ipv4_address));
    memset(&m_ipv6_address, 0, sizeof(m_ipv6_address));
    memset(&m_options, 0, sizeof(m_options));
    memset(&m_server_id_duid, 0, sizeof(m_server_id_duid));
    memset(&m_client_id_duid, 0, sizeof(m_client_id_duid));
    memset(&m_iaid, 0, sizeof(m_iaid));
    
    m_ttl = 63;
    m_vlan_id = 0;
    m_payload_len = 0;
	m_payload_data = NULL;
	m_payload_type = PAYLOAD_HEX;
	
    m_http_action = 2;  //0表示GET，1表示POST, 2表示默认ACK
    m_https_action = 2;  //0 hello 1 application 2 走原来的ack
	m_sip_action = 2;   // sip INVITE和REGISTER字段， m_sip_action=0 表示INVITE, m_sip_action=1 表示REGISTER, m_sip_action=2表示默认UDP攻击
	m_icmp_type = 8; //icmptype=0 表示reply, icmptype=8 表示request, 默认为icmp request
    m_mac_start = 0;


    m_dont_frag = true;
    m_issyn64 = false;
    m_is_passfw = false;
    m_is_sockstress = false;
    m_is_bot = false;
    m_is_random_domain = false;
    m_prefix_delegetion = false;
    m_ia_ta = false;
    m_bootp = false;

    util_strncpy(m_http_method, (char*)"GET", 31);
    m_http_method[31] = 0;
    util_strncpy(m_http_path, (char*)"/", 255);
    m_http_path[31] = 0;

    m_concurrent_cnt = 1;
    m_is_browser = false;

    m_ntp_monlist = false;
	memset(&m_json_name, 0, sizeof(m_json_name));
	m_ip_type =  IP_V4;
	m_iph_proto =  0;
    m_msg_type = 1; //默认发送solicit报文
   // m_ipv6_address = "";
}

int CDDoSParam::params_check()
{

    if (m_ttl < 1 || m_ttl >= 256)
    {
        printf("invalid ttl %u\n", m_ttl);
        return RC_ERROR;
    }

    /*vlan暂时不支持*/
    if (m_vlan_id != 0)
    {
        printf("vlan id not support in this version\n");
        return RC_ERROR;
    }

    if (m_vlan_id > 4094)
    {
        printf("invalid vlan id %u\n", m_vlan_id);
        return RC_ERROR;
    }

    if (m_type == ATK_VEC_MAX)
    {
        printf("invalid attack type\n");
        return RC_ERROR;
    }

   if( m_ip_type == IP_V4 )
   {
	   if (m_dstnet.begin_addr == 0 || m_dstnet.end_addr < m_dstnet.begin_addr)
	   {
		     
		   printf("invalid dst net\n");
		   return RC_ERROR;
	   }
	   
	   if (m_srcnet.end_addr < m_srcnet.begin_addr)
	   {
		   printf("invalid src net\n");
		   return RC_ERROR;
	   }

   }
   else if ( m_ip_type == IP_V6 )
   {


	   for(int i=0; i<4; i++)
	   {
		   uint32_t min= ntohl(m_dstnet6.begin_addr6.__u6_addr.__u6_addr32[i]);
		   uint32_t max =ntohl(m_dstnet6.end_addr6.__u6_addr.__u6_addr32[i] ); 
		   if(min>max)
		   	{  
			   printf("invalid dst net %x,%x\n");
			   return RC_ERROR; 	   
		   }
	   
	   }
	   
	   for(int i=0; i<4; i++){
		   uint32_t min= ntohl(m_srcnet6.begin_addr6.__u6_addr.__u6_addr32[i]);
		   uint32_t max =ntohl(m_srcnet6.end_addr6.__u6_addr.__u6_addr32[i] );
		   
		   if(min>max)
		   {
			   printf("invalid src net\n");
			   return RC_ERROR; 	   
		   }
	   
	   }

   
   }
	else
	{
		printf("invalid ip type.\n");
		return RC_ERROR;
   }

	



    if (m_dstport.begin_port == 0 || (m_dstport.end_port < m_dstport.begin_port))
    {
        if(m_type != ATK_VEC_ICMP){

	    printf("--------------invalid dst port\n");
	    return RC_ERROR;
	}
    }

    if (m_srcport.end_port < m_srcport.begin_port)
    {
        printf("invalid src port\n");
        return RC_ERROR;
    }

    if (util_strncmp(m_http_method, (char*)"GET", 32) != 0 
        && util_strncmp(m_http_method, (char*)"POST", 32) != 0 )
    {
        printf("invalid http method, only support GET and POST\n");
        return RC_ERROR;
    }

    if (m_concurrent_cnt > MAX_CONCUR_CNT)
    {
        printf("concurrent count too much, should less than %d\n", MAX_CONCUR_CNT);
        return RC_ERROR;
    }

    if (g_thrd_cnt > MAX_THRD_CNT)
    {
        g_thrd_cnt = MAX_THRD_CNT;
    }
    else if (g_thrd_cnt == 0)
    {
        g_thrd_cnt = 1;
    }


    return RC_OK;
}


int CDDoSParam::set_payload_data(char * str, uint32_t len){
    //RC_LOG_INFO(" set_payload_data %d\n %s ", len,str);
    if(str ==NULL || len <=0|| len>= 1500)
		return -1;
	
	delete[]  m_payload_data;
    m_payload_data = new char[sizeof(char)* (len +1)];
	
	util_memcpy(m_payload_data,str,len);
	m_payload_data[len]='\0';
	RC_LOG_INFO(" CDDoSParam::set_payload_data finished %d %s \n%s", len,str,m_payload_data);
    return 0;
  
}


