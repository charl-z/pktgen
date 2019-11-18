#ifndef _ATTACK_H
#define _ATTACK_H

#include "pktbuild.h" 

#define  ATTACK_TIMER_INTVAL  1000
#define  ATTACK_BUF_LEN 1500
#define  DNS_PKT_MAX_LEN 600


typedef enum{
  	JOB_GOON = 0,
  	JOB_PAUSE,
  	JOB_STOP
}JOB_ST_E;


class CAttack {
public:
	CAttack();
	CAttack(const CDDoSParam &param){
		init();
		m_params = param;
		
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
	virtual ~CAttack();

	virtual bool check_params() 
	{
		return true;
	}

	virtual int32_t start() = 0;   // 纯虚函数
	virtual void stop() = 0;   //
	
	virtual bool is_stopped()
	{
		return true;
	}
	
	virtual int32_t attack_one_pkt(int thrd_index) = 0;  //
	virtual void expire_handle();

	void set_ddos_params(CDDoSParam *params);
	void attack_handle(int thrd_index);
	
	uint32_t get_cur_dstaddr();
	uint32_t get_cur_srcaddr();
	struct libnet_in6_addr get_cur_dstaddr6();
	struct libnet_in6_addr get_cur_srcaddr6();	
	
	uint16_t get_cur_dstport();
	uint16_t get_cur_srcport();
	uint32_t get_cur_seq();
	uint32_t get_cur_ack();
	
	void get_dns_domain(char *domain_name);
	void get_random_mac(char *client_ip_mac);


	int init_raw_tcp_socket();
	int init_raw_udp_socket();
	int init_raw_icmp_socket();   // icmp的初始化
	void common_free();
	int sendpkt(uint32_t dstaddr , int dport,int pkt_len,int thrd_index );
	//返回ip头的长度
	int copy_ip_header(char * buffer,uint32_t buffer_len,pdu_l3_desc_t *pdu_desc);
	//返回ip头的长度

	

private:
	JOB_ST_E update_job_status();

public:
	CDDoSParam m_params;

	char m_name[32];

	JOB_ST_E m_job_status;
	uint32_t m_curcnt_in_cycle;
	uint32_t m_curcnt_total;
	uint32_t m_eclapse_second;

public:
    int m_fd[MAX_THRD_CNT];
    char *m_pkt_buf[MAX_THRD_CNT];
	libnet_t *m_libnet;

private:
	uint32_t m_cur_srcaddr;
	uint32_t m_cur_dstaddr;
	uint16_t m_cur_srcport;
	uint16_t m_cur_dstport;
	struct libnet_in6_addr m_cur_srcaddr6;
    struct libnet_in6_addr m_cur_dstaddr6;
	

private:
	uint32_t m_maxcnt_in_cycle;
private :
	void init();

    void init_libnet(){	
		char errbuf[LIBNET_ERRBUF_SIZE];
		m_libnet= libnet_init(LIBNET_RAW6, /* injection type */
							NULL, /* network interface */
							errbuf); /* error buffer */
		if (m_libnet == NULL)
		{				

			RC_LOG_ERROR("libnet_init() failed: %s", errbuf);				

		}	
		libnet_seed_prand(m_libnet);
	}

	
};

#endif

