/*
 * util.cpp
 *
 *  Created on: 2016年7月19日
 *      Author: cht
 */
#ifdef _RPS_LINUX
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
//#include <linux/if.h>
#include <getopt.h>
#include <unistd.h>
#endif

#include "xtool.h"
#include "ipparser.h"

unsigned long long ntohll(unsigned long long val)
{
    if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {
        return (((unsigned long long )htonl((int)((val << 32) >> 32))) << 32) | (unsigned int)htonl((int)(val >> 32));
    }
    else if (__BYTE_ORDER == __BIG_ENDIAN)
    {
        return val;
    }
}

unsigned long long htonll(unsigned long long val)
{
    if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {
        return (((unsigned long long )htonl((int)((val << 32) >> 32))) << 32) | (unsigned int)htonl((int)(val >> 32));
    }
    else if (__BYTE_ORDER == __BIG_ENDIAN)
    {
        return val;
    }
}


bool host_addr_check(char *hostname)
{
	int count = 0;
	char* p = hostname;

	while(0 != *p)
	{
	   if(*p =='.')
		if((p+1) != NULL && *(p+1)!= '.')
			count++;
	   p++;
	}

	if(count != 3)
	{
		return FALSE;
	}

	return TRUE;
}

char* ip_to_str(uint32_t ipaddr)
{
	struct in_addr tempaddr;
	tempaddr.s_addr = ipaddr;
	return inet_ntoa(tempaddr);
}


unsigned int str_to_ip(char* ipstr, uint32_t *addr)
{
	struct in_addr tempaddr;
	if (FALSE == host_addr_check(ipstr))
	{
		return RC_ERROR;
	}

	if (inet_aton(ipstr, &tempaddr) != 0)
	{
		*addr = tempaddr.s_addr;
		return RC_OK;
	}

	return RC_ERROR;
}

int str_split(char *strs, char *** substrs, const char delimit)
{
	int count = 0;
	char *str = strdup(strs);
	char *pos = str;
	char *tmpstr = str;
	if ((str == NULL) || !(*pos))
	{
		*substrs = NULL;
		return count;
	}
	*substrs = (char **) malloc(sizeof(char *));
	while (*pos)
	{

		while (*str != delimit && *str != '\0')
		{
			str++;
		}
		if (*str == delimit)
		{
			*str++ = '\0';
			*substrs = (char **) realloc((void *) *substrs, sizeof(char *)
			        * (count + 1));
			(*substrs)[count] = strdup(pos);
			count++;
		}
		else
		{
			*substrs = (char **) realloc((void *) *substrs, sizeof(char *)
			        * (count + 1));
			(*substrs)[count] = strdup(pos);
		}
		pos = str;
	}
	free(tmpstr);

	return ++count;
}


void str_buf_free(char ***buf, int buf_size)
{
	int cnt;
	for (cnt = 0; cnt < buf_size; cnt++)
	{
		free((*buf)[cnt]);
	}

	free(*buf);
	*buf = NULL;
}


/*
三种ip格式 
ip
ip/mask
begin_ip-end_ip
*/
int32_t get_ip6_scope(char* ipstr, HOST_RANGE6_T* result){
	char *p, *pch;
    int len;
    char str[HOST_IP_LEN] = {0};
    struct libnet_in6_addr  begin6 , end_a6 ;
	//memset(begin6,0,sizeof(begin6));
	//memset(end_a6,0,sizeof(end_a6));
	
    /*1.1.1.1/24*/
	if ((p = strpbrk(ipstr, "/")) != NULL)
	{
		*p = '\0';
		p++;

		uint32_t i_mask = strtol(p, (char **) NULL, 10);
		if (i_mask <= 128)
		{
			if(!inet_pton(AF_INET6, ipstr, &begin6)){
				printf("host %s/%d not valid.\n", ipstr, i_mask);
				return RC_ERROR;

			}
			end_a6=begin6;
		    uint32_t mask=128-i_mask;
			uint32_t tmpmask= 0 ;
			for(int i=3; i>=0; i--){	
				if(mask<32){
					tmpmask=mask;
					mask=0;
				}else{
	                tmpmask=32;
                    mask-=32;
				}

				begin6.__u6_addr.__u6_addr32[i] = (uint32_t)htonl(  ntohl(begin6.__u6_addr.__u6_addr32[i]) &   ( 0xffffffff<<tmpmask )     );
				//printf("tmpmask:%u,%u\n",tmpmask, ( ((uint32_t)0xffffffff)>>(32-tmpmask) ) );
				end_a6.__u6_addr.__u6_addr32[i] = (uint32_t)htonl( ntohl(begin6.__u6_addr.__u6_addr32[i]) | ((uint64_t)0xffffffff)>>(32-tmpmask)  );

			}
			

			result->begin_addr6 = begin6;
			result->end_addr6 = end_a6;
					
			return RC_OK;

			
		}

		printf("host %s/%d not valid.\n", ipstr, i_mask);
		return RC_ERROR;
	}
	else if ((p = strpbrk(ipstr, "-")) != NULL)
	{
		/*1.1.1.1-1.1.1.200*/
		*p = '\0';
		p++;
        if (((pch = strrchr(ipstr, ':')) != NULL)
        		&& (strchr(p, ':') == NULL) )
        {
        	/*192.168.1.1-50 鐟滆埇鍨圭槐锟�*/
            len = pch - ipstr + 1;
            strncpy(str, ipstr, len);
            strncpy(str + len, p, strlen(p));
            p = str;
        }

		if(!inet_pton(AF_INET6, ipstr, &begin6)){
			printf("begin host %s not valid.\n", ipstr);
			return RC_ERROR;
		
		}

		if(!inet_pton(AF_INET6, p, &end_a6)){
			printf("end host %s not valid.\n", p);
			return RC_ERROR;

		}				

        result->begin_addr6 = begin6;
		result->end_addr6 = end_a6;
		for(int i=0; i<4; i++){
		    int32_t min= ntohl(result->begin_addr6.__u6_addr.__u6_addr32[i]);
			int32_t max =ntohl(result->end_addr6.__u6_addr.__u6_addr32[i] );
		    
            if(min>max){
				printf("host %s-%s not invalid.\n", ipstr, p);
				return RC_ERROR;		
		    }

		}

		return RC_OK;
	}
	else
	{

		if(!inet_pton(AF_INET6, ipstr, &begin6)){
			printf("begin host %s not valid.\n", ipstr);
			return RC_ERROR;
		
		}
        result->begin_addr6 = begin6;
		result->end_addr6 = begin6;

		return RC_OK;
	}

	return RC_OK;


}



int32_t get_ip_scope(char* ipstr, HOST_RANGE_T* result)
{
	char *p, *pch;
    int len;
    char str[HOST_IP_LEN] = {0};
    uint32_t ipaddr = 0, begin = 0, end_a = 0;

    /*1.1.1.1/24*/
	if ((p = strpbrk(ipstr, "/")) != NULL)
	{
		*p = '\0';
		p++;

		uint32_t i_mask = strtol(p, (char **) NULL, 10);
		if (i_mask <= 32)
		{
			if(RC_OK != str_to_ip(ipstr, &ipaddr))
			{
				printf("host %s/%d not valid.\n", ipstr, i_mask);
				return RC_ERROR;
			}

			begin = ntohl(ipaddr);
			CONVERT_TO_BEGIN_END(begin, end_a, i_mask);

			result->begin_addr = begin;
			result->end_addr = end_a;
			return RC_OK;
		}

		printf("host %s/%d not valid.\n", ipstr, i_mask);
		return RC_ERROR;
	}
	else if ((p = strpbrk(ipstr, "-")) != NULL)
	{
		/*1.1.1.1-1.1.1.200*/
		*p = '\0';
		p++;

        if (((pch = strrchr(ipstr, '.')) != NULL)
        		&& (strchr(p, '.') == NULL) )
        {
        	/*192.168.1.1-50 鐟滆埇鍨圭槐锟�*/
            len = pch - ipstr + 1;
            strncpy(str, ipstr, len);
            strncpy(str + len, p, strlen(p));
            p = str;
        }

        if(RC_OK != str_to_ip(ipstr, &begin))
		{
			printf("begin host %s not valid.\n", ipstr);
			return RC_ERROR;
		}

        if(RC_OK != str_to_ip(p, &end_a))
		{
        	printf("end host %s not valid.\n", p);
			return RC_ERROR;
		}

        result->begin_addr = ntohl(begin);
		result->end_addr = ntohl(end_a);

		if (result->end_addr < result->begin_addr)
		{
			printf("host %s-%s not invalid.\n", ipstr, p);
			return RC_ERROR;
		}

		return RC_OK;
	}
	else
	{
		if(RC_OK != str_to_ip(ipstr, &begin))
		{
			printf("host %s not valid.\n", ipstr);
			return RC_ERROR;
		}

		result->begin_addr = ntohl(begin);
		result->end_addr = ntohl(begin);
		return RC_OK;
	}

	return RC_OK;
}

int32_t get_port_scope(char* portstr, PORT_RANGE_T* result)
{
	char *p;
	int ret = RC_OK;

	/*2-1000*/
	if ((p = strpbrk(portstr, "-")) != NULL)
	{
		*p = '\0';
		p++;

		result->begin_port = atoi(portstr);;
		result->end_port = atoi(p);
	}
	else
	{
		result->begin_port = atoi(portstr);
		result->end_port = result->begin_port;
	}

	if (result->begin_port < SCAN_PORT_MIN
			|| result->begin_port > SCAN_PORT_MAX)
	{
		printf("port %d invalid, must between 16-65535.\n",
				result->begin_port);
		ret = RC_PARAM_INV;
	}

	if (result->end_port < SCAN_PORT_MIN
				|| result->end_port > SCAN_PORT_MAX)
	{
		printf("port %d invalid, must between 16-65535.\n",
					result->end_port);
		ret = RC_PARAM_INV;
	}

	if (result->end_port < result->begin_port)
	{
		printf("port %d-%d not invalid.\n", result->begin_port,
					result->end_port);
		ret = RC_PARAM_INV;
	}

	return ret;
}

int getLocalIpAddress(char *iface_name, uint32_t *ip_addr)
{
	char err_buf[64] = {0};

	int i=0;
	int sockfd;
	struct ifconf ifconf;
	char buf[512];
	struct ifreq *ifreq;

	//初始化ifconf
	ifconf.ifc_len = 512;
	ifconf.ifc_buf = buf;

	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0)
	{
		str_error_s(err_buf, 32, errno);
		printf("create socket error, %s.\n", err_buf);
		return RC_ERROR;
	}

	if (-1 == ioctl(sockfd, SIOCGIFCONF, &ifconf))    //获取所有接口信息
	{
		str_error_s(err_buf, 32, errno);
		printf("SIOCGIFCONF error, %s.\n", err_buf);

		close(sockfd);
		return RC_ERROR;
	}

	//接下来一个一个的获取IP地址
	ifreq = (struct ifreq*)buf;
	for(i = (int)(ifconf.ifc_len/sizeof(struct ifreq)) - 1; i >= 0 ; i--)
	{
		if (0 == strncmp(ifreq[i].ifr_name, iface_name, IFNAMSIZ))
		{
			*ip_addr = ((struct sockaddr_in*)&(ifreq[i].ifr_addr))->sin_addr.s_addr;
		}

		//printf("name = [%s]\n", ifreq[i].ifr_name);
		//printf("local addr = [%s]\n", inet_ntoa(((struct sockaddr_in*)&(ifreq[i].ifr_addr))->sin_addr));
	}

	close(sockfd);

	if (*ip_addr == 0)
	{
		printf("fail to get ip address for %s.\n", iface_name);
		return RC_ERROR;
	}

	return RC_OK;
}
