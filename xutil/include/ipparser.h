#ifndef IPPARSER_H_
#define IPPARSER_H_

#include "tcpip.h"

#include <libnet.h>

#define MAX_SCAN_PORT_RANGES 1000
#define MAX_SCAN_HOST_RANGES 1000

#define HOST_IP_LEN 32
#define PATH_MAX_LEN  256

#define RPS_USER_LEN  64
#define RPS_PASSWD_LEN 128

#define  CONVERT_TO_BEGIN_END(minIP, maxIP, i_mask) \
        minIP &= (uint32_t)(((uint64_t)0xffffffff) << (32 - (i_mask))); \
        maxIP = (minIP) + (((uint64_t)0xffffffff) >> (i_mask));





#define SCAN_PORT_MIN 1
#define SCAN_PORT_MAX 65535

typedef struct
{
    unsigned int begin_addr;
    unsigned int end_addr;
}HOST_RANGE_T;


typedef struct
{
    struct libnet_in6_addr begin_addr6;
    struct libnet_in6_addr end_addr6;
}HOST_RANGE6_T;


typedef struct
{
    unsigned short begin_port;
    unsigned short end_port;
}PORT_RANGE_T;

extern unsigned long long ntohll(unsigned long long val);
extern unsigned long long htonll(unsigned long long val);
extern unsigned int str_to_ip(char* ipstr, uint32_t *addr);
extern char* ip_to_str(uint32_t ipaddr);

extern int str_split(char *strs, char *** substrs, const char delimit);
extern void str_buf_free(char ***buf, int buf_size);
extern int32_t get_ip_scope(char* ipstr, HOST_RANGE_T* result);
extern int32_t get_ip6_scope(char* ipstr, HOST_RANGE6_T* result);

extern int32_t get_port_scope(char* portstr, PORT_RANGE_T* result);
extern int getLocalIpAddress(char *iface_name, uint32_t *ip_addr);

#endif /* UTIL_H_ */
