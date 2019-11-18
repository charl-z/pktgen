#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "utilstr.h"
#include <string.h>
#include <arpa/inet.h>

void util_ipv6_to_str(char* dest, char* src)
{
 /*
  * 将ipv6转换成标准形式表示
  * 2001::46 -> 20010000000000000000000000000046
 */
 struct in6_addr ip;
    inet_pton(AF_INET6, src, &ip);
    //char ipv6[33] = {0};
    for(int i = 0; i < 16; i ++)
    {
    char temp[3] = {0};
    sprintf(temp, "%02x", ip.s6_addr[i]);
    strcat(dest, temp);
    }
}

char *util_reserver_str(char *str, size_t len)
{
    /*翻转字符串*/
    char *start = str;
    char *end = str + len - 1;
    char ch;

    if (str != NULL)
    {
        while (start < end)
        {
            ch = *start;
            *start++ = *end;
            *end-- = ch;
        }
    } 
    return str;
} 

int util_strlen(char *str)
{
    int c = 0;

    while (*str++ != 0)
        c++;
    return c;
}

void util_insert(char *str, char *pch, int pos) 
{
	/*插入字符串到指定位置*/
	int len = strlen(str);
	int nlen = strlen(pch);
	for (int i = len - 1; i >= pos; --i) {
		*(str + i + nlen) = *(str + i);
	}
	for (int n = 0; n < nlen;n++)
	*(str + pos + n) = *pch++;
	*(str + len + nlen) = 0;
}

void ip_address_hex(char* address, char* hex_address)
{
	/*
    将ip地址转化为16进制
    输入：10.1.109.12
    输出：0A016D0C   
    */
	char* s = (char*)address;
	char* ss = NULL;
    int output[5] = {0};
	int n=0;
	while (n<4&&(ss = strchr(s,'.')) != NULL)
	{
		*ss = 0;
		output[n++] = atoi(s);
		s = ss+1;
	}
	if (n<4&&*s)
	output[n]=atoi(s);

	sprintf(hex_address,"%02X%02X%02X%02X",output[0], output[1], output[2], output[3]);
	return;
}

int util_strncmp(char *s1, char *s2, int n)
{
    //assert((s1!=NULL)&&(s2!=NULL));  
  
    while(*s1!='\0'&&*s2!='\0'&&n)
    {  
        if(*s1-*s2>0)  
            return 1;  
        if(*s1-*s2<0)  
            return -1;  
        s1++;  
        s2++;  
        n--;  
    }  
    if(*s1=='\0'&&*s2!='\0')
        return -1;  
    if(*s2=='\0'&&*s1!='\0')  
        return 1;  
    return 0; 
}

int util_strcmp(char *s1, char *s2)
{
    //assert((s1!=NULL)&&(s2!=NULL));  
  
    while(*s1!='\0'&&*s2!='\0')
    {  
        if(*s1-*s2>0)  
            return 1;  
        if(*s1-*s2<0)  
            return -1;  
        s1++;  
        s2++;  
    }  
    if(*s1=='\0'&&*s2!='\0')
        return -1;  
    if(*s2=='\0'&&*s1!='\0')  
        return 1;  
    return 0; 
}

int util_strncpy(char *dst, char *src, int len)
{
    int l = util_strlen(src) + 1;
    if (l > len) l = len;

    util_memcpy(dst, src, l);

    return l;
}

int util_strcpy(char *dst, char *src)
{
    int l = util_strlen(src) + 1;

    util_memcpy(dst, src, l);

    return l;
}

void util_memcpy(void *dst, void *src, int len)
{
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}

void util_zero(void *buf, int len)
{
    char *zero = (char*)buf;
    while (len--)
        *zero++ = 0;
}

int util_atoi(char *str, int base)
{
	unsigned long acc = 0;
	int c;
	unsigned long cutoff;
	int neg = 0, any, cutlim;

	do {
		c = *str++;
	} while (util_isspace(c));
	if (c == '-') {
		neg = 1;
		c = *str++;
	} else if (c == '+')
		c = *str++;

	cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
	cutlim = cutoff % (unsigned long)base;
	cutoff /= (unsigned long)base;
	for (acc = 0, any = 0;; c = *str++) {
		if (util_isdigit(c))
			c -= '0';
		else if (util_isalpha(c))
			c -= util_isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
            
		if (c >= base)
			break;

		if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = neg ? LONG_MIN : LONG_MAX;
	} else if (neg)
		acc = -acc;
	return (acc);
}

char *util_itoa(int value, int radix, char *string)
{
    if (string == NULL)
        return NULL;

    if (value != 0)
    {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        if (radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }

        while (accum)
        {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }
        
        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        util_strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}

int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;

    if (mem_len > buf_len)
        return -1;

    for (i = 0; i < buf_len; i++)
    {
        if (buf[i] == mem[matched])
        {
            if (++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}

int util_stristr(char *haystack, int haystack_len, char *str)
{
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while (haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if (a == b)
        {
            if (++match_count == str_len)
                return (ptr - haystack);
        }
        else
            match_count = 0;
    }

    return -1;
}

