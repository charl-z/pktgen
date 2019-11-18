//#define _GNU_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "rand.h"

static uint32_t x, y, z, w;

/*
-1 ���ת���������򷵻�-1
�����򷵻���Ӧ�ַ��ı���
*/

int hexChar2value(const char high, const char  low){
    char s[2] = {high,low};
	char ch;
	
	int result = 0;
	int tmp = 0;
	for(int i=0; i<2; i++){
       ch = s[i];
	   //��ȡ16���Ƶĸ��ֽ�λ����
	   if(ch >= '0' && ch <= '9'){
		 tmp = (int)(ch - '0');
	   }
	   else if(ch >= 'a' && ch <= 'z'){
		 tmp = (int)(ch - 'a') + 10;
	   }
	   else if(ch >= 'A' && ch <= 'Z'){
		 tmp = (int)(ch - 'A') + 10;
	   }
	   else{
		 tmp = -1;
	   }
	   
	   if(tmp!=-1){
          result = (result <<4) +tmp;
	   }else{
          return -1;
	   }
	}
    return result;
}

//ʮ�������ַ���תascii�ַ�����dstStr�ĳ���Ϊlen/2 
//ʮ�������ַ�������ΪsrcLen/2 == 0 ����ȷ
int hex2str(char *dstStr, const char * srcStr, int srcLen){
   if(srcLen%2==1){
       return -1;   
   }
   int tmp=0 ;
   int i=0;
    for(; i < srcLen; i+=2){
        tmp= hexChar2value(srcStr[i], srcStr[i+1]);
		if(tmp == -1){
            return -1;
		}else{
			dstStr[i/2]  = (char)tmp;	
		}
	}
	dstStr[i/2] = '\0';
    return 0;
}


void rand_init(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}

uint32_t rand_next(void) //period 2^96-1
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

void rand_str(char *str, uint32_t len) // Generate random buffer (not alphanumeric!) of length len
{
    while (len > 0)
    {
        if (len >= 4)
        {
            *((uint32_t *)str) = rand_next();
            str += sizeof (uint32_t);
            len -= sizeof (uint32_t);
        }
        else if (len >= 2)
        {
            *((uint16_t *)str) = rand_next() & 0xFFFF;
            str += sizeof (uint16_t);
            len -= sizeof (uint16_t);
        }
        else
        {
            *str++ = rand_next() & 0xFF;
            len--;
        }
    }
}

void rand_alphastr(char *str, uint32_t len) // Random alphanumeric string, more expensive than rand_str
{
    const char alphaset[] = "abcdefghijklmnopqrstuvw012345678";

    while (len > 0)
    {
        if (len >= sizeof (uint32_t))
        {
            uint32_t i;
            uint32_t entropy = rand_next();

            for (i = 0; i < sizeof (uint32_t); i++)
            {
                uint8_t tmp = entropy & 0xff;

                entropy = entropy >> 8;
                tmp = tmp >> 3;

                *str++ = alphaset[tmp];
            }
            len -= sizeof (uint32_t);
        }
        else
        {
            *str++ = rand_next() % (sizeof (alphaset));
            len--;
        }
    }
}
