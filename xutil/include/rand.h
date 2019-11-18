#pragma once

#include <stdint.h>

#define PHI 0x9e3779b9

void rand_init(void);
uint32_t rand_next(void);
int hex2str(char *dstStr, const char * srcStr,int srcLen);
void rand_str(char *, uint32_t);
void rand_alphastr(char *, uint32_t);
