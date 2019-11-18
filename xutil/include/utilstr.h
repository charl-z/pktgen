#pragma once

int util_strlen(char *);
int util_strncmp(char *s1, char *s2, int n);
int util_strcmp(char *s1, char *s2);
int util_strncpy(char *, char *, int);
int util_strcpy(char *, char *);
void util_memcpy(void *, void *, int);
void util_zero(void *, int);
int util_atoi(char *, int);
char *util_itoa(int, int, char *);
int util_memsearch(char *, int, char *, int);
int util_stristr(char *, int, char *);
void ip_address_hex(char* address, char* output);
void util_insert(char *str, char *pch, int pos);
void util_ipv6_to_str(char* dest, char* src);
char *util_reserver_str(char *str, size_t len);



static inline int util_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

static inline int util_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

static inline int util_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

static inline int util_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}