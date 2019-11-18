
#ifndef _DDOS_APP_H
#define _DDOS_APP_H


class CDDoSApp: public CBaseApp {
public:
	CDDoSApp();
	virtual ~CDDoSApp();

public:
	int init(int argc, char *argv[]);
	void destroy();
	int start();
	void stop();
	bool check_task_end();
	void post_out(uint64_t eclipase_sec);
	
	int net_worker_thrd_cnt();

private:
	static void attack_loop(void* param1, void* param2, void* param3, void* param4);
	static void expire_handle(void* param1, void* param2, void* param3, void* param4);

	void _stop_evt_thrds();
	int _start_evt_thrds();

public:
    void *m_thrdpool;
    int m_evt_thrd_cnt;
    int m_net_thrd_cnt;

private:
	bool m_shutdown;
	bool m_is_net_use_thrd;
	bool m_is_evt_use_thrd;
};

extern CDDoSApp g_ddosApp;

#endif