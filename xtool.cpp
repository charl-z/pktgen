/*
 * main.cpp
 *
 *  Created on: 2015骞�4鏈�25鏃�
 *      Author: cht
 */

#ifdef _RPS_LINUX
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <execinfo.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "netpool.h"
#include "xtool.h"
#include "sigproc.h"

#ifdef INCLUDE_PORT_SCAN
#include "CPortScan.h"
#endif

#ifdef INCLUDE_SSH_SCAN
#include "CSshScan.h"
#endif

#ifdef INCLUDE_DDOS
#include "CDDoSApp.h"
#endif

static int register_signal(void)
{
	if (SIG_ERR == signal(SIGPIPE, SIG_IGN))
	{
		fprintf(stderr, "signal error!\n");
		return RC_ERROR;
	}

	sigproc((char*)RC_DUMP_FILE);
	return OK;
}

/*程序入口*/
int main(int argc, char *argv[])
{
	struct rlimit rlimit;
	rlimit.rlim_cur = 65536;
	rlimit.rlim_max = 65536;
	if(0 > setrlimit(RLIMIT_NOFILE, &rlimit))
	{
		printf("modify file limit failed.\n");
	}

	loggger_init((char*)"/tmp/", (char *)"xddos", 3 * 1024, 1, FALSE);
	logger_set_level(L_DEBUG);

	if (OK != register_signal())
	{
		return 1;
	}

	CBaseApp *app = NULL;
	if (argc == 1)
	{
		/*default ddos*/
		app = &g_ddosApp;
	}
	else
	{
		#ifdef INCLUDE_PORT_SCAN
		if (strncmp(argv[1], "port", strlen("port")+1) == 0)
		{
			app = &g_portScan;
		}
		#endif

		#ifdef INCLUDE_SSH_SCAN
		if (strncmp(argv[1], "ssh", strlen("ssh")+1) == 0)
		{
			//app = &g_sshScan;
			return RC_ERROR;
		}
		#endif

		#ifdef INCLUDE_DDOS
		if (strncmp(argv[1], "ddos", strlen("ddos")+1) == 0)
		{
			
			app = &g_ddosApp;
		}
		else
		{
			/*default ddos*/
			app = &g_ddosApp;
		}
		#endif
	}

	int net_worker_thrd = 0;

	if (FALSE == np_init())
	{
		RC_LOG_ERROR("etp init failed.");
		return RC_ERROR;
	}

	if(RC_OK != app->init(argc, argv))
	{
		RC_LOG_ERROR("app init failed.");
		goto exit;
	}
	
    /*至少要保证一个线程*/
    net_worker_thrd = app->net_worker_thrd_cnt();
    np_init_worker_thrds(net_worker_thrd);

	unsigned long start_time, end_time;
	start_time = time(NULL);

	if (RC_OK != app->start())
	{
		app->destroy();
		goto exit;
	}

	if(FALSE == np_start())
	{
		RC_LOG_ERROR("start failed.");
		return RC_ERROR;
	}

	/*wait app end*/
	while(app->check_task_end() == FALSE)
	{
		sleep_s(1);
	}

	end_time = time(NULL);
	app->post_out(end_time-start_time);
	app->destroy();

exit:
	/*设置etp退出*/
	np_let_stop();
	np_wait_stop();
	np_free();
	return 0;
}
