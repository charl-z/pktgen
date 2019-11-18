
#ifndef XTOOL_H_
#define XTOOL_H_

#include "commtype.h"
#include "logproc.h"
#include "utilfile.h"
#include "utilstr.h"
#include "rand.h"
#include "ipparser.h"

#define RC_OK 0
#define RC_ERROR -1
#define RC_PARAM_INV -2

#define RC_LOG_DEBUG _LOG_DEBUG
#define RC_LOG_ERROR _LOG_ERROR
#define RC_LOG_INFO _LOG_INFO
#define RC_LOG_WARN _LOG_WARN

#define RC_DUMP_FILE "./core_dump.info"
#define JSON_CONF_FILE "./attack_conf.json"
#define PTR_TO_INT32(ptr) ((u_int64_t)(ptr) & 0xffffffff)
#define INT32_TO_PTR(var) ((void*)(u_int64_t)(var))


class CBaseApp {
public:
	CBaseApp(){};
	virtual ~CBaseApp(){};

	virtual int init(int argc, char *argv[]) = 0;
	virtual void destroy() = 0;

	virtual int start() = 0;
	virtual void stop() = 0;
	virtual bool check_task_end() = 0;

    virtual int net_worker_thrd_cnt()
    {
        return 0;
    }

	virtual void post_out(uint64_t eclipase_sec) = 0;
};

#endif