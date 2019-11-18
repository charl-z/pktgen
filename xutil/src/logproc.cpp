#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <assert.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <dirent.h>
#include <sys/time.h>
#endif

#include "commtype.h"
#include "utilfile.h"
#include "logproc.h"


#define MAX_NAME_LEN 256

#define MAX_SIZE_KB (8 * 1024) //8MB����־��С

#define MAX_LINE_LEN    2048
#define RING_SIZE 0x800000 //8M��С

typedef struct log_q {
      char data[RING_SIZE];//�˷�һ���ڵ�f ��������'��'��'��'
      int front, rear;

      MUTEX_TYPE lock;

      pthread_mutex_t job_lock;
	  pthread_cond_t job_notify;
} log_queue;


static pthread_t g_thd_handle;

static int g_thd_run = 0;

static unsigned int g_cur_files_cnt = 0;
static log_queue g_log_queue;

static unsigned int g_logfile_max_kb = MAX_SIZE_KB;
static unsigned int g_logfile_max_cnt = 8;
static unsigned int g_isAsyncWrite = FALSE;

static char g_log_path[MAX_NAME_LEN + 1] = {0};
static char g_log_name[MAX_NAME_LEN + 1] = {0};
static int g_log_level = L_INFO;


// default_size : The size of Linked Queue by deault
static inline void init_queue(log_queue *lq){
	lq->front = lq->rear = 0;

	MUTEX_SETUP(lq->lock);

	pthread_mutex_init(&lq->job_lock, NULL);
	pthread_cond_init(&lq->job_notify, NULL);
}

static inline void free_queue(log_queue *lq)
{
	MUTEX_CLEANUP(lq->lock);
}

static inline void queue_in(log_queue *lq, char *data, int len){
	int pos = 0;
	while(pos < len)
	{
		if(lq->front == (lq->rear + 1) % (RING_SIZE)){
			static int count = 1;
			count++;
			if (count % 1000)
			{
				usleep(10);
				printf("log queue is full\n");
			}
			break;
		}

		lq->data[lq->rear] = data[pos];
		lq->rear = (lq->rear + 1) % (RING_SIZE);

		pos++;
	}
}

static inline int queue_out(log_queue *lq, char *ret){
	if(lq->front == lq->rear){
		return -1;
	}

    *ret = lq->data[lq->front];
    lq->front = (lq->front + 1) % (RING_SIZE);
    return 0;
}

static unsigned long get_cur_logfile_size(char *logName)
{
    unsigned long filesize = 0;
    char temp[128] = {0};
	SNPRINTF(temp, 127, "%s/%s.log", g_log_path, logName);

    struct stat statbuff;
    if(stat(temp, &statbuff) < 0)
    {
        return filesize;
    }else
    {
        filesize = statbuff.st_size;
    }

    return filesize;
}

static void file_size_check(char *logName){
    unsigned long size = get_cur_logfile_size(logName);

    if((size >> 10) >= g_logfile_max_kb)
    {
        char oldFile[128] = {0}, newFile[128] = {0};
        SNPRINTF(oldFile, 127, "%s/%s.log", g_log_path, g_log_name);

        if (g_cur_files_cnt >= g_logfile_max_cnt)
        {
        	g_cur_files_cnt = 0;
        }

		SNPRINTF(newFile, 127, "%s.%d", oldFile, g_cur_files_cnt+1);

        rename(oldFile, newFile);//������

        g_cur_files_cnt += 1;
#if 0
        FILE *pfd = fopen(oldFile, "a");
		if (NULL == pfd)
		{
			fprintf(stderr, "open %s failed.\n", oldFile);
		}
		else
		{
			chmod(oldFile, S_IRWXU | S_IRWXG | S_IRWXO);
			fclose(pfd);
		}
#endif
    }
}

static unsigned int get_cur_logfile_cnt(char *logName){
    DIR *dir = NULL;
    struct dirent *dptr = NULL;
    if(!(dir = opendir(g_log_path))){
        printf("[error]open dir %s failed", g_log_path);
        exit(-1);
    }

    int count = 0;
    while(NULL != (dptr = readdir(dir))){
        if(dptr->d_type != DT_DIR){
        	if(strstr(dptr->d_name, logName) != NULL)
			{
        		count++;
			}
        }
    }
    return count;
}

static void *async_fputs(void *arg)
{
	int ret = -1;

	char fileName[128] = {0};
	SNPRINTF(fileName, 127, "%s/%s.log", g_log_path, g_log_name);

	file_size_check(g_log_name);

	int count = 0;

	/*��ʾ�߳��Ѿ�����*/
	g_thd_run = 2;

	while(g_thd_run != 0)
	{
		//��ȡ�������еĴ�, ��д����־�ļ�
        /*wait*/
        struct timespec beattime;
		struct timeval now;

		gettimeofday(&now, NULL);
		beattime.tv_sec = now.tv_sec + 2;
		beattime.tv_nsec = now.tv_usec * 1000;

		pthread_mutex_lock(&g_log_queue.job_lock);
		pthread_cond_timedwait(&g_log_queue.job_notify, &g_log_queue.job_lock, &beattime);
		pthread_mutex_unlock(&g_log_queue.job_lock);

		FILE *file = NULL;
		if((file = fopen(fileName, "a+")) == NULL)
		{
			//����ֵ������ΪNULL
			printf("[error]open log %s file failed.\n", fileName);
			continue;
		}

		char outch = 0;
		while(-1 != (ret = queue_out(&g_log_queue, &outch)))
		{
			fputc(outch, file);

			count++;
			/*ÿд1M���һ�δ�С*/
			if((count & 0xfffff) == 0)
			{
				/*��close*/
				fclose(file);
				/*����С*/
				file_size_check(g_log_name);
				/*���´�*/
				if((file = fopen(fileName, "a+")) == NULL)
				{
					//����ֵ������ΪNULL
					printf("[error]open log %s file failed.\n", fileName);
					break;
				}
			}
		}

		if (file != NULL)
		{
			fclose(file);
		}
	}

	pthread_exit((void *)1);
	return NULL;
}

int loggger_init(char *log_path, char *mod_name,
		unsigned int maxfilekb, unsigned int maxfilecnt,
		BOOL isAsynWr)
{
	strncpy(g_log_path, log_path, MAX_NAME_LEN);
	strncpy(g_log_name, mod_name, MAX_NAME_LEN);
	g_logfile_max_kb = maxfilekb;
	g_logfile_max_cnt = maxfilecnt;
	g_isAsyncWrite = isAsynWr;

	struct stat s;
	if(-1 == stat(g_log_path, &s))
	{
		util_creatdir(g_log_path);
	}

	g_cur_files_cnt = get_cur_logfile_cnt(g_log_name);

	if (g_isAsyncWrite)
	{
		init_queue(&g_log_queue);

		g_thd_run = 1;
		pthread_create(&g_thd_handle, NULL, async_fputs, NULL);
		/*�ȴ��߳�����*/
		while(g_thd_run != 2)
		{
			usleep(1);
		}
	}

    return 0;
}

void loggger_exit()
{
	if (g_isAsyncWrite)
	{
		g_thd_run = 0;
		pthread_join(g_thd_handle, NULL);
		free_queue(&g_log_queue);
	}
}

void logger_char_flush()
{
}

void logger_char_write(int level, char ch)
{
	if (level < g_log_level)
	{
		return;
	}

	if (g_isAsyncWrite)
	{
		/*���*/
		MUTEX_LOCK(g_log_queue.lock);
		queue_in(&g_log_queue, &ch, 1);
		MUTEX_UNLOCK(g_log_queue.lock);

		pthread_mutex_lock(&g_log_queue.job_lock);
		pthread_cond_broadcast(&g_log_queue.job_notify);
		pthread_mutex_unlock(&g_log_queue.job_lock);
	}
	else
	{
		/*���*/
		char fileName[128] = {0};
		SNPRINTF(fileName, 127, "%s/%s.log", g_log_path, g_log_name);

		//file_size_check(g_log_name);

		FILE *file = NULL;
		if((file = fopen(fileName, "a+")) == NULL)
		{
			//����ֵ������ΪNULL
			printf("[error]open log %s file failed.\n", fileName);
			return;
		}

		fputc(ch, file);
		fclose(file);
	}
}

void logger_write(int level, const char *format, ...)
{// һ�����ȥ֮����ô��ת��־???
    char src[MAX_LINE_LEN + 1] = {'\0'};
    char dateformat[64] = {'\0'};
    char outstr[MAX_LINE_LEN + 1] = {0};
    int outstrlen = 0;

    if (level < g_log_level)
    {
    	return;
    }

    va_list argp;

    time_t timer;
	struct tm *now = NULL;
    time(&timer);
    now = localtime(&timer);
    sprintf(dateformat, "[%04d-%02d-%02d %02d:%02d:%02d]", now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);

    va_start(argp, format);
    VSNPRINTF(src, MAX_LINE_LEN, format, argp);
    va_end(argp);

    //�� �߳�ά����ѭ������ �������Ҫд��Ĵ�
    switch(level){
        case L_ERROR://error����
        	outstrlen = SNPRINTF(outstr, MAX_LINE_LEN, "%s [ERR]:%s \n", dateformat, src);
        	break;
        case L_DEBUG://debug����
        	outstrlen = SNPRINTF(outstr, MAX_LINE_LEN, "%s [DBG]:%s \n", dateformat, src);
        	break;
        case L_WARN://warn����
        	outstrlen = SNPRINTF(outstr, MAX_LINE_LEN, "%s [WARN]:%s \n", dateformat, src);
        	break;
        case L_INFO://info����
        	outstrlen = SNPRINTF(outstr, MAX_LINE_LEN, "%s [INFO]:%s \n", dateformat, src);
            break;
        default:
        	outstrlen = SNPRINTF(outstr, MAX_LINE_LEN, "%s [DEF]:%s \n", dateformat, src);
            break;
    }

    if (g_isAsyncWrite)
    {
		MUTEX_LOCK(g_log_queue.lock);
		queue_in(&g_log_queue, outstr, outstrlen);
		MUTEX_UNLOCK(g_log_queue.lock);

		pthread_mutex_lock(&g_log_queue.job_lock);
		pthread_cond_broadcast(&g_log_queue.job_notify);
		pthread_mutex_unlock(&g_log_queue.job_lock);
    }
    else
    {
    	char fileName[128] = {0};
		SNPRINTF(fileName, 127, "%s/%s.log", g_log_path, g_log_name);

    	file_size_check(g_log_name);

		FILE *file = NULL;
		if((file = fopen(fileName, "a+")) == NULL)
		{
			//����ֵ������ΪNULL
			printf("[error]open log %s file failed, error %d, %s.\n", fileName, errno, strerror(errno));
			return;
		}

		fputs(outstr, file);
		fclose(file);
    }
}

void logger_set_level(int level)
{
	g_log_level = level;
}

