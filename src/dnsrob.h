#ifndef __RS_DNSROB_H__
#define __RS_DNSROB_H__

#include <pthread.h>
#include "dq_data.h"

typedef struct {
    pthread_t thread_id;        /* unique ID of this thread */
//    struct event notify_event;  /* listen event for notify pipe */
    int notify_receive_fd;      /* receiving end of notify pipe */
    int notify_send_fd;         /* sending end of notify pipe */
    DQ*	m_DQ;
//    struct conn_queue *new_conn_queue; /* queue of new connections to handle */
} DNS_THREAD;

extern int pcap_off;
extern libnet_t *l;
extern DQ* freeDQ;
extern DNS_THREAD g_thread;

extern struct ub_ctx* g_ctx;
extern int isdone;
extern int free_num;

#endif
