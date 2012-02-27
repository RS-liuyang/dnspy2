
#ifndef __DQ_DATA_H__
#define __DQ_DATA_H__

#include <pthread.h>
#include <sys/types.h>

#define MAX_PKT_SIZE 1024

typedef struct dns_query_item DQ_ITEM;
struct dns_query_item
{
	u_char pkt[MAX_PKT_SIZE];
	u_int32_t pkt_len;
	DQ_ITEM* next;
};

typedef struct dns_query_queue DQ;
struct dns_query_queue
{
	DQ_ITEM* head;
	DQ_ITEM* tail;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    u_int32_t num;
};

void DQ_init(DQ* dq);
DQ_ITEM *DQ_pop(DQ *dq);
void DQ_push(DQ *dq, DQ_ITEM *item);
void DQ_ITEM_init(DQ_ITEM *item);
u_int32_t freeDQ_init(DQ* freeDQ, const u_int32_t n);



#endif
