
#include <pthread.h>

#include "dq_data.h"
#include "log.h"

void DQ_init(DQ* dq)
{
	pthread_mutex_init(&dq->lock, NULL);
	pthread_cond_init(&dq->cond, NULL);
	dq->head = NULL;
	dq->tail = NULL;
	dq->num = 0;
}


DQ_ITEM *DQ_pop(DQ *dq)
{
    DQ_ITEM *item;

    pthread_mutex_lock(&dq->lock);
    item = dq->head;
    if (NULL != item)
    {
        dq->head = item->next;
        dq->num--;
        if (NULL == dq->head)
            dq->tail = NULL;
    }
    pthread_mutex_unlock(&dq->lock);

    return item;
}

void DQ_push(DQ *dq, DQ_ITEM *item)
{
    item->next = NULL;

    pthread_mutex_lock(&dq->lock);
    dq->num++;
    if (NULL == dq->tail)
        dq->head = item;
    else
        dq->tail->next = item;
    dq->tail = item;
    //pthread_cond_signal(&dq->cond);
    pthread_mutex_unlock(&dq->lock);
}

void DQ_ITEM_init(DQ_ITEM *item)
{
	memset(item->pkt, 0x00, MAX_PKT_SIZE);
	item->pkt_len = 0;
	item->next = NULL;
}

u_int32_t freeDQ_init(DQ* freeDQ, const u_int32_t n)
{
	DQ_init(freeDQ);

	DQ_ITEM *item = NULL;
	u_int32_t num, i;

	if(0 == n)
		num = 1000;
	else
		num = n;

	item = malloc(sizeof(DQ_ITEM) * num);
	if(NULL == item)
		return -1;

	for(i = 1; i < num; i++)
	{
		DQ_ITEM_init(&item[i-1]);
		item[i-1].next = &item[i];
	}
	DQ_ITEM_init(&item[num-1]);

	pthread_mutex_lock(&freeDQ->lock);
	freeDQ->head = &item[0];
	freeDQ->tail = &item[num-1];
	freeDQ->num = num;
	pthread_mutex_unlock(&freeDQ->lock);

	return num;
}
