
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <libnet.h>
#include <unbound.h>

#include "dnsrob.h"
#include "dq_data.h"

int isdone = 0;
int free_num = 1024;

//static
void create_dns_worker(void *(*func)(void *), void *arg) {
    pthread_t       thread;
    pthread_attr_t  attr;
    int             ret;

    pthread_attr_init(&attr);

    if ((ret = pthread_create(&thread, &attr, func, arg)) != 0) {
        fprintf(stderr, "Can't create thread: %s\n",
                strerror(ret));
        exit(1);
    }
}

#include <arpa/inet.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <libnet.h>

void mycallback(void* mydata, int err, struct ub_result* result)
{
	DQ_ITEM* item = mydata;

	if(err != 0)
	{
		printf("resolve error: %s\n", ub_strerror(err));
		goto clean;
	}

	/* show first result */
//	if(!result->havedata)
//		goto clean;

	struct libnet_ipv4_hdr *ip;
	struct libnet_udp_hdr *udp;
	HEADER *dns;
	libnet_ptag_t ptag;
	u_char buf[1024];

	ip = (struct libnet_ipv4_hdr *)(item->pkt + pcap_off);
	udp = (struct libnet_udp_hdr *)(item->pkt + pcap_off + (ip->ip_hl * 4));
	dns = (HEADER *)(udp + 1);

	log_stderr(1, "answer packet lenth is %d, dns id is %u", result->answer_len, dns->id);

	memcpy(buf, result->answer_packet, result->answer_len);
	memcpy(buf, dns, 2);

	ptag = libnet_build_udp(
			ntohs(udp->uh_dport),
			ntohs(udp->uh_sport),
			LIBNET_UDP_H + result->answer_len,
			0,
			buf,
			result->answer_len,
			l,
			0);
	if(ptag == -1)
	{
		log_stderr(1, "libnet_build_udp err\n");
		goto clean;
	}

	ptag = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_UDP_H + result->answer_len,
			0,
			libnet_get_prand(LIBNET_PRu16),
			0,
			64,
			IPPROTO_UDP,
			0,
			ip->ip_dst.s_addr,
			ip->ip_src.s_addr,
			NULL,
			0,
			l,
			0);

	if(ptag == -1)
	{
		log_stderr(1, "libnet_build_ipv4 err\n");
		goto clean;
	}

	int c = libnet_write(l);

    if (c == -1)
    {
        log_stderr(1, "Write error: %s\n", libnet_geterror(l));
        goto clean;
    }
    else
    {
        log_stderr(1, "Wrote %d byte DNS packet; check the wire.\n", c);
    }

clean:
    DQ_ITEM_init(item);
    DQ_push(freeDQ, item);
    log_stderr(1, "free element num is %d", freeDQ->num);

    libnet_clear_packet(l);
	ub_resolve_free(result);
}

void deliver_dns(DNS_THREAD* me, DQ_ITEM* item)
{
	struct libnet_ipv4_hdr *ip;
	struct libnet_udp_hdr *udp;
	HEADER *dns;

	char name[MAXHOSTNAMELEN];
	u_char *p, *q, *end, buf[1024];
	int i, anslen, dnslen;
	struct in_addr dst;
	u_short type, class;

	memset(buf, 0x0, sizeof(buf));
	memcpy(buf, item->pkt, item->pkt_len);

	ip = (struct libnet_ipv4_hdr *)(buf + pcap_off);
	udp = (struct libnet_udp_hdr *)(buf + pcap_off + (ip->ip_hl * 4));
	dns = (HEADER *)(udp + 1);
	p = (u_char *)(dns + 1);
	end = (u_char *)buf + item->pkt_len;

	if ((dnslen = end - (u_char *)dns) < sizeof(*dns))
		goto clean;

	if (dns->opcode != QUERY || ntohs(dns->qdcount) != 1 ||
	    dns->ancount || dns->nscount || dns->arcount)
		goto clean;

	if ((i = dn_expand((u_char *)dns, end, p, name, sizeof(name))) < 0)
		goto clean;

	p += i;
	GETSHORT(type, p);
	GETSHORT(class, p);

	if (class != C_IN)
		goto clean;

	log_stderr(1, "query type is %d, name is %s, id is %u \n", type, name, dns->id);

	int retval = ub_resolve_async(g_ctx, name,
		type, class,
		(void*)item, mycallback, NULL);

	if(retval != 0)
	{
		log_stderr(1, "resolve error: %s\n", ub_strerror(retval));
		goto clean;
	}

	return;

clean:
	DQ_ITEM_init(item);
	DQ_push(freeDQ, item);
	log_stderr(1, "free element num is %d", freeDQ->num);

}
void read_dns(DNS_THREAD* me, DQ_ITEM* item)
{
	struct libnet_ipv4_hdr *ip;
	struct libnet_udp_hdr *udp;
	HEADER *dns;

	char name[MAXHOSTNAMELEN];
	u_char *p, *q, *end, buf[1024];
	int i, anslen, dnslen;
	struct in_addr dst;
	u_short type, class;

	ip = (struct libnet_ipv4_hdr *)(item->pkt + pcap_off);
	udp = (struct libnet_udp_hdr *)(item->pkt + pcap_off + (ip->ip_hl * 4));
	dns = (HEADER *)(udp + 1);
	p = (u_char *)(dns + 1);
	end = (u_char *)item->pkt + item->pkt_len;

	if ((dnslen = end - (u_char *)dns) < sizeof(*dns))
		return;

	if (dns->opcode != QUERY || ntohs(dns->qdcount) != 1 ||
	    dns->ancount || dns->nscount || dns->arcount)
		return;

	if ((i = dn_expand((u_char *)dns, end, p, name, sizeof(name))) < 0)
		return;

	p += i;
	GETSHORT(type, p);
	GETSHORT(class, p);

	if (class != C_IN)
		return;

	fprintf(stderr, "query type is %d, name is %s\n", type, name);

	libnet_ptag_t ptag;
	p = buf + dnslen;
	//tmp
	inet_aton("127.0.0.1", &dst);
	memcpy(p, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04",
	       12);
	memcpy(p + 12, &dst.s_addr, sizeof(dst.s_addr));
	anslen = 16;
	//tmp
	memcpy(buf, (u_char *)dns, dnslen);
	//dns = (HEADER *)(buf + LIBNET_IPV4_H + LIBNET_UDP_H);
	dns = (HEADER *)(buf);
	dns->qr = dns->ra = 1;
	//if (type == T_PTR) dns->aa = 1;
	dns->ancount = htons(1);

	dnslen += anslen;

	ptag = libnet_build_udp(
			ntohs(udp->uh_dport),
			ntohs(udp->uh_sport),
			LIBNET_UDP_H + dnslen,
			0,
			buf,
			dnslen,
			l,
			0);
	if(ptag == -1)
	{
		log_stderr(1, "libnet_build_udp err\n");
		return;
	}

	ptag = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_UDP_H + dnslen,
			0,
			libnet_get_prand(LIBNET_PRu16),
			0,
			64,
			IPPROTO_UDP,
			0,
			ip->ip_dst.s_addr,
			ip->ip_src.s_addr,
			NULL,
			0,
			l,
			0);

	if(ptag == -1)
	{
		log_stderr(1, "libnet_build_ipv4 err\n");
		return;
	}

	int c = libnet_write(l);

    if (c == -1)
    {
        log_stderr(1, "Write error: %s\n", libnet_geterror(l));
        return;
    }
    else
    {
        log_stderr(1, "Wrote %d byte DNS packet; check the wire.\n", c);
    }

    libnet_clear_packet(l);
    //libnet_destroy(l);
}

void read_query(DNS_THREAD* me)
{
	char buf[1];
	DQ_ITEM* item;

    if (read(me->notify_receive_fd, buf, 1) != 1)
    	fprintf(stderr, "Can't read from receive pipe\n");

//    log_stderr(1, "get one \n");

    item = DQ_pop(me->m_DQ);
    if(NULL != item)
    {
    	//read_dns(me, item);
    	deliver_dns(me, item);
 //   	DQ_ITEM_init(item);
 //  	DQ_push(freeDQ, item);
 //   	log_stderr(1, "free element num is %d", freeDQ->num);
    }

}

#define max(a,b) ((a)>(b))?(a):(b)

void *thread_run(void* arg)
{
	DNS_THREAD* me = arg;
	me->thread_id = pthread_self();

	int maxfd, retval;
	fd_set readfds;
	struct timeval *tv, tvbuf;
	int u_fd = 0;

	u_fd = ub_fd(g_ctx);
	maxfd= max(u_fd, me->notify_receive_fd) + 1;

	log_stderr(1, "thread id is %lu", me->thread_id);
	log_stderr(1, "maxfd  is %d", maxfd);

	while(1)
	{
		FD_ZERO(&readfds);
		FD_SET(me->notify_receive_fd, &readfds);
		FD_SET(u_fd, &readfds);

		tv = 0;
		retval = select(maxfd, &readfds, NULL, NULL, NULL);

		if(isdone)
		{
			printf("get isdone in thread! \n");
			ub_ctx_delete(g_ctx);
			return;
		}

		if(retval == -1) // 0 for timeout
		{
			if (errno == EINTR) continue;
			printf("select error! \n");
			exit(1);
		}
		if FD_ISSET(me->notify_receive_fd, &readfds)
		{
			//printf("now read stdin \n");
			read_query(me);
		}
		if FD_ISSET(u_fd, &readfds)
		{
			log_stderr(1, "now ub_process \n");
			retval = ub_process(g_ctx);
			if(retval != 0) {
				printf("resolve error: %s\n", ub_strerror(retval));
				return 1;
			}
		}

	}
	return NULL;
}

void thread_init()
{
	log_stderr(1, "thread init\n");

	freeDQ = malloc(sizeof(DQ));
	freeDQ_init(freeDQ, free_num);

	log_stderr(1, "thread init\n");

    int fds[2];
    if (pipe(fds))
    {
        log_stderr(1, "Can't create notify pipe");
        exit(1);
    }
	g_thread.notify_receive_fd = fds[0];
	g_thread.notify_send_fd = fds[1];

	g_thread.m_DQ = malloc(sizeof(DQ));
	DQ_init(g_thread.m_DQ);

	create_dns_worker(thread_run, &g_thread);

}
