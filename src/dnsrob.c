/*
 ============================================================================
 Name        : dnsrob.c
 Author      : Yang Liu
 Version     :
 Copyright   : Runstone Co.
 Description : dnsrob in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>

#include <resolv.h>
#include <arpa/nameser.h>
#include <libnet.h>

#include <pthread.h>
#include <pcap.h>
#include <unbound.h>
#include "log.h"
#include "dq_data.h"
#include "dnsrob.h"

void usage();
void cleanup(int sig);
int pcap_dloff(pcap_t *pd);
void dns_spoof(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt);
void send_dns(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt);

#ifndef HAVE_SIGIGNORE
static int sigignore(int sig) {
    struct sigaction sa = { .sa_handler = SIG_IGN, .sa_flags = 0 };

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(sig, &sa, 0) == -1) {
        return -1;
    }
    return 0;
}
#endif



static pcap_t *pd = NULL;
int pcap_off = -1;
libnet_t *l = NULL;
DQ* freeDQ = NULL;
DNS_THREAD g_thread;
struct ub_ctx* g_ctx;

int
main(int argc, char* argv[])
{
/*
	get_options();
	show_message();
	get_pid();
	time_init();
	log_init();

	save_options();
	process_options();
	os_init();

	test_config();
	process_signals();

	get_config();
	init_signals();
	do_daemon();

	create_pid_file();
*/
	char *p, *dev, *mydnsip, buf[1024];
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;

	dev = mydnsip = NULL;

	while ((i = getopt(argc, argv, "s:v:i:r:h?")) != -1) {
		switch (i) {
		case 'i':
			dev = optarg;
			break;
		case 'r':
			mydnsip = optarg;
			break;
		case 'v':
			verbosity = atoi(optarg);
			break;
		case 's':
			free_num = atoi(optarg);
			break;
		default:
			//usage();
			break;
		}
	}


	if(mydnsip == NULL)
	{
		log_stderr(1, "%s", "Error! Must set resolver ip with -r");
	    return 1;
	}

	if(getuid())
	{
		log_stderr(1, "%s", "Error! Must be root ... exiting");
	    return 1;
	}

	if (dev == NULL && (dev = pcap_lookupdev(errbuf)) == NULL)
	{
		log_stderr(1, "pcap_lookupdev err: %s", errbuf);
		return 1;
	}

	//on Linux systems with 2.2 or later kernels, a device
    //argument of "any" or NULL can be  used  to  capture  packets  from  all
    //interfaces. but if an argument of "any" or NULL is supplied, the promisc flag is ignored

	snprintf(buf, sizeof(buf), "udp dst port 53 and not net %s", mydnsip);

	pcap_t *pd;
	bpf_u_int32 net, mask = 0;
	struct bpf_program filter;

	pd = pcap_open_live(dev, 65536, 1, 512, errbuf);
	if(pd == NULL)
	{
		log_stderr(1, "pcap_open_live err: %s", errbuf);
		return 1;
	}

	//network mask may useless in this use case, so we juse leave mask as 0.
	/*
	if (pcap_lookupnet(dev, &net, &mask, ebuf) == -1)
	{
		log_stderr(1, "pcap_lookupnet err: %s", errbuf);
		return 1;
	}
*/
	if (pcap_compile(pd, &filter, buf, 1, mask) < 0) {
		pcap_perror(pd, "pcap_compile");
		return 1;
	}

	if (pcap_setfilter(pd, &filter) == -1) {
		pcap_perror(pd, "pcap_setfilter");
		return 1;
	}

	pcap_off = pcap_dloff(pd);

	//pcap_dloff(pd)

	//char errbuf[LIBNET_ERRBUF_SIZE];
    l = libnet_init(
            LIBNET_RAW4,                            /* injection type */
            dev,                                   /* network interface */
            errbuf);                                /* error buffer */
    if (!l)
    {
        log_stderr(1, "libnet_init: %s", errbuf);
        return 1;
    }

	libnet_seed_prand(l);

	//

	signal(SIGHUP, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGQUIT, cleanup);

	sigignore(SIGPIPE);

	g_ctx = ub_ctx_create();
	if(!g_ctx) {
		printf("error: could not create unbound context\n");
		return 1;
	}
	ub_ctx_set_fwd(g_ctx, mydnsip);


	thread_init();

	//pcap_loop(pd, -1, dns_spoof, NULL);
	pcap_loop(pd, -1, send_dns, NULL);
}

void
cleanup(int sig)
{
	set_isdone();
	libnet_destroy(l);
//	pcap_breakloop(pd);
//	pcap_close(pd);
//	ub_ctx_delete(g_ctx);

	//pthread_join(g_thread.thread_id, NULL);
	exit(EXIT_SUCCESS);
}

int
pcap_dloff(pcap_t *pd)
{
	int offset = -1;

	switch (pcap_datalink(pd))
	{
		case DLT_EN10MB:
			offset = 14;
			break;
		case DLT_IEEE802:
			offset = 22;
			break;
		case DLT_FDDI:
			offset = 21;
			break;
		case DLT_NULL:
			offset = 4;
			break;
		default:
			log_stderr(1, "unsupported datalink type");
			break;
	}
	return (offset);
}

void set_isdone()
{
	isdone = 1;
	if (write(g_thread.notify_send_fd, "", 1) != 1)
	{
		log_stderr(1, "Writing to thread notify pipe");
	}
}

void
send_dns(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	DQ_ITEM *item = DQ_pop(freeDQ);
	if(NULL == item)
		return;

	memcpy(item->pkt, pkt, pkthdr->caplen);
	item->pkt_len = pkthdr->caplen;

	DQ_push(g_thread.m_DQ, item);

	if (write(g_thread.notify_send_fd, "", 1) != 1)
	{
		log_stderr(1, "Writing to thread notify pipe");
	}
	//log_stderr(1, "send one\n");
}

void
dns_spoof(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	struct libnet_ipv4_hdr *ip;
	struct libnet_udp_hdr *udp;
	HEADER *dns;

	char name[MAXHOSTNAMELEN];
	u_char *p, *q, *end, buf[1024];
	int i, anslen, dnslen;
	struct in_addr dst;
	u_short type, class;

	ip = (struct libnet_ipv4_hdr *)(pkt + pcap_off);
	udp = (struct libnet_udp_hdr *)(pkt + pcap_off + (ip->ip_hl * 4));
	dns = (HEADER *)(udp + 1);
	p = (u_char *)(dns + 1);
	end = (u_char *)pkt + pkthdr->caplen;

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

//	p = buf + IP_H + UDP_H + dnslen;

	//in_addr_t dst;

	libnet_ptag_t ptag;

	//p = buf + LIBNET_IPV4_H + LIBNET_UDP_H + dnslen;
	p = buf + dnslen;
	//tmp
	inet_aton("127.0.0.1", &dst);
	memcpy(p, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04",
	       12);
	memcpy(p + 12, &dst.s_addr, sizeof(dst.s_addr));
	anslen = 16;
	//tmp

	//memcpy(buf + LIBNET_IPV4_H + LIBNET_UDP_H, (u_char *)dns, dnslen);
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
