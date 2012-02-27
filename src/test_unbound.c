
/*
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
*/


#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <unbound.h>
#include <errno.h>
#include <signal.h>

#include "log.h"


struct ub_ctx* ctx;
volatile int done = 0;

int is_pipe = 1;
static int used, avail;
static char *buf;

/* This is called when resolution is completed */
void mycallback(void* mydata, int err, struct ub_result* result)
{
	int* done = (int*)mydata;
	*done = 1;
	if(err != 0) {
		printf("resolve error: %s\n", ub_strerror(err));
		return;
	}
	/* show first result */
	if(result->havedata)
		printf("The address of %s is %s\n", result->qname,
			inet_ntoa(*(struct in_addr*)result->data[0]));

	ub_resolve_free(result);
}


void process_optarg(const char* buf)
{

	int retval = ub_resolve_async(ctx, buf,
		1 /* TYPE A (IPv4 address) */,
		1 /* CLASS IN (internet) */,
		(void*)&done, mycallback, NULL);
	if(retval != 0) {
		printf("resolve error: %s\n", ub_strerror(retval));
		return;
	}
}


static void read_stdin(void)
{
	char buffer[1024];
	int r;
	memset(buffer, 0x0, 1024);

	do
	{
		r = read(0, buffer, 1024);
	} while (r < 0 && errno == EINTR);

	if (r == 0)
	{
		is_pipe=0;
		return;
	}
	if (r < 0)
	{
		printf("read stdin error: %s\n", strerror(errno));
		exit(1);
	}
	buffer[r-1]=0;
	printf("buffer is: %s, lenth is: %d\n", buffer, r);

	process_optarg(buffer);
}

int main(void)
{
	int retval;
	int i = 0;
	signal(SIGPIPE,SIG_IGN);
	/* create context */
	ctx = ub_ctx_create();
	if(!ctx) {
		printf("error: could not create unbound context\n");
		return 1;
	}
	ub_ctx_set_fwd(ctx, "8.8.8.8");

	/* asynchronous query for webserver */
	retval = ub_resolve_async(ctx, "www.nlnetlabs.nl",
		1 /* TYPE A (IPv4 address) */,
		1 /* CLASS IN (internet) */,
		(void*)&done, mycallback, NULL);
	if(retval != 0) {
		printf("resolve error: %s\n", ub_strerror(retval));
		return 1;
	}

	int u_fd = ub_fd(ctx);

	int maxfd;
	fd_set readfds;
	struct timeval *tv, tvbuf;

	while(1)
	{
		maxfd= u_fd + 1;
		FD_ZERO(&readfds);
		if(is_pipe) FD_SET(0,&readfds);
		FD_SET(u_fd, &readfds);
		tv = 0;
		retval = select(maxfd, &readfds, NULL, NULL, NULL);
		if(retval == -1) // 0 for timeout
		{
			if (errno == EINTR) continue;
			printf("select error! \n");
			exit(1);
		}
		if FD_ISSET(0, &readfds)
		{
			printf("now read stdin \n");
			read_stdin();
		}
		if FD_ISSET(u_fd, &readfds)
		{
			printf("now ub_process \n");
			retval = ub_process(ctx);
			if(retval != 0) {
				printf("resolve error: %s\n", ub_strerror(retval));
				return 1;
			}
		}


	}


	/* we keep running, lets do something while waiting */
/*
	while(!done) {
		usleep(100000);  wait 1/10 of a second
		printf("time passed (%d) ..\n", i++);
		retval = ub_process(ctx);
		if(retval != 0) {
			printf("resolve error: %s\n", ub_strerror(retval));
			return 1;
		}
	}

	printf("done\n");*/

	ub_ctx_delete(ctx);
	return 0;
}
