#ifndef __SOCKS_H__
#define __SOCKS_H__

#include <sys/types.h>

struct bufferevent;
struct tcp_pcb;
struct event_base;

struct socks_data {
	struct bufferevent *bev;
	u_char version;
	ip_addr_t ipaddr;
	u_int16_t port;
	struct tcp_pcb *pcb;
};

void socks_free(struct socks_data *data);
void socks_flush_response(struct socks_data *data);
int socks_tcp_connect(struct socks_data *data);
int socks_tcp_bind(struct socks_data *data);
void socks_error(struct bufferevent *bev, short events, void *ctx);

int socks_listen(struct event_base *base, u_int16_t port);

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#endif
