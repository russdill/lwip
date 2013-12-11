#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <lwip/tcp.h>
#include <lwip/tcp_impl.h>

#include "socks.h"
#include "socks4.h"
#include "socks5.h"

void
socks_free(struct socks_data *data)
{
	LWIP_DEBUGF(SOCKS_DEBUG, ("%s\n", __func__));
	if (data->bev) {
		bufferevent_free(data->bev);
		data->bev = NULL;
	}
	if (data->pcb) {
		tcp_arg(data->pcb, NULL);
		if (tcp_close(data->pcb) < 0)
			tcp_abort(data->pcb);
	}
	free(data);
}

/* Finish writing out tcp write buffer, then close */
static void
socks_flush_tcp(struct socks_data *data)
{
	if (data->bev) {
		bufferevent_free(data->bev);
		data->bev = NULL;
	}
	if (!data->pcb || tcp_sndbuf(data->pcb) == TCP_SND_BUF)
		socks_free(data);
}

static void
socks_flush_socks_fin(struct bufferevent *bev, void *ctx)
{
	LWIP_DEBUGF(SOCKS_DEBUG, ("%s\n", __func__));
	socks_free(ctx);
}

/* Finish writing out socks write buffer, then close */
void
socks_flush_socks(struct socks_data *data)
{
	if (data->pcb) {
		tcp_arg(data->pcb, NULL);
		if (tcp_close(data->pcb) < 0)
			tcp_abort(data->pcb);
		data->pcb = NULL;
	}
	bufferevent_disable(data->bev, EV_READ);
	bufferevent_setwatermark(data->bev, EV_WRITE, 0, 16384);
	bufferevent_setcb(data->bev, NULL, socks_flush_socks_fin, socks_error, data);
}

static void
socks_tcp_err(void *ctx, err_t err)
{
	struct socks_data *data = ctx;
	LWIP_DEBUGF(SOCKS_DEBUG, ("%s\n", __func__));
	if (!data)
		return;

	/* lwIP will free the pcb */
	tcp_arg(data->pcb, NULL);
	data->pcb = NULL;

	if (!data->connected) {
	} else
		socks_flush_socks(data);
}

static void
socks_writable(struct bufferevent *bev, void *ctx)
{
	struct socks_data *data = ctx;
	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: We can write data to socks\n", __func__));
	if (data->pcb && data->pcb->refused_data) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: Asking stack to send refused data\n", __func__));
		tcp_process_refused_data(data->pcb);
	}
}

static err_t
socks_tcp_recv(void *ctx, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	struct socks_data *data = ctx;
	struct pbuf *curr;
	int len;

	if (err < 0 || !p || !data || !data->bev) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: ERR_ABRT, (%s)\n", __func__, tcp_debug_state_str(pcb->state)));
		if (data)
			socks_flush_socks(data);
		return ERR_ABRT;
	}

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: %d bytes have been received from TCP\n", __func__, p->tot_len));
	if (evbuffer_get_length(bufferevent_get_output(data->bev)) > 4096) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: socks output buffer is full\n", __func__));
		return ERR_WOULDBLOCK;
	}

	len = p->tot_len;
	for (curr = p; curr; curr = curr->next)
		bufferevent_write(data->bev, curr->payload, curr->len);
	pbuf_free(p);
	tcp_recved(pcb, len);

	return 0;
}

static void
socks_readable(struct bufferevent *bev, void *ctx)
{
	struct socks_data *data = ctx;
	int avail;
	struct evbuffer *buf;
	struct evbuffer_iovec vec_out;
	err_t ret;
	int wait_for_more = 0;

	avail = tcp_sndbuf(data->pcb);
	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: %d bytes of sndbuf space\n", __func__, avail));
	if (!avail) {
		bufferevent_disable(bev, EV_READ);
		return;
	}

	buf = bufferevent_get_input(data->bev);
	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: We can send %d bytes\n", __func__, evbuffer_get_length(buf)));
	if (avail < evbuffer_get_length(buf)) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: Not enough sndbuf space, wait for more\n", __func__));
		wait_for_more = 1;
	} else if (avail > evbuffer_get_length(buf))
		avail = evbuffer_get_length(buf);

	if (!avail)
		return;

	evbuffer_pullup(buf, avail);
	evbuffer_peek(buf, avail, NULL, &vec_out, 1);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: Writing %d bytes to TCP\n", __func__, avail));
	ret = tcp_write(data->pcb, vec_out.iov_base, avail, TCP_WRITE_FLAG_COPY);
	if (ret == ERR_MEM) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: ERR_MEM\n", __func__));
		bufferevent_disable(bev, EV_READ);
	} else if (ret < 0) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: tcp_write err\n", __func__));
		socks_flush_socks(data);
	} else {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: Draining %d bytes from socks read\n", __func__, avail));
		evbuffer_drain(buf, avail);
		if (wait_for_more)
			bufferevent_disable(bev, EV_READ);
	}
}

static err_t
socks_tcp_sent(void *ctx, struct tcp_pcb *pcb, u16_t len)
{
	struct socks_data *data = ctx;

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: Stack has sent %d bytes\n", __func__, len));
	if (!data || !data->bev) {
		if (!data->pcb || tcp_sndbuf(data->pcb) == TCP_SND_BUF)
			socks_free(data);
	} else if (len != 0) {
		bufferevent_enable(data->bev, EV_READ);
		socks_readable(data->bev, ctx);
	}

	return 0;
}

static err_t
socks_tcp_connected(void *ctx, struct tcp_pcb *pcb, err_t err)
{
	struct socks_data *data = ctx;

	if (!pcb || err < 0 || !data || !data->bev) {
		if (data) {
			LWIP_DEBUGF(SOCKS_DEBUG, ("%s: err\n", __func__));
			socks_flush_socks(data);
		}
		return err;
	}

	if (pcb != data->pcb) {
		tcp_close(data->pcb);
		data->pcb = pcb;
	}

	data->connected = 1;

	if (data->version == 4)
		socks4_connected(data);
	else
		socks5_connected(data);

	bufferevent_setwatermark(data->bev, EV_READ, 1, 2048);
	bufferevent_setwatermark(data->bev, EV_WRITE, 4096, 16384);
	bufferevent_setcb(data->bev, socks_readable, socks_writable,
							socks_error, data);
	bufferevent_enable(data->bev, EV_READ);
	bufferevent_set_timeouts(data->bev, NULL, NULL);
	socks_readable(data->bev, ctx);

	return 0;
}

int
socks_tcp_connect(struct socks_data *data)
{
	bufferevent_disable(data->bev, EV_READ);

	data->pcb = tcp_new();
	if (!data->pcb) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: tcp_new failed\n", __func__));
		return -1;
	}
	tcp_arg(data->pcb, data);
	tcp_err(data->pcb, socks_tcp_err);
	tcp_recv(data->pcb, socks_tcp_recv);
	tcp_sent(data->pcb, socks_tcp_sent);
	data->pcb->flags |= TF_NODELAY;

	return tcp_connect(data->pcb, &data->ipaddr, data->port,
							socks_tcp_connected);
}

int
socks_tcp_bind(struct socks_data *data)
{
	err_t ret;

	bufferevent_disable(data->bev, EV_READ);

	data->pcb = tcp_new();
	if (!data->pcb)
		return -1;

	tcp_arg(data->pcb, data);
	tcp_err(data->pcb, socks_tcp_err);
	tcp_recv(data->pcb, socks_tcp_recv);
	tcp_sent(data->pcb, socks_tcp_sent);
	data->pcb->flags |= TF_NODELAY;

	ret = tcp_bind(data->pcb, IP_ADDR_ANY, data->port);
	if (ret < 0)
		return ret;

	data->pcb = tcp_listen(data->pcb);
	tcp_accept(data->pcb, socks_tcp_connected);

	return 0;
}

void
socks_error(struct bufferevent *bev, short events, void *ctx)
{
	if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF))
		socks_flush_tcp(ctx);
}

static void
socks_version(struct bufferevent *bev, void *ctx)
{
	u_char version;

	bufferevent_read(bev, &version, 1);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: socks version %d\n", __func__, version));

	switch (version) {
	case 4:
		socks4_start(bev);
		break;
	case 5:
		socks5_start(bev);
		break;
	default:
		bufferevent_free(bev);
	}
}

static void
socks_accept(struct evconnlistener *evl, evutil_socket_t new_fd,
			struct sockaddr *addr, int socklen, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(evl);
	struct bufferevent *bev;
	struct timeval timeout = {5, 0};

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: Accepting socks connection\n", __func__));

	bev = bufferevent_socket_new(base, new_fd, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_set_timeouts(bev, &timeout, NULL);
	bufferevent_setcb(bev, socks_version, NULL, socks_error, NULL);
	bufferevent_setwatermark(bev, EV_READ, 1, 2048);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
}

#ifndef LEV_OPT_DEFERRED_ACCEPT
#define LEV_OPT_DEFERRED_ACCEPT 0
#endif

int
socks_listen(struct event_base *base, u_int16_t port)
{
	struct sockaddr_in addr;
	struct evconnlistener *evl;

	addr.sin_family = AF_INET;
	addr.sin_port = port;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	evl = evconnlistener_new_bind(base, socks_accept, NULL,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC |
		LEV_OPT_REUSEABLE | LEV_OPT_DEFERRED_ACCEPT, 10,
		(struct sockaddr *) &addr, sizeof(addr));
	if (!evl) {
		perror(__func__);
		return -1;
	}

	return 0;
}
