#include <stdlib.h>
#include <lwip/tcp.h>
#include <lwip/dns.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "socks.h"

#define SOCKS4_CMD_CONNECT	1
#define SOCKS4_CMD_BIND		2
#define SOCKS4_CMD_RESOLVE	240

#define SOCKS4_RESP_GRANT       90
#define SOCKS4_RESP_REJECT      91

struct socks4_hdr {
	u_char    version;
	u_char    cmd;
	u_int16_t port;
	u_int32_t addr;
} __attribute__((__packed__));

struct socks4_data {
	struct socks_data socks;
	u_char pos;
	char fqdn[256];
	u_char cmd;
};

static void
socks4_response(struct socks_data *sdata, int code, int die)
{
	struct socks4_hdr hdr = {.version = 0, .cmd = code};
	struct bufferevent *bev = sdata->bev;
	struct socks4_data *data = container_of(sdata, struct socks4_data, socks);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: %d%s\n", __func__, code,
							die ? " die" : ""));
	if (!die) {
		if (sdata->connected && data->cmd == SOCKS4_CMD_BIND) {
			hdr.port = htons(sdata->pcb->remote_port);
			hdr.addr = sdata->pcb->remote_ip.addr;
		} else {
			hdr.port = htons(sdata->pcb->local_port);
			hdr.addr = sdata->pcb->local_ip.addr;
		}
	} else {
		hdr.port = 0;
		hdr.addr = sdata->ipaddr.addr;
	}

	bufferevent_write(bev, &hdr, sizeof(hdr));

	if (die)
		socks_flush_socks(sdata);
}

void
socks4_connected(struct socks_data *sdata)
{
	struct socks4_data *data = container_of(sdata, struct socks4_data, socks);
	data->connected = 1;
	socks4_response(sdata, SOCKS4_RESP_GRANT, 0);
}

static void
socks4_connect(struct socks_data *sdata)
{
	struct socks4_data *data = container_of(sdata, struct socks4_data, socks);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s\n", __func__));
	if (data->cmd == SOCKS4_CMD_RESOLVE) {
		socks4_response(sdata, SOCKS4_RESP_GRANT, 1);

	} else if (data->cmd == SOCKS4_CMD_CONNECT) {
		err_t ret;
		ret = socks_tcp_connect(sdata);
		if (ret < 0) {
			LWIP_DEBUGF(SOCKS_DEBUG, ("%s: failed, %d\n", __func__,
								ret));
			socks4_response(sdata, SOCKS4_RESP_REJECT, 1);
		}
	} else {
		if (socks_tcp_bind(sdata) < 0)
			socks4_response(sdata, SOCKS4_RESP_REJECT, 1);
		else
			socks4_response(sdata, SOCKS4_RESP_GRANT, 0);
	}
}

static void
socks4_found_host(const char *name, ip_addr_t *ipaddr, void *ctx)
{
	struct socks_data *sdata = ctx;

	if (!ipaddr || !ipaddr->addr)
		socks4_response(sdata, SOCKS4_RESP_REJECT, 1);
	else {
		sdata->ipaddr.addr = ipaddr->addr;
		socks4_connect(sdata);
	}
}

static void
socks4_read_fqdn(struct bufferevent *bev, void *ctx)
{
	struct socks_data *sdata = ctx;
	struct socks4_data *data = container_of(sdata, struct socks4_data, socks);

	while (evbuffer_get_length(bufferevent_get_input(bev))) {
		bufferevent_read(bev, data->fqdn + data->pos, 1);
		if (!data->fqdn[data->pos]) {
			int ret;
			ret = dns_gethostbyname(data->fqdn, &sdata->ipaddr,
							socks4_found_host, ctx);
			bufferevent_disable(bev, EV_READ);
			if (ret == 0)
				socks4_connect(sdata);
			return;
		}
		data->pos++;
		if (data->pos == 255) {
			socks4_response(sdata, SOCKS4_RESP_REJECT, 1);
			return;
		}
	}

	bufferevent_setwatermark(bev, EV_READ, 1, 2048);
	bufferevent_setcb(bev, socks4_read_fqdn, NULL, socks_error, ctx);
}

static void
socks4_read_user(struct bufferevent *bev, void *ctx)
{
	struct socks_data *sdata = ctx;
	u_char ch;

	if (!evbuffer_get_length(bufferevent_get_input(bev))) {
		bufferevent_setwatermark(bev, EV_READ, 1, 2048);
		bufferevent_setcb(bev, socks4_read_user, NULL, socks_error, ctx);
		return;
	}

	while (bufferevent_read(bev, &ch, 1) > 0 && ch);

	if (!ch) {
		unsigned long ip = ntohl(sdata->ipaddr.addr);
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s\n", __func__));
		if (ip < 0x100 && ip)
			socks4_read_fqdn(bev, ctx);
		else
			socks4_connect(sdata);
	} else {
		bufferevent_setwatermark(bev, EV_READ, 1, 2048);
		bufferevent_setcb(bev, socks4_read_user, NULL, socks_error, ctx);
	}
}

static void
socks4_read_hdr(struct bufferevent *bev, void *ctx)
{
	struct socks_data *sdata = ctx;
	struct socks4_data *data = container_of(sdata, struct socks4_data, socks);
	struct socks4_hdr hdr = {.version = 4};

	if (evbuffer_get_length(bufferevent_get_input(bev)) < sizeof(hdr) - 1) {
		bufferevent_setwatermark(bev, EV_READ, sizeof(hdr) - 1, 2048);
		bufferevent_setcb(bev, socks4_read_hdr, NULL, socks_error, ctx);
		return;
	}

	bufferevent_read(bev, ((char *) &hdr) + 1, sizeof(hdr) - 1);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: cmd %d\n", __func__, hdr.cmd));

	if (hdr.cmd != SOCKS4_CMD_CONNECT && hdr.cmd != SOCKS4_CMD_BIND &&
	    !(hdr.cmd == SOCKS4_CMD_RESOLVE && !hdr.port)) {
		socks4_response(sdata, SOCKS4_RESP_REJECT, 1);
		return;
	}

	data->cmd = hdr.cmd;
	sdata->ipaddr.addr = hdr.addr;
	sdata->port = ntohs(hdr.port);

	socks4_read_user(bev, ctx);
}

void
socks4_start(struct bufferevent *bev)
{
	struct socks4_data *data;
	struct socks_data *sdata;
	data = calloc(1, sizeof(struct socks4_data));
	sdata = &data->socks;
	sdata->bev = bev;
	sdata->version = 4;
	socks4_read_hdr(bev, sdata);
}
