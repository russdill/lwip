#include <stdlib.h>
#include <lwip/tcp.h>
#include <lwip/dns.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "socks.h"

#define SOCKS5_ATYP_IPV4	0x01
#define SOCKS5_ATYP_FQDN	0x03

#define SOCKS5_CMD_CONNECT	0x01
#define SOCKS5_CMD_BIND		0x02

#define SOCKS5_RESP_GRANTED		0x00
#define SOCKS5_RESP_FAILURE		0x01
#define SOCKS5_RESP_PERM		0x02
#define SOCKS5_RESP_NET_UNREACH		0x03
#define SOCKS5_RESP_HOST_UNREACH	0x04
#define SOCKS5_RESP_REFUSED		0x05
#define SOCKS5_RESP_TTL			0x06
#define SOCKS5_RESP_CMD_UNSUP		0x07
#define SOCKS5_RESP_ADDR_UNSUP		0x08

struct socks5_req {
	u_char	version;
	u_char	cmd;
	u_char	reserved;
	u_char	atyp;
} __attribute__((__packed__));

struct socks5_rep {
	u_char version;
	u_char auth;
} __attribute__((__packed__));

struct socks5_data {
	struct socks_data socks;
	u_char nauth;
	u_char atyp;
	u_char nfqdn;
	u_char cmd;
};

static void
socks5_response(struct socks_data *sdata, int code, int die)
{
	struct socks5_data *data = container_of(sdata, struct socks5_data, socks);
	struct socks5_req req = {.version = 5, .cmd = code, .atyp = SOCKS5_ATYP_IPV4};
	struct bufferevent *bev = sdata->bev;
	u_short port;

        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: code %d, die %d\n", __func__, code, die));
	bufferevent_write(bev, &req, sizeof(req));
	if (sdata->pcb) {
		if (sdata->connected && data->cmd == SOCKS5_CMD_BIND) {
			bufferevent_write(bev, &sdata->pcb->remote_ip.addr, 4);
			port = htons(sdata->pcb->remote_port);
		} else {
			bufferevent_write(bev, &sdata->pcb->local_ip.addr, 4);
			port = htons(sdata->pcb->local_port);
		}
	}
	bufferevent_write(bev, &port, 2);
	if (die)
		socks_flush_socks(sdata);
}

void
socks5_connected(struct socks_data *sdata)
{
	if (sdata->connected)
		socks5_response(sdata, SOCKS5_RESP_GRANTED, 0);
	else
		socks5_response(sdata, SOCKS5_RESP_HOST_UNREACH, 1);
}

static void
socks5_read_port(struct bufferevent *bev, void *ctx)
{
	struct socks_data *sdata = ctx;
	struct socks5_data *data = container_of(sdata, struct socks5_data, socks);

	if (evbuffer_get_length(bufferevent_get_input(bev)) < 2) {
		bufferevent_setwatermark(bev, EV_READ, 2, 2048);
		bufferevent_setcb(bev, socks5_read_port, NULL, socks_error,
									ctx);
		return;
	}

	bufferevent_read(bev, &sdata->port, 2);
	sdata->port = ntohs(sdata->port);

        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: port %d\n", __func__, sdata->port));

	switch (data->cmd) {
	case SOCKS5_CMD_CONNECT:
		if (socks_tcp_connect(sdata) < 0)
			socks5_response(sdata, SOCKS5_RESP_FAILURE, 1);
		break;
	case SOCKS5_CMD_BIND:
		if (socks_tcp_bind(sdata) < 0)
			socks5_response(sdata, SOCKS5_RESP_FAILURE, 1);
		else
			socks5_response(sdata, SOCKS5_RESP_GRANTED, 0);
		break;
	default:
		socks5_response(sdata, SOCKS5_RESP_CMD_UNSUP, 1);
	}
}

static void
socks5_read_ipv4(struct bufferevent *bev, void *ctx)
{
	struct socks_data *sdata = ctx;

	if (evbuffer_get_length(bufferevent_get_input(bev)) < 4) {
		bufferevent_setwatermark(bev, EV_READ, 4, 2048);
		bufferevent_setcb(bev, socks5_read_ipv4, NULL,
						socks_error, ctx);
		return;
	}

	bufferevent_read(bev, &sdata->ipaddr.addr, 4);
	socks5_read_port(bev, ctx);
}

void
socks5_found_host(struct socks_data *sdata)
{
	struct bufferevent *bev = sdata->bev;

	bufferevent_enable(bev, EV_READ);
	socks5_read_port(bev, sdata);
}

void
socks5_host_failed(struct socks_data *sdata)
{
	socks5_response(sdata, SOCKS5_RESP_FAILURE, 1);
}

static void
socks5_read_fqdn(struct bufferevent *bev, void *ctx)
{
	struct socks_data *sdata = ctx;
	struct socks5_data *data = container_of(sdata, struct socks5_data, socks);
	err_t ret;

	if (evbuffer_get_length(bufferevent_get_input(bev)) < data->nfqdn) {
		bufferevent_setwatermark(bev, EV_READ, data->nfqdn, 2048);
		bufferevent_setcb(bev, socks5_read_fqdn, NULL, socks_error,
									ctx);
		return;
	}

	bufferevent_read(bev, sdata->fqdn, data->nfqdn);
	sdata->fqdn[data->nfqdn] = '\0';
        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: fqdn %s\n", __func__, sdata->fqdn));
	ret = socks_lookup_host(sdata);
	if (!ret)
		socks5_read_port(bev, ctx);
	else
		bufferevent_disable(bev, EV_READ);
}

static void
socks5_read_n_fqdn(struct bufferevent *bev, void *ctx)
{
	struct socks_data *sdata = ctx;
	struct socks5_data *data = container_of(sdata, struct socks5_data, socks);

	if (!evbuffer_get_length(bufferevent_get_input(bev))) {
		bufferevent_setwatermark(bev, EV_READ, 1, 2048);
		bufferevent_setcb(bev, socks5_read_n_fqdn, NULL, socks_error,
									ctx);
		return;
	}

	bufferevent_read(bev, &data->nfqdn, 1);
        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: nfqdn %d\n", __func__, data->nfqdn));
	if (!data->nfqdn)
		socks5_response(sdata, SOCKS5_RESP_CMD_UNSUP, 1);
	else
		socks5_read_fqdn(bev, ctx);
}

static void
socks5_read_hdr(struct bufferevent *bev, void *ctx)
{
	struct socks_data *sdata = ctx;
	struct socks5_data *data = container_of(sdata, struct socks5_data, socks);
	struct socks5_req req;

	if (evbuffer_get_length(bufferevent_get_input(bev)) < sizeof(req)) {
		bufferevent_setwatermark(bev, EV_READ, sizeof(req), 2048);
		bufferevent_setcb(bev, socks5_read_hdr, NULL, socks_error, ctx);
		return;
	}
	bufferevent_read(bev, &req, sizeof(req));
	if (req.version != 5) {
		socks_free(sdata);
		return;
	}

	data->cmd = req.cmd;
	data->atyp = req.atyp;

        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: cmd %d, atyp %d\n", __func__, data->cmd, data->atyp));

	if (req.atyp == SOCKS5_ATYP_IPV4)
		socks5_read_ipv4(bev, ctx);
	else if (req.atyp == SOCKS5_ATYP_FQDN)
		socks5_read_n_fqdn(bev, ctx);
	else
		socks5_response(sdata, SOCKS5_RESP_ADDR_UNSUP, 1);
}

static void
socks5_read_auth(struct bufferevent *bev, void *ctx)
{
	struct socks_data *sdata = ctx;
	struct socks5_data *data = container_of(sdata, struct socks5_data, socks);
	u_char auth[255];
	struct socks5_rep rep = {5, 0};

	if (evbuffer_get_length(bufferevent_get_input(bev)) < data->nauth) {
		bufferevent_setwatermark(bev, EV_READ, data->nauth, 2048);
		bufferevent_setcb(bev, socks5_read_auth, NULL, socks_error,
									ctx);
		return;
	}

	if (data->nauth)
		bufferevent_read(bev, auth, data->nauth);

	bufferevent_write(bev, &rep, sizeof(rep));

	socks5_read_hdr(bev, ctx);
}

static void
socks5_read_n_auth(struct bufferevent *bev, void *ctx)
{
	struct socks_data *sdata = ctx;
	struct socks5_data *data = container_of(sdata, struct socks5_data, socks);

	if (!evbuffer_get_length(bufferevent_get_input(bev))) {
		bufferevent_setwatermark(bev, EV_READ, 1, 2048);
		bufferevent_setcb(bev, socks5_read_n_auth, NULL, socks_error,
									ctx);
		return;
	}

	bufferevent_read(bev, &data->nauth, 1);
        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: nauth %d\n", __func__, data->nauth));
	socks5_read_auth(bev, ctx);
}

void
socks5_start(struct bufferevent *bev)
{
	struct socks5_data *data;
	struct socks_data *sdata;

	data = calloc(1, sizeof(struct socks5_data));
	sdata = &data->socks;
	sdata->bev = bev;
	sdata->version = 5;
	bufferevent_setcb(bev, socks5_read_n_auth, NULL, socks_error, sdata);
	socks5_read_n_auth(bev, sdata);
}
