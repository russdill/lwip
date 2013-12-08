#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>

#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/stats.h>
#include <lwip/ip4.h>
#include <lwip/init.h>
#include <lwip/tcp_impl.h>
#include <lwip/dns.h>
#include <netif/tunif.h>

#include <pcap/pcap.h>
#include <event2/event.h>

struct tunif_data {
	struct netif netif;
	int fd;
	int header;
	struct event *ev;
	u_char buf[4096];
};

static pcap_dumper_t *pcap_dumper;

static err_t
tunif_output(struct netif *netif, struct pbuf *p, ip_addr_t *ipaddr)
{
	struct tunif_data *data = netif->state;
	int len;

	len = pbuf_copy_partial(p, data->buf, sizeof(data->buf), 0);
	if (pcap_dumper) {
		struct pcap_pkthdr hdr = {.caplen = len, .len = len};
		gettimeofday(&hdr.ts, NULL);
		pcap_dump((void *) pcap_dumper, &hdr, data->buf);
	}
	len = write(data->fd, data->buf, len);
	if (len < 0)
		LINK_STATS_INC(link.drop);
	else
		LINK_STATS_INC(link.xmit);

	return 0;
}

static void
tunif_ready(evutil_socket_t fd, short events, void *ctx)
{
	struct tunif_data *data = ctx;
	int ret;

	ret = read(fd, data->buf, sizeof(data->buf));
	if ((ret < 0 && errno != EAGAIN) || !ret) {
		/* FATAL */
		event_del(data->ev);
	} else if (ret > 0) {
		struct pbuf *p;
		p = pbuf_alloc(PBUF_IP, ret, PBUF_POOL);
		if (!p) {
			LINK_STATS_INC(link.memerr);
			LINK_STATS_INC(link.drop);
			return;
		}
		LINK_STATS_INC(link.recv);
		if (pcap_dumper) {
			struct pcap_pkthdr hdr = {.caplen = ret, .len = ret};
			gettimeofday(&hdr.ts, NULL);
			pcap_dump((void *) pcap_dumper, &hdr, data->buf);
		}
		pbuf_take(p, data->buf, ret);
		if (data->netif.input(p, &data->netif) < 0)
			pbuf_free(p);
	}
}

static err_t
tunif_init(struct netif *netif)
{
	NETIF_INIT_SNMP(netif, snmp_ifType_other, 0);
	netif->name[0] = 't';
	netif->name[1] = 'p';

	netif->output = tunif_output;
	netif->mtu = 1360;
	netif->flags = NETIF_FLAG_LINK_UP;

	return 0;
}

struct tunif_data *
tunif_add(struct event_base *base, int fd, int header)
{
	struct tunif_data *data;
	const char *pcap = getenv("TUNIF_PCAP_FILE");

	if (pcap && !pcap_dumper) {
		pcap_t *p;
		p = pcap_open_dead(DLT_RAW, 2000);
		pcap_dumper = pcap_dump_open(p, pcap);
	}


	data = calloc(1, sizeof(*data));
	data->fd = fd;
	data->header = header;
	data->ev = event_new(base, fd, EV_READ | EV_PERSIST, tunif_ready, data);
	event_add(data->ev, NULL);
	netif_add(&data->netif, NULL, NULL, NULL, data, tunif_init, ip_input);
	netif_set_default(&data->netif);
	return data;
}

void
tunif_del(struct tunif_data *data)
{
	netif_remove(&data->netif);
	event_del(data->ev);
	event_free(data->ev);
	free(data);
}

void
tunif_set_ipaddr(struct tunif_data *data, u_int32_t addr)
{
	ip_addr_t ipaddr;
	ipaddr.addr = addr;
	netif_set_ipaddr(&data->netif, &ipaddr);
}

void
tunif_set_netmask(struct tunif_data *data, u_int32_t addr)
{
	ip_addr_t ipaddr;
	ipaddr.addr = addr;
	netif_set_netmask(&data->netif, &ipaddr);
}

void
tunif_set_gw(struct tunif_data *data, u_int32_t addr)
{
	ip_addr_t ipaddr;
	ipaddr.addr = addr;
	netif_set_gw(&data->netif, &ipaddr);
}

void
tunif_set_up(struct tunif_data *data)
{
	netif_set_up(&data->netif);
}

void
tunif_set_down(struct tunif_data *data)
{
	netif_set_down(&data->netif);
}

void
tunif_set_mtu(struct tunif_data *data, int mtu)
{
	data->netif.mtu = mtu;
}

void
tunif_set_flag(struct tunif_data *data, int flag)
{
	data->netif.flags |= flag;
}

void
tunif_clear_flag(struct tunif_data *data, int flag)
{
	data->netif.flags &= ~flag;
}

static int dns_count;

void
tunif_clear_dns(void)
{
	ip_addr_t addr;
	addr.addr = INADDR_ANY;
	int i;
	for (i = 0; i < DNS_MAX_SERVERS; i++)
		dns_setserver(i, &addr);
	dns_count = 0;
}

void
tunif_add_dns(u_int32_t addr)
{
	ip_addr_t ipaddr;
	ipaddr.addr = addr;
	dns_setserver(dns_count++, &ipaddr);
}
