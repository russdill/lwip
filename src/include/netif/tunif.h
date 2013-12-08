#ifndef __TUNIF_H__
#define __TUNIF_H__

#include <sys/types.h>

#define NETIF_FLAG_BROADCAST    0x02U
#define NETIF_FLAG_POINTTOPOINT 0x04U

struct tunif_data;
struct event_base;

struct tunif_data *tunif_add(struct event_base *base, int fd, int header);
void tunif_del(struct tunif_data *data);

void tunif_set_ipaddr(struct tunif_data *data, u_int32_t addr);
void tunif_set_netmask(struct tunif_data *data, u_int32_t addr);
void tunif_set_gw(struct tunif_data *data, u_int32_t addr);
void tunif_set_up(struct tunif_data *data);
void tunif_set_down(struct tunif_data *data);
void tunif_set_mtu(struct tunif_data *data, int mtu);
void tunif_set_flag(struct tunif_data *data, int flag);
void tunif_clear_flag(struct tunif_data *data, int flag);
void tunif_clear_dns(void);
void tunif_add_dns(u_int32_t addr);

#endif
