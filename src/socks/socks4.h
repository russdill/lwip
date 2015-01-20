#ifndef __SOCKS4_H__
#define __SOCKS4_H__

struct bufferevent;

void socks4_start(struct bufferevent *bev);
void socks4_connected(struct socks_data *sdata);
void socks4_found_host(struct socks_data *sdata);
void socks4_host_failed(struct socks_data *sdata);


#endif
