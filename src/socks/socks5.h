#ifndef __SOCKS5_H__
#define __SOCKS5_H__

struct bufferevent;

void socks5_connected(struct socks_data *sdata);
void socks5_start(struct bufferevent *bev);

#endif
