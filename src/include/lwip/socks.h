#ifndef __SOCKS_H__
#define __SOCKS_H__

#include <sys/types.h>

struct event_base;

int socks_listen(struct event_base *base, u_int16_t port);
void socks_clear_search(void);
void socks_add_search(char *search);

#endif
