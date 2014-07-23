CC=gcc

CFLAGS=-Isrc/include -Isrc/include/ipv4 -Isrc/include/ipv6
CFLAGS+=-Wall -O2 -g -fPIC -fno-stack-protector -m32

AR=ar
ARFLAGS=rv

C_SOURCES = \
src/api/err.c \
src/core/init.c \
src/core/def.c \
src/core/mem.c \
src/core/memp.c \
src/core/netif.c \
src/core/pbuf.c \
src/core/stats.c \
src/core/libevent.c \
src/core/dns.c \
src/core/udp.c \
src/core/raw.c \
src/core/sys.c \
src/core/tcp.c \
src/core/tcp_in.c \
src/core/tcp_out.c \
src/core/inet_chksum.c \
src/core/ipv4/ip4.c \
src/core/ipv4/icmp.c \
src/core/ipv4/ip4_addr.c \
src/core/ipv4/ip_frag.c \
src/socks/socks4.c \
src/socks/socks5.c \
src/socks/socks.c \
src/netif/tunif.c \

OBJS=$(C_SOURCES:.c=.o)

all: libtunsock.a

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

libtunsock.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

clean:
	-rm -f $(OBJS) libtunsock.a
