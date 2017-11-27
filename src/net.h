#ifndef __NET_H
#define __NET_H

#include <stdint.h>

enum net_events {
	NET_POLLIN = 0,
	NET_POLLOUT = 1,
};

struct net_opts {
	int32_t read_timeout;
	int32_t connect_timeout;
	int32_t accept_timeout;
	int32_t read_buf;
	int32_t write_buf;
	int32_t keepalive;
	int32_t tcp_nodelay;
	int32_t reuseaddr;
};

struct net_context;

int32_t net_error();
int32_t net_would_block();
int32_t net_in_progress();
int32_t net_bad_fd();

void net_close(struct net_context *nc);
void net_default_opts(struct net_opts *opts);
int32_t net_poll(struct net_context *nc, int32_t net_event, int32_t timeout_ms);
int32_t net_getip4(char *host, char *ip4, uint32_t ip4_len);
int32_t net_connect(struct net_context **nc_in, char *ip4, uint16_t port, struct net_opts *opts);
int32_t net_listen(struct net_context **nc_in, char *bind_ip4, uint16_t port, struct net_opts *opts);
int32_t net_accept(struct net_context *nc, struct net_context **nc_in);
void net_get_socket(struct net_context *nc, void *socket);
void net_get_opts(struct net_context *nc, struct net_opts *opts);

int32_t net_write(void *ctx, char *buf, uint32_t buf_size);
int32_t net_read(void *nc, char *buf, uint32_t buf_size);

#endif
