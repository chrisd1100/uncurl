#ifndef __NET_H
#define __NET_H

#include <stdint.h>
#include <stddef.h>

enum net_events {
	NET_POLLIN  = 0,
	NET_POLLOUT = 1,
};

struct net_context;

int32_t net_error(void);
int32_t net_would_block(void);
int32_t net_in_progress(void);
int32_t net_bad_fd(void);

void net_close(struct net_context *nc);
int32_t net_poll(struct net_context *nc, int32_t net_event, int32_t timeout_ms);
int32_t net_getip4(char *host, char *ip4, uint32_t ip4_len);
int32_t net_connect(struct net_context **nc_out, char *ip4, uint16_t port, int32_t timeout_ms);
int32_t net_listen(struct net_context **nc_out, char *bind_ip4, uint16_t port);
int32_t net_accept(struct net_context *nc, struct net_context **child, int32_t timeout_ms);
void net_get_socket(struct net_context *nc, void *socket);

int32_t net_write(void *ctx, char *buf, size_t size);
int32_t net_read(void *ctx, char *buf, size_t size, int32_t timeout_ms);

#endif
