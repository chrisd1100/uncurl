#ifndef __TLS_H
#define __TLS_H

#include <stdint.h>

struct tls_opts {
	int8_t dummy;
};

struct net_context;
struct tls_context;
struct tls_state;

#ifdef __cplusplus
extern "C" {
#endif

int32_t tlss_alloc(struct tls_state **tlss_in);
void tlss_free(struct tls_state *tlss);

void tls_default_opts(struct tls_opts *opts);
void tls_close(struct tls_context *tls);
int32_t tls_connect(struct tls_context **tls_in, struct tls_state *tlss,
	struct net_context *nc, struct tls_opts *opts);

int32_t tls_write(void *ctx, char *buf, uint32_t buf_size);
int32_t tls_read(void *ctx, char *buf, uint32_t buf_size);

#ifdef __cplusplus
}
#endif

#endif
