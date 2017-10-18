#ifndef __TLS_H
#define __TLS_H

#include <stdint.h>
#include <stddef.h>

struct tls_opts {
	int32_t verify_host;
};

struct net_context;
struct tls_context;
struct tls_state;

int32_t tlss_alloc(struct tls_state **tlss_in);
void tlss_free(struct tls_state *tlss);
int32_t tlss_load_cacert(struct tls_state *tlss, char *cacert, size_t size);
int32_t tlss_load_cacert_file(struct tls_state *tlss, char *cacert_file);

void tls_default_opts(struct tls_opts *opts);
void tls_close(struct tls_context *tls);
int32_t tls_connect(struct tls_context **tls_in, struct tls_state *tlss,
	struct net_context *nc, char *host, struct tls_opts *opts);

int32_t tls_write(void *ctx, char *buf, uint32_t buf_size);
int32_t tls_read(void *ctx, char *buf, uint32_t buf_size);

void tls_sha1(uint8_t *dest, char *src);

#endif
