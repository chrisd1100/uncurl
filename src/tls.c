#include "tls.h"

#include <stdlib.h>
#include <string.h>

#if defined(__WINDOWS__)
	#pragma warning(disable: 4090)
#endif

#include "openssl/ssl.h"

#if defined(__WINDOWS__)
	#pragma warning(default: 4090)
#endif

#include "uncurl/status.h"
#include "net.h"

#include "../cacert/cacert.h"

#define TLS_DEF_VERIFY_DEPTH 4


/*** STATE ***/

struct tls_state {
	SSL_CTX *ctx;
};

static int32_t tlss_load_root_certs(struct tls_state *tlss)
{
	int32_t r = UNCURL_OK;

	X509_STORE *store = SSL_CTX_get_cert_store(tlss->ctx);
	if (!store) return UNCURL_TLS_ERR_CACERT;

	for (int32_t x = 0; x < CACERT_LEN && r == UNCURL_OK; x++) {
		BIO *bio = BIO_new_mem_buf(CACERT[x], -1);
		if (!bio) break;

		X509 *cert = NULL;
		if (PEM_read_bio_X509(bio, &cert, 0, NULL)) {
			X509_STORE_add_cert(store, cert);
			X509_free(cert);
		} else {
			r = UNCURL_TLS_ERR_CACERT;
		}

		BIO_free(bio);
	}

	return r;
}

void tlss_free(struct tls_state *tlss)
{
	if (!tlss) return;

	if (tlss->ctx)
		SSL_CTX_free(tlss->ctx);

	free(tlss);
}

int32_t tlss_alloc(struct tls_state **tlss_in)
{
	int32_t e;
	struct tls_state *tlss = *tlss_in = calloc(1, sizeof(struct tls_state));

	//the SSL context can be reused for multiple connections
	tlss->ctx = SSL_CTX_new(TLS_client_method());
	if (!tlss->ctx) return UNCURL_TLS_ERR_CONTEXT;

	SSL_CTX_set_verify(tlss->ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(tlss->ctx, TLS_DEF_VERIFY_DEPTH);

	//the context stores the trusted root certs
	e = tlss_load_root_certs(tlss);
	if (e == UNCURL_OK) return e;

	tlss_free(tlss);
	*tlss_in = NULL;

	return e;
}


/*** CONTEXT ***/

struct tls_context {
	struct net_context *nc;
	struct tls_opts opts;
	SSL *ssl;
};

void tls_close(struct tls_context *tls)
{
	if (!tls) return;

	if (tls->ssl) {
		int32_t e;

		//SSL_shutdown may need to be called twice
		e = SSL_shutdown(tls->ssl);
		if (e == 0)
			SSL_shutdown(tls->ssl);

		SSL_free(tls->ssl);
	}

	free(tls);
}

void tls_default_opts(struct tls_opts *opts)
{
	opts;
}

int32_t tls_connect(struct tls_context **tls_in, struct tls_state *tlss,
	struct net_context *nc, struct tls_opts *opts)
{
	int32_t e;
	int32_t r = UNCURL_ERR_DEFAULT;

	struct tls_context *tls = *tls_in = calloc(1, sizeof(struct tls_context));

	//set options
	memcpy(&tls->opts, opts, sizeof(struct tls_opts));

	//keep handle to the underlying net_context
	tls->nc = nc;

	tls->ssl = SSL_new(tlss->ctx);
	if (!tls->ssl) {r = UNCURL_TLS_ERR_SSL; goto tls_connect_failure;}

	e = SSL_set_fd(tls->ssl, net_get_fd(tls->nc));
	if (e != 1) {r = UNCURL_TLS_ERR_FD; goto tls_connect_failure;}

	tls_connect_retry:

	//attempt SSL connection on nonblocking socket -- 1 is success
	e = SSL_connect(tls->ssl);
	if (e == 1) return UNCURL_OK;

	//retrieve net options
	struct net_opts nopts;
	net_get_opts(tls->nc, &nopts);

	//if not successful, check for bad file descriptor
	int32_t ne = net_error();
	if (ne == net_bad_fd()) {r = UNCURL_TLS_ERR_FD; goto tls_connect_failure;}

	//if not successful, see if we neeed to poll for more data
	int32_t ssl_e = SSL_get_error(tls->ssl, e);
	if (ne == net_would_block() || ssl_e == SSL_ERROR_WANT_READ) {
		e = net_poll(tls->nc, NET_POLLIN, nopts.connect_timeout_ms);
		if (e == UNCURL_OK) goto tls_connect_retry;
		r = e;
	}

	r = UNCURL_TLS_ERR_CONNECT;

	//cleanup on failure
	tls_connect_failure:

	tls_close(tls);
	*tls_in = NULL;

	return r;
}

int32_t tls_write(void *ctx, char *buf, uint32_t buf_size)
{
	struct tls_context *tls = (struct tls_context *) ctx;

	int32_t n;

	n = SSL_write(tls->ssl, buf, buf_size);
	if (n != (int32_t) buf_size) return UNCURL_TLS_ERR_WRITE;

	return UNCURL_OK;
}

int32_t tls_read(void *ctx, char *buf, uint32_t buf_size)
{
	struct tls_context *tls = (struct tls_context *) ctx;

	int32_t e;
	int32_t n;
	uint32_t total = 0;

	//retrieve net options
	struct net_opts nopts;
	net_get_opts(tls->nc, &nopts);

	while (total < buf_size) {
		if (SSL_has_pending(tls->ssl) == 0) {
			e = net_poll(tls->nc, NET_POLLIN, nopts.read_timeout_ms);
			if (e != UNCURL_OK) return e;
		}

		n = SSL_read(tls->ssl, buf + total, buf_size - total);
		if (n <= 0) {
			int32_t ssl_e = SSL_get_error(tls->ssl, n);
			if (ssl_e == SSL_ERROR_WANT_READ) continue;
			if (ssl_e == SSL_ERROR_ZERO_RETURN) return UNCURL_TLS_ERR_CLOSED;
			return UNCURL_TLS_ERR_READ;
		}

		total += n;
	}

	return UNCURL_OK;
}
