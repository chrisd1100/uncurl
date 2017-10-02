#include "tls.h"

#include <stdlib.h>
#include <string.h>

#include "openssl/ssl.h"
#include "openssl/x509v3.h"

#include "uncurl/status.h"
#include "net.h"

#define TLS_VERIFY_DEPTH 4

#define TLS_CIPHER_LIST \
	"ECDHE-ECDSA-AES128-GCM-SHA256:" \
	"ECDHE-ECDSA-AES256-GCM-SHA384:" \
	"ECDHE-ECDSA-AES128-SHA:" \
	"ECDHE-ECDSA-AES256-SHA:" \
	"ECDHE-ECDSA-AES128-SHA256:" \
	"ECDHE-ECDSA-AES256-SHA384:" \
	"ECDHE-RSA-AES128-GCM-SHA256:" \
	"ECDHE-RSA-AES256-GCM-SHA384:" \
	"ECDHE-RSA-AES128-SHA:" \
	"ECDHE-RSA-AES256-SHA:" \
	"ECDHE-RSA-AES128-SHA256:" \
	"ECDHE-RSA-AES256-SHA384:" \
	"DHE-RSA-AES128-GCM-SHA256:" \
	"DHE-RSA-AES256-GCM-SHA384:" \
	"DHE-RSA-AES128-SHA:" \
	"DHE-RSA-AES256-SHA:" \
	"DHE-RSA-AES128-SHA256:" \
	"DHE-RSA-AES256-SHA256"


/*** STATE ***/

struct tls_state {
	SSL_CTX *ctx;
};

int32_t tlss_load_cacert(struct tls_state *tlss, char **cacert, uint32_t num_certs)
{
	int32_t r = UNCURL_OK;

	X509_STORE *store = SSL_CTX_get_cert_store(tlss->ctx);
	if (!store) return UNCURL_TLS_ERR_CACERT;

	for (uint32_t x = 0; x < num_certs && r == UNCURL_OK; x++) {
		X509 *cert = NULL;
		BIO *bio = BIO_new_mem_buf(cacert[x], -1);

		if (bio && PEM_read_bio_X509(bio, &cert, 0, NULL)) {
			X509_STORE_add_cert(store, cert);
			X509_free(cert);
			BIO_free(bio);
		} else {
			r = UNCURL_TLS_ERR_CACERT;
		}
	}

	return r;
}

int32_t tlss_load_cacert_file(struct tls_state *tlss, char *cacert_file)
{
	int32_t e;

	e = SSL_CTX_load_verify_locations(tlss->ctx, cacert_file, NULL);
	if (e != 1) return UNCURL_TLS_ERR_CACERT;

	return UNCURL_OK;
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
	int32_t r = UNCURL_ERR_DEFAULT;
	int32_t e;

	struct tls_state *tlss = *tlss_in = calloc(1, sizeof(struct tls_state));

	//the SSL context can be reused for multiple connections
	tlss->ctx = SSL_CTX_new(TLS_client_method());
	if (!tlss->ctx) {r = UNCURL_TLS_ERR_CONTEXT; goto tlss_alloc_end;}

	//set peer certificate verification
	SSL_CTX_set_verify(tlss->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_verify_depth(tlss->ctx, TLS_VERIFY_DEPTH);

	//limit ciphers to predefined secure list
	e = SSL_CTX_set_cipher_list(tlss->ctx, TLS_CIPHER_LIST);
	if (e != 1) {r = UNCURL_TLS_ERR_CIPHER; goto tlss_alloc_end;}

	//disable any non TLS protocols
	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(tlss->ctx, flags);

	return UNCURL_OK;

	tlss_alloc_end:

	tlss_free(tlss);
	*tlss_in = NULL;

	return r;
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
	opts->verify_host = 1;
}

int32_t tls_connect(struct tls_context **tls_in, struct tls_state *tlss,
	struct net_context *nc, char *host, struct tls_opts *opts)
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

	//set hostname validation
	if (opts->verify_host) {
		X509_VERIFY_PARAM *param = SSL_get0_param(tls->ssl);
		X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		X509_VERIFY_PARAM_set1_host(param, host, 0);
	}

	//set hostname extension -- sometimes required
	SSL_set_tlsext_host_name(tls->ssl, host);

	e = SSL_set_fd(tls->ssl, net_get_fd(tls->nc));
	if (e != 1) {r = UNCURL_TLS_ERR_FD; goto tls_connect_failure;}

	while (1) {
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
			e = net_poll(tls->nc, NET_POLLIN, nopts.connect_timeout);
			if (e != UNCURL_OK) {r = e; break;}

		} else {r = UNCURL_TLS_ERR_CONNECT; break;}
	}

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
	uint32_t total = 0;

	while (total < buf_size) {
		n = SSL_write(tls->ssl, buf + total, buf_size - total);
		if (n <= 0) {
			int32_t ssl_e = SSL_get_error(tls->ssl, n);
			if (ssl_e == SSL_ERROR_WANT_READ || ssl_e == SSL_ERROR_WANT_WRITE) continue;
			if (ssl_e == SSL_ERROR_ZERO_RETURN) return UNCURL_TLS_ERR_CLOSED;
			return UNCURL_TLS_ERR_WRITE;
		}

		total += n;
	}

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
			e = net_poll(tls->nc, NET_POLLIN, nopts.read_timeout);
			if (e != UNCURL_OK) return e;
		}

		n = SSL_read(tls->ssl, buf + total, buf_size - total);
		if (n <= 0) {
			int32_t ssl_e = SSL_get_error(tls->ssl, n);
			if (ssl_e == SSL_ERROR_WANT_READ || ssl_e == SSL_ERROR_WANT_WRITE) continue;
			if (ssl_e == SSL_ERROR_ZERO_RETURN) return UNCURL_TLS_ERR_CLOSED;
			return UNCURL_TLS_ERR_READ;
		}

		total += n;
	}

	return UNCURL_OK;
}

void tls_sha1(uint8_t *dest, char *src)
{
	SHA1((uint8_t *) src, strlen(src), dest);
}
