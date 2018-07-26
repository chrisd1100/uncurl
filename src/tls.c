#include "tls.h"

#include <stdlib.h>
#include <string.h>

#include "openssl/ssl.h"
#include "openssl/x509v3.h"
#include "openssl/rsa.h"

#include "uncurl/status.h"

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

static char **tlss_parse_cacert(char *raw, size_t size, uint32_t *n)
{
	char *cacert = calloc(size + 1, 1);
	memcpy(cacert, raw, size);

	char **out = NULL;
	uint32_t out_len = 0;

	char *tok = cacert;
	char *next = strstr(tok, "\n\n");
	if (!next) next = strstr(tok, "\r\n\r\n");

	while (next) {
		out_len++;
		out = realloc(out, sizeof(char *) * out_len);

		size_t this_len = next - tok;
		out[out_len - 1] = calloc(this_len + 1, 1);
		memcpy(out[out_len - 1], tok, this_len);

		tok = next + 2;
		next = strstr(tok, "\n\n");
		if (!next) next = strstr(tok, "\r\n\r\n");
	}

	free(cacert);

	*n = out_len;
	return out;
}

int32_t tlss_load_cacert(struct tls_state *tlss, char *cacert, size_t size)
{
	int32_t r = UNCURL_OK;

	X509_STORE *store = SSL_CTX_get_cert_store(tlss->ctx);
	if (!store) return UNCURL_TLS_ERR_CACERT;

	uint32_t num_certs = 0;
	char **parsed_cacert = tlss_parse_cacert(cacert, size, &num_certs);

	for (uint32_t x = 0; x < num_certs && r == UNCURL_OK; x++) {
		X509 *cert = NULL;
		BIO *bio = BIO_new_mem_buf(parsed_cacert[x], -1);

		if (bio && PEM_read_bio_X509(bio, &cert, 0, NULL)) {
			X509_STORE_add_cert(store, cert);
			X509_free(cert);
			BIO_free(bio);
		} else {
			r = UNCURL_TLS_ERR_CACERT;
		}
	}

	for (uint32_t x = 0; x < num_certs; x++)
		free(parsed_cacert[x]);

	free(parsed_cacert);

	return r;
}

int32_t tlss_load_cacert_file(struct tls_state *tlss, char *cacert_file)
{
	int32_t e = SSL_CTX_load_verify_locations(tlss->ctx, cacert_file, NULL);
	if (e != 1) return UNCURL_TLS_ERR_CACERT;

	return UNCURL_OK;
}

int32_t tlss_load_cert_and_key(struct tls_state *tlss, char *cert, size_t cert_size, char *key, size_t key_size)
{
	int32_t r = UNCURL_OK;

	BIO *cbio = NULL, *kbio = NULL;
	X509 *cert_x509 = NULL;
	RSA *rsa = NULL;

	cbio = BIO_new_mem_buf(cert, (int32_t) cert_size);
	cert_x509 = PEM_read_bio_X509(cbio, NULL, 0, NULL);
	if (!cert_x509) {r = UNCURL_TLS_ERR_CERT; goto except;}

	int32_t e = SSL_CTX_use_certificate(tlss->ctx, cert_x509);
	if (e != 1) {r = UNCURL_TLS_ERR_CERT; goto except;}

	kbio = BIO_new_mem_buf(key, (int32_t) key_size);
	rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);
	if (!rsa) {r = UNCURL_TLS_ERR_KEY; goto except;}

	e = SSL_CTX_use_RSAPrivateKey(tlss->ctx, rsa);
	if (e != 1) {r = UNCURL_TLS_ERR_KEY; goto except;}

	e = SSL_CTX_check_private_key(tlss->ctx);
	if (e != 1) {r = UNCURL_TLS_ERR_KEY; goto except;}

	except:

	if (cert_x509)
		X509_free(cert_x509);

	if (rsa)
		RSA_free(rsa);

	if (kbio)
		BIO_free(kbio);

	if (cbio)
		BIO_free(cbio);

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
	struct tls_state *tlss = *tlss_in = calloc(1, sizeof(struct tls_state));

	int32_t r = UNCURL_OK;

	//the SSL context can be reused for multiple connections
	tlss->ctx = SSL_CTX_new(TLS_method());
	if (!tlss->ctx) {r = UNCURL_TLS_ERR_CONTEXT; goto except;}

	//limit ciphers to predefined secure list
	int32_t e = SSL_CTX_set_cipher_list(tlss->ctx, TLS_CIPHER_LIST);
	if (e != 1) {r = UNCURL_TLS_ERR_CIPHER; goto except;}

	//disable any non TLS protocols
	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(tlss->ctx, flags);

	except:

	if (r != UNCURL_OK) {
		tlss_free(tlss);
		*tlss_in = NULL;
	}

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

static int32_t tls_context_new(struct tls_context **tls_in, struct tls_state *tlss,
	struct net_context *nc, struct tls_opts *opts)
{
	struct tls_context *tls = *tls_in = calloc(1, sizeof(struct tls_context));

	//set options
	memcpy(&tls->opts, opts, sizeof(struct tls_opts));

	//keep handle to the underlying net_context
	tls->nc = nc;

	tls->ssl = SSL_new(tlss->ctx);
	if (!tls->ssl) return UNCURL_TLS_ERR_SSL;

	int32_t s = -1;
	net_get_socket(tls->nc, &s);
	int32_t e = SSL_set_fd(tls->ssl, s);
	if (e != 1) return UNCURL_TLS_ERR_FD;

	return UNCURL_OK;
}

static int32_t tls_handshake_poll(struct tls_context *tls, int32_t e, int32_t timeout_ms)
{
	int32_t ne = net_error();
	if (ne == net_bad_fd()) return UNCURL_TLS_ERR_FD;

	if (ne == net_would_block() || SSL_get_error(tls->ssl, e) == SSL_ERROR_WANT_READ)
		return net_poll(tls->nc, NET_POLLIN, timeout_ms);

	return UNCURL_TLS_ERR_HANDSHAKE;
}

int32_t tls_connect(struct tls_context **tls_in, struct tls_state *tlss,
	struct net_context *nc, char *host, struct tls_opts *opts)
{
	int32_t r = UNCURL_OK;

	int32_t e = tls_context_new(tls_in, tlss, nc, opts);
	struct tls_context *tls = *tls_in;
	if (e != UNCURL_OK) {r = e; goto except;}

	//set peer certificate verification
	SSL_set_verify(tls->ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_set_verify_depth(tls->ssl, TLS_VERIFY_DEPTH);

	//set hostname validation
	if (opts->verify_host) {
		X509_VERIFY_PARAM *param = SSL_get0_param(tls->ssl);
		X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		X509_VERIFY_PARAM_set1_host(param, host, 0);
	}

	//set hostname extension -- sometimes required
	SSL_set_tlsext_host_name(tls->ssl, host);

	//retrieve net options
	struct net_opts nopts;
	net_get_opts(tls->nc, &nopts);

	while (1) {
		//attempt SSL connection on nonblocking socket -- 1 is success
		e = SSL_connect(tls->ssl);
		if (e == 1) break;

		//if not successful, see if we neeed to poll for more data
		e = tls_handshake_poll(tls, e, nopts.connect_timeout);
		if (e != UNCURL_OK) {r = e; break;}
	}

	except:

	if (r != UNCURL_OK) {
		tls_close(tls);
		*tls_in = NULL;
	}

	return r;
}

int32_t tls_accept(struct tls_context **tls_in, struct tls_state *tlss,
	struct net_context *nc, struct tls_opts *opts)
{
	int32_t r = UNCURL_OK;

	int32_t e = tls_context_new(tls_in, tlss, nc, opts);
	struct tls_context *tls = *tls_in;
	if (e != UNCURL_OK) {r = e; goto except;}

	//retrieve net options
	struct net_opts nopts;
	net_get_opts(tls->nc, &nopts);

	while (1) {
		//attempt SSL accept on nonblocking socket -- 1 is success
		e = SSL_accept(tls->ssl);
		if (e == 1) break;

		//if not successful, see if we neeed to poll for more data
		e = tls_handshake_poll(tls, e, nopts.accept_timeout);
		if (e != UNCURL_OK) {r = e; break;}
	}

	except:

	if (r != UNCURL_OK) {
		tls_close(tls);
		*tls_in = NULL;
	}

	return r;
}

int32_t tls_write(void *ctx, char *buf, uint32_t buf_size)
{
	struct tls_context *tls = (struct tls_context *) ctx;

	uint32_t total = 0;

	while (total < buf_size) {
		int32_t n = SSL_write(tls->ssl, buf + total, buf_size - total);
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

	//retrieve net options
	struct net_opts nopts;
	net_get_opts(tls->nc, &nopts);

	uint32_t total = 0;

	while (total < buf_size) {
		if (SSL_has_pending(tls->ssl) == 0) {
			int32_t e = net_poll(tls->nc, NET_POLLIN, nopts.read_timeout);
			if (e != UNCURL_OK) return e;
		}

		int32_t n = SSL_read(tls->ssl, buf + total, buf_size - total);
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
