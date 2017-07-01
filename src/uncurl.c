#include "uncurl/uncurl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"
#include "tls.h"
#include "http.h"
#include "thread.h"

#include "../cacert/cacert.h"

#define LEN_IP4 16
#define LEN_CHUNK_LEN 64
#define LEN_HTTP_HEADER 1024

#if defined(__WINDOWS__)
	#define strdup(a) _strdup(a)
#endif

struct uncurl_opts {
	uint32_t max_response_header;
	uint32_t max_content_length;
};

struct uncurl {
	pthread_mutex_t mutex;

	struct uncurl_opts opts;
	struct net_opts nopts;
	struct tls_opts topts;

	struct tls_state *tlss;
};

struct uncurl_conn {
	struct uncurl *uc;

	char *hreq;
	struct http_header *hres;

	struct net_context *net;
	struct tls_context *tls;

	void *ctx;
	int32_t (*read)(void *ctx, char *buf, uint32_t buf_size);
	int32_t (*write)(void *ctx, char *buf, uint32_t buf_size);

	char *host;
	uint16_t port;
};


/*** INITIALIZATION ***/

UNCURL_EXPORT void uncurl_destroy(struct uncurl *uc)
{
	if (!uc) return;

	tlss_free(uc->tlss);

	pthread_mutex_destroy(&uc->mutex);

	free(uc);
}

UNCURL_EXPORT int32_t uncurl_init(struct uncurl **uc_in)
{
	int32_t e;

	struct uncurl *uc = *uc_in = calloc(1, sizeof(struct uncurl));

	pthread_mutex_init(&uc->mutex, NULL);

	net_default_opts(&uc->nopts);
	tls_default_opts(&uc->topts);

	e = tlss_alloc(&uc->tlss, CACERT, sizeof(CACERT) / sizeof(const char *));
	if (e == UNCURL_OK) return e;

	uncurl_destroy(uc);
	*uc_in = NULL;

	return e;
}


/*** HEADERS ***/

UNCURL_EXPORT int8_t uncurl_check_header(struct uncurl_conn *ucc, char *name, char *subval)
{
	int32_t e;
	char *val = NULL;

	e = http_get_header_str(ucc->hres, name, &val);
	if (e == UNCURL_OK && strstr(http_lc(val), subval)) return 1;

	return 0;
}


/*** CONNECTION ***/

UNCURL_EXPORT int32_t uncurl_connect(struct uncurl *uc, struct uncurl_conn **ucc_in,
	int32_t scheme, char *host, uint16_t port)
{
	int32_t r = UNCURL_ERR_DEFAULT;
	int32_t e;

	//create uncurl_conn and attach uncurl to it
	struct uncurl_conn *ucc = *ucc_in = calloc(1, sizeof(struct uncurl_conn));
	ucc->uc = uc;

	//set state
	ucc->host = strdup(host);
	ucc->port = port;

	//resolve the hostname into an ip4 address
	char ip4[LEN_IP4];
	e = net_getip4(ucc->host, ip4, LEN_IP4);
	if (e != UNCURL_OK) {r = e; goto uncurl_connect_end;}

	//make the net connection
	e = net_connect(&ucc->net, ip4, ucc->port, &uc->nopts);
	if (e != UNCURL_OK) {r = e; goto uncurl_connect_end;}

	//default read/write callbacks
	ucc->ctx = ucc->net;
	ucc->read = net_read;
	ucc->write = net_write;

	if (scheme == UNCURL_HTTPS) {
		pthread_mutex_lock(&uc->mutex);

		e = tls_connect(&ucc->tls, uc->tlss, ucc->net, &uc->topts);

		pthread_mutex_unlock(&uc->mutex);

		if (e != UNCURL_OK) {r = e; goto uncurl_connect_end;}

		//tls read/write callbacks
		ucc->ctx = ucc->tls;
		ucc->read = tls_read;
		ucc->write = tls_write;
	}

	r = UNCURL_OK;

	uncurl_connect_end:

	return r;
}

UNCURL_EXPORT void uncurl_close(struct uncurl_conn *ucc)
{
	pthread_mutex_lock(&ucc->uc->mutex);

	tls_close(ucc->tls);
	ucc->tls = NULL;

	pthread_mutex_unlock(&ucc->uc->mutex);

	net_close(ucc->net);
	ucc->net = NULL;

	free(ucc->host);
	ucc->host = NULL;

	http_free_header(ucc->hres);
	ucc->hres = NULL;

	free(ucc->hreq);
	ucc->hreq = NULL;

	free(ucc);
}


/*** REQUEST ***/

UNCURL_EXPORT void uncurl_set_header_str(struct uncurl_conn *ucc, char *name, char *value)
{
	ucc->hreq = http_set_header(ucc->hreq, name, HTTP_STRING, value);
}

UNCURL_EXPORT void uncurl_set_header_int(struct uncurl_conn *ucc, char *name, int32_t value)
{
	ucc->hreq = http_set_header(ucc->hreq, name, HTTP_INT, &value);
}

UNCURL_EXPORT void uncurl_clear_header(struct uncurl_conn *ucc)
{
	free(ucc->hreq);
	ucc->hreq = NULL;
}

UNCURL_EXPORT int32_t uncurl_write_header(struct uncurl_conn *ucc, char *method, char *path)
{
	int32_t e;

	//generate the HTTP request header
	char *req = http_request(method, ucc->host, path, ucc->hreq);

	pthread_mutex_lock(&ucc->uc->mutex);

	//write the request header to the HTTP server
	e = ucc->write(ucc->ctx, req, (uint32_t) strlen(req));

	pthread_mutex_unlock(&ucc->uc->mutex);

	free(req);

	return e;
}

UNCURL_EXPORT int32_t uncurl_write_body(struct uncurl_conn *ucc, char *body, uint32_t body_len)
{
	int32_t e;

	pthread_mutex_lock(&ucc->uc->mutex);

	e = ucc->write(ucc->ctx, body, body_len);

	pthread_mutex_unlock(&ucc->uc->mutex);

	return e;
}


/*** READING HEADER ***/

static int32_t uncurl_read_header_(struct uncurl_conn *ucc, char **header)
{
	int32_t e = UNCURL_ERR_HEADER;
	char *h = *header = calloc(LEN_HTTP_HEADER, 1);

	for (int32_t x = 0; x < LEN_HTTP_HEADER - 1; x++) {
		e = ucc->read(ucc->ctx, h + x, 1);
		if (e != UNCURL_OK) break;

		if (x > 2 && h[x - 3] == '\r' && h[x - 2] == '\n' && h[x - 1] == '\r' && h[x] == '\n')
			return UNCURL_OK;
	}

	free(h);
	*header = NULL;

	return e ? e : UNCURL_ERR_HEADER;
}

UNCURL_EXPORT int32_t uncurl_read_header(struct uncurl_conn *ucc)
{
	int32_t e;

	//free any exiting response headers
	if (ucc->hres) http_free_header(ucc->hres);
	ucc->hres = NULL;

	pthread_mutex_lock(&ucc->uc->mutex);

	//read the HTTP response header
	char *header = NULL;
	e = uncurl_read_header_(ucc, &header);

	pthread_mutex_unlock(&ucc->uc->mutex);

	if (e == UNCURL_OK) {
		//parse the header into the http_header struct
		ucc->hres = http_parse_header(header);
		free(header);
	}

	return e;
}


/*** READING BODY ***/

static int32_t uncurl_read_chunk_len(struct uncurl_conn *ucc, uint32_t *len)
{
	int32_t e = UNCURL_ERR_CHUNK_LEN;

	char chunk_len[LEN_CHUNK_LEN];
	memset(chunk_len, 0, LEN_CHUNK_LEN);

	for (int32_t x = 0; x < LEN_CHUNK_LEN - 1; x++) {
		e = ucc->read(ucc->ctx, chunk_len + x, 1);
		if (e != UNCURL_OK) break;

		if (x > 0 && chunk_len[x - 1] == '\r' && chunk_len[x] == '\n') {
			chunk_len[x - 1] = '\0';
			*len = strtoul(chunk_len, NULL, 16);
			return UNCURL_OK;
		}
	}

	*len = 0;

	return e ? e : UNCURL_ERR_CHUNK_LEN;
}

static int32_t uncurl_response_body_chunked(struct uncurl_conn *ucc, char **body, uint32_t *body_len)
{
	uint32_t offset = 0;
	uint32_t chunk_len = 0;

	do {
		int32_t e;

		//read the chunk size one byte at a time
		e = uncurl_read_chunk_len(ucc, &chunk_len);
		if (e != UNCURL_OK) return e;

		//make room for chunk and "\r\n" after chunk
		*body = realloc(*body, offset + chunk_len + 2);

		//read chunk into buffer with extra 2 bytes for "\r\n"
		e = ucc->read(ucc->ctx, *body + offset, chunk_len + 2);
		if (e != UNCURL_OK) return e;

		offset += chunk_len;

	} while (chunk_len > 0);

	(*body)[offset] = '\0';
	*body_len = offset;

	return UNCURL_OK;
}

UNCURL_EXPORT int32_t uncurl_read_body_all(struct uncurl_conn *ucc, char **body, uint32_t *body_len)
{
	int32_t r = UNCURL_ERR_DEFAULT;
	int32_t e;

	*body = NULL;
	*body_len = 0;

	//look for chunked response
	if (uncurl_check_header(ucc, "Transfer-Encoding", "chunked")) {
		pthread_mutex_lock(&ucc->uc->mutex);

		e = uncurl_response_body_chunked(ucc, body, body_len);

		pthread_mutex_unlock(&ucc->uc->mutex);

		if (e != UNCURL_OK) {r = e; goto uncurl_response_body_end;}

		r = UNCURL_OK;
	}

	//fall through to using Content-Length
	if (r != UNCURL_OK) {
		e = http_get_header_int(ucc->hres, "Content-Length", (int32_t *) body_len);
		if (e != UNCURL_OK) {r = e; goto uncurl_response_body_end;}

		if (*body_len == 0) {r = UNCURL_ERR_NO_BODY; goto uncurl_response_body_end;}

		*body = calloc(*body_len + 1, 1);

		pthread_mutex_lock(&ucc->uc->mutex);

		e = ucc->read(ucc->ctx, *body, *body_len);

		pthread_mutex_unlock(&ucc->uc->mutex);

		if (e != UNCURL_OK) {r = e; goto uncurl_response_body_end;}

		r = UNCURL_OK;
	}

	uncurl_response_body_end:

	if (r != UNCURL_OK) {
		free(*body);
		*body = NULL;
	}

	return r;
}


/*** HELPERS ***/

UNCURL_EXPORT int32_t uncurl_get_status_code(struct uncurl_conn *ucc, int32_t *status_code)
{
	*status_code = 0;
	return http_get_status_code(ucc->hres, status_code);
}

UNCURL_EXPORT int32_t uncurl_parse_url(char *url, struct uncurl_info *uci)
{
	memset(uci, 0, sizeof(struct uncurl_info));

	return http_parse_url(url, &uci->scheme, &uci->host, &uci->port, &uci->path);
}

UNCURL_EXPORT void uncurl_free_info(struct uncurl_info *uci)
{
	free(uci->host);
	free(uci->path);
}
