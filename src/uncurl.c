#include "uncurl/uncurl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"
#include "tls.h"
#include "http.h"
#include "thread.h"

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

	char *hreq;
	struct http_header *hres;

	struct uncurl_opts opts;
	struct net_opts nopts;
	struct tls_opts topts;

	struct net_context *net;
	struct tls_context *tls;
	struct tls_state *tlss;

	void *ctx;
	int32_t (*read)(void *ctx, char *buf, uint32_t buf_size);
	int32_t (*write)(void *ctx, char *buf, uint32_t buf_size);

	int32_t scheme;
	char *host;
	uint16_t port;
};


/*** INITIALIZATION ***/

DLL_EXPORT void uncurl_destroy(struct uncurl *uc)
{
	if (!uc) return;

	tlss_free(uc->tlss);

	pthread_mutex_destroy(&uc->mutex);

	free(uc);
}

DLL_EXPORT int32_t uncurl_init(struct uncurl **uc_in)
{
	int32_t e;

	struct uncurl *uc = *uc_in = calloc(1, sizeof(struct uncurl));

	pthread_mutex_init(&uc->mutex, NULL);

	net_default_opts(&uc->nopts);
	tls_default_opts(&uc->topts);

	e = tlss_alloc(&uc->tlss);
	if (e == UNCURL_OK) return e;

	uncurl_destroy(uc);
	*uc_in = NULL;

	return e;
}


/*** CONNECTION ***/

DLL_EXPORT int32_t uncurl_connect(struct uncurl *uc, int32_t scheme, char *host, uint16_t port)
{
	int32_t r = ERR_DEFAULT;
	int32_t e;

	pthread_mutex_lock(&uc->mutex);

	//free existing host
	if (uc->host) free(uc->host);
	uc->host = NULL;

	//set state
	uc->scheme = scheme;
	uc->host = strdup(host);
	uc->port = port;

	//resolve the hostname into an ip4 address
	char ip4[LEN_IP4];
	e = net_getip4(uc->host, ip4, LEN_IP4);
	if (e != UNCURL_OK) {r = e; goto uncurl_connect_end;}

	//make the net connection
	e = net_connect(&uc->net, ip4, uc->port, &uc->nopts);
	if (e != UNCURL_OK) {r = e; goto uncurl_connect_end;}

	//default read/write callbacks
	uc->ctx = uc->net;
	uc->read = net_read;
	uc->write = net_write;

	if (scheme == UNCURL_HTTPS) {
		e = tls_connect(&uc->tls, uc->tlss, uc->net, &uc->topts);
		if (e != UNCURL_OK) {r = e; goto uncurl_connect_end;}

		//tls read/write callbacks
		uc->ctx = uc->tls;
		uc->read = tls_read;
		uc->write = tls_write;
	}

	r = UNCURL_OK;

	uncurl_connect_end:

	pthread_mutex_unlock(&uc->mutex);

	return r;
}

DLL_EXPORT void uncurl_close(struct uncurl *uc)
{
	pthread_mutex_lock(&uc->mutex);

	tls_close(uc->tls);
	uc->tls = NULL;

	net_close(uc->net);
	uc->net = NULL;

	free(uc->host);
	uc->host = NULL;

	http_free_header(uc->hres);
	uc->hres = NULL;

	free(uc->hreq);
	uc->hreq = NULL;

	pthread_mutex_unlock(&uc->mutex);
}


/*** REQUEST ***/

DLL_EXPORT void uncurl_set_request_header(struct uncurl *uc, ...)
{
	va_list args;

	pthread_mutex_lock(&uc->mutex);

	//free existing hreq
	if (uc->hreq) free(uc->hreq);
	uc->hreq = NULL;

	va_start(args, uc);

	uc->hreq = http_request_header(args);

	va_end(args);

	pthread_mutex_unlock(&uc->mutex);
}

DLL_EXPORT int32_t uncurl_send_request(struct uncurl *uc, char *method, char *path, char *body, uint32_t body_len)
{
	int32_t e;

	pthread_mutex_lock(&uc->mutex);

	//generate the HTTP request header
	char *req = http_request(method, uc->host, path, uc->hreq, body, body_len);

	//send the request header to the HTTP server
	e = uc->write(uc->ctx, req, (uint32_t) strlen(req));
	free(req);

	pthread_mutex_unlock(&uc->mutex);

	return e;
}


/*** READING HEADER ***/

static int32_t uncurl_read_header(struct uncurl *uc, char **header)
{
	int32_t e = UNCURL_ERR_HEADER;
	char *h = *header = calloc(LEN_HTTP_HEADER, 1);

	for (int32_t x = 0; x < LEN_HTTP_HEADER - 1; x++) {
		e = uc->read(uc->ctx, h + x, 1);
		if (e != UNCURL_OK) break;

		if (x > 2 && h[x - 3] == '\r' && h[x - 2] == '\n' && h[x - 1] == '\r' && h[x] == '\n')
			return UNCURL_OK;
	}

	free(h);
	*header = NULL;

	return e ? e : UNCURL_ERR_HEADER;
}

DLL_EXPORT int32_t uncurl_read_response_header(struct uncurl *uc)
{
	int32_t e;

	pthread_mutex_lock(&uc->mutex);

	//free any exiting response headers
	if (uc->hres) http_free_header(uc->hres);
	uc->hres = NULL;

	//read the HTTP response header
	char *header = NULL;
	e = uncurl_read_header(uc, &header);

	if (e == UNCURL_OK) {
		//parse the header into the http_header struct
		uc->hres = http_parse_header(header);
		free(header);
	}

	pthread_mutex_unlock(&uc->mutex);

	return e;
}


/*** READING BODY ***/

static int32_t uncurl_read_chunk_len(struct uncurl *uc, uint32_t *len)
{
	int32_t e = UNCURL_ERR_CHUNK_LEN;

	char chunk_len[LEN_CHUNK_LEN];
	memset(chunk_len, 0, LEN_CHUNK_LEN);

	for (int32_t x = 0; x < LEN_CHUNK_LEN - 1; x++) {
		e = uc->read(uc->ctx, chunk_len + x, 1);
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

static int32_t uncurl_response_body_chunked(struct uncurl *uc, char **body, uint32_t *body_len)
{
	uint32_t offset = 0;
	uint32_t chunk_len = 0;

	do {
		int32_t e;

		//read the chunk size one byte at a time
		e = uncurl_read_chunk_len(uc, &chunk_len);
		if (e != UNCURL_OK) return e;

		//make room for chunk and "\r\n" after chunk
		*body = realloc(*body, offset + chunk_len + 2);

		//read chunk into buffer with extra 2 bytes for "\r\n"
		e = uc->read(uc->ctx, *body + offset, chunk_len + 2);
		if (e != UNCURL_OK) return e;

		offset += chunk_len;

	} while (chunk_len > 0);

	(*body)[offset] = '\0';
	*body_len = offset;

	return UNCURL_OK;
}

DLL_EXPORT int32_t uncurl_read_response_body(struct uncurl *uc, char **body, uint32_t *body_len)
{
	int32_t r = ERR_DEFAULT;
	int32_t e;

	*body = NULL;
	*body_len = 0;

	pthread_mutex_lock(&uc->mutex);

	//look for chunked response
	char *te = NULL;
	e = http_get_header_str(uc->hres, "Transfer-Encoding", &te);
	if (e == UNCURL_OK && strstr(http_lc(te), "chunked")) {
		e = uncurl_response_body_chunked(uc, body, body_len);
		if (e != UNCURL_OK) {r = e; goto uncurl_response_body_end;}

		r = UNCURL_OK;
	}

	//fall through to using Content-Length
	if (r != UNCURL_OK) {
		e = http_get_header_int(uc->hres, "Content-Length", (int32_t *) body_len);
		if (e != UNCURL_OK) {r = e; goto uncurl_response_body_end;}

		*body = calloc(*body_len + 1, 1);
		e = uc->read(uc->ctx, *body, *body_len);
		if (e != UNCURL_OK) {r = e; goto uncurl_response_body_end;}

		r = UNCURL_OK;
	}

	uncurl_response_body_end:

	if (r != UNCURL_OK) {
		free(*body);
		*body = NULL;
	}

	pthread_mutex_unlock(&uc->mutex);

	return r;
}


/*** HELPERS ***/

DLL_EXPORT int32_t uncurl_get_status_code(struct uncurl *uc, int32_t *status_code)
{
	*status_code = 0;
	return http_get_status_code(uc->hres, status_code);
}

DLL_EXPORT int32_t uncurl_parse_url(char *url, int32_t *scheme, char **host, uint16_t *port, char **path)
{
	return http_parse_url(url, scheme, host, port, path);
}
