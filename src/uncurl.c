#include "uncurl/uncurl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"
#include "tls.h"
#include "http.h"
#include "ws.h"

#define LEN_IP4 16
#define LEN_CHUNK_LEN 64

#if defined(__WINDOWS__)
	#include <winsock2.h>
	#define strdup(a) _strdup(a)
#endif

struct uncurl_opts {
	uint32_t max_header;
	uint32_t max_body;
};

struct uncurl_tls_ctx {
	struct tls_state *tlss;
};

struct uncurl_conn {
	struct uncurl_opts opts;
	struct net_opts nopts;
	struct tls_opts topts;

	char *hreq;
	struct http_header *hres;

	struct net_context *net;
	struct tls_context *tls;

	void *ctx;
	int32_t (*read)(void *ctx, char *buf, uint32_t buf_size);
	int32_t (*write)(void *ctx, char *buf, uint32_t buf_size);

	char *host;
	uint16_t port;

	uint32_t seed;
};


/*** TLS CONTEXT ***/

UNCURL_EXPORT void uncurl_free_tls_ctx(struct uncurl_tls_ctx *uc_tls)
{
	if (!uc_tls) return;

	tlss_free(uc_tls->tlss);

	free(uc_tls);
}

UNCURL_EXPORT int32_t uncurl_new_tls_ctx(struct uncurl_tls_ctx **uc_tls_in)
{
	int32_t e;

	struct uncurl_tls_ctx *uc_tls = *uc_tls_in = calloc(1, sizeof(struct uncurl_tls_ctx));

	e = tlss_alloc(&uc_tls->tlss);
	if (e == UNCURL_OK) return e;

	uncurl_free_tls_ctx(uc_tls);
	*uc_tls_in = NULL;

	return e;
}

UNCURL_EXPORT int32_t uncurl_set_cacert(struct uncurl_tls_ctx *uc_tls, char **cacert, uint32_t num_certs)
{
	return tlss_load_cacert(uc_tls->tlss, cacert, num_certs);
}

UNCURL_EXPORT int32_t uncurl_set_cacert_file(struct uncurl_tls_ctx *uc_tls, char *cacert_file)
{
	return tlss_load_cacert_file(uc_tls->tlss, cacert_file);
}


/*** CONNECTION ***/

static void uncurl_default_opts(struct uncurl_opts *opts)
{
	opts->max_header = 1024;
	opts->max_body = 128 * 1024 * 1024;
}

UNCURL_EXPORT struct uncurl_conn *uncurl_new_conn()
{
	struct uncurl_conn *ucc = calloc(1, sizeof(struct uncurl_conn));

	uncurl_default_opts(&ucc->opts);
	net_default_opts(&ucc->nopts);
	tls_default_opts(&ucc->topts);

	ucc->seed = ws_rand(&ucc->seed);

	return ucc;
}

UNCURL_EXPORT int32_t uncurl_connect(struct uncurl_tls_ctx *uc_tls, struct uncurl_conn *ucc,
	int32_t scheme, char *host, uint16_t port)
{
	int32_t r = UNCURL_ERR_DEFAULT;
	int32_t e;

	//set state
	ucc->host = strdup(host);
	ucc->port = port;

	//resolve the hostname into an ip4 address
	char ip4[LEN_IP4];
	e = net_getip4(ucc->host, ip4, LEN_IP4);
	if (e != UNCURL_OK) {r = e; goto uncurl_connect_end;}

	//make the net connection
	e = net_connect(&ucc->net, ip4, ucc->port, &ucc->nopts);
	if (e != UNCURL_OK) {r = e; goto uncurl_connect_end;}

	//default read/write callbacks
	ucc->ctx = ucc->net;
	ucc->read = net_read;
	ucc->write = net_write;

	if (scheme == UNCURL_HTTPS || scheme == UNCURL_WSS) {
		e = tls_connect(&ucc->tls, uc_tls->tlss, ucc->net, ucc->host, &ucc->topts);
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
	tls_close(ucc->tls);
	ucc->tls = NULL;

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

UNCURL_EXPORT void uncurl_set_option(struct uncurl_conn *ucc, int32_t opt, int32_t val)
{
	switch (opt) {
		//uncurl options
		case UNCURL_OPT_MAX_HEADER:
			ucc->opts.max_header = (uint32_t) val; break;
		case UNCURL_OPT_MAX_BODY:
			ucc->opts.max_body = (uint32_t) val; break;

		//net options
		case UNCURL_NOPT_READ_TIMEOUT:
			ucc->nopts.read_timeout = val; break;
		case UNCURL_NOPT_CONNECT_TIMEOUT:
			ucc->nopts.connect_timeout = val; break;
		case UNCURL_NOPT_READ_BUF:
			ucc->nopts.read_buf = val; break;
		case UNCURL_NOPT_WRITE_BUF:
			ucc->nopts.write_buf = val; break;
		case UNCURL_NOPT_KEEPALIVE:
			ucc->nopts.keepalive = val; break;
		case UNCURL_NOPT_TCP_NODELAY:
			ucc->nopts.tcp_nodelay = val; break;

		//tls options
		case UNCURL_TOPT_VERIFY_HOST:
			ucc->topts.verify_host = val; break;
	}
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

UNCURL_EXPORT void uncurl_free_header(struct uncurl_conn *ucc)
{
	free(ucc->hreq);
	ucc->hreq = NULL;
}

UNCURL_EXPORT int32_t uncurl_write_header(struct uncurl_conn *ucc, char *method, char *path)
{
	int32_t e;

	//generate the HTTP request header
	char *req = http_request(method, ucc->host, path, ucc->hreq);

	//write the request header to the HTTP server
	e = ucc->write(ucc->ctx, req, (uint32_t) strlen(req));

	free(req);

	return e;
}

UNCURL_EXPORT int32_t uncurl_write_body(struct uncurl_conn *ucc, char *body, uint32_t body_len)
{
	int32_t e;

	e = ucc->write(ucc->ctx, body, body_len);

	return e;
}


/*** RESPONSE ***/

static int32_t uncurl_read_header_(struct uncurl_conn *ucc, char **header)
{
	int32_t r = UNCURL_ERR_MAX_HEADER;

	uint32_t max_header = ucc->opts.max_header;
	char *h = *header = calloc(max_header, 1);

	uint32_t x = 0;
	for (; x < max_header - 1; x++) {
		int32_t e;

		e = ucc->read(ucc->ctx, h + x, 1);
		if (e != UNCURL_OK) {r = e; break;}

		if (x > 2 && h[x - 3] == '\r' && h[x - 2] == '\n' && h[x - 1] == '\r' && h[x] == '\n')
			return UNCURL_OK;
	}

	free(h);
	*header = NULL;

	return r;
}

UNCURL_EXPORT int32_t uncurl_read_header(struct uncurl_conn *ucc)
{
	int32_t e;

	//free any exiting response headers
	if (ucc->hres) http_free_header(ucc->hres);
	ucc->hres = NULL;

	//read the HTTP response header
	char *header = NULL;
	e = uncurl_read_header_(ucc, &header);

	if (e == UNCURL_OK) {
		//parse the header into the http_header struct
		ucc->hres = http_parse_header(header);
		free(header);
	}

	return e;
}

static int32_t uncurl_read_chunk_len(struct uncurl_conn *ucc, uint32_t *len)
{
	int32_t r = UNCURL_ERR_MAX_CHUNK;

	char chunk_len[LEN_CHUNK_LEN];
	memset(chunk_len, 0, LEN_CHUNK_LEN);

	for (uint32_t x = 0; x < LEN_CHUNK_LEN - 1; x++) {
		int32_t e;

		e = ucc->read(ucc->ctx, chunk_len + x, 1);
		if (e != UNCURL_OK) {r = e; break;}

		if (x > 0 && chunk_len[x - 1] == '\r' && chunk_len[x] == '\n') {
			chunk_len[x - 1] = '\0';
			*len = strtoul(chunk_len, NULL, 16);
			return UNCURL_OK;
		}
	}

	*len = 0;

	return r;
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
		if (offset + chunk_len > ucc->opts.max_body) return UNCURL_ERR_MAX_BODY;

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
		e = uncurl_response_body_chunked(ucc, body, body_len);
		if (e != UNCURL_OK) {r = e; goto uncurl_response_body_end;}

		r = UNCURL_OK;
	}

	//fall through to using Content-Length
	if (r != UNCURL_OK) {
		e = uncurl_get_header_int(ucc, "Content-Length", (int32_t *) body_len);
		if (e != UNCURL_OK) {r = e; goto uncurl_response_body_end;}

		if (*body_len == 0) {r = UNCURL_ERR_NO_BODY; goto uncurl_response_body_end;}
		if (*body_len > ucc->opts.max_body) {r = UNCURL_ERR_MAX_BODY; goto uncurl_response_body_end;}

		*body = calloc(*body_len + 1, 1);

		e = ucc->read(ucc->ctx, *body, *body_len);

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


/*** WEBSOCKETS ***/

UNCURL_EXPORT int32_t uncurl_ws_connect(struct uncurl_conn *ucc, char *path)
{
	int32_t e;

	//obligatory websocket headers
	char *sec_key = ws_create_key(&ucc->seed);
	uncurl_set_header_str(ucc, "Upgrade", "websocket");
	uncurl_set_header_str(ucc, "Connection", "Upgrade");
	uncurl_set_header_str(ucc, "Sec-WebSocket-Key", sec_key);
	uncurl_set_header_str(ucc, "Sec-WebSocket-Version", "13");
	free(sec_key);

	//write the header
	e = uncurl_write_header(ucc, "GET", path);
	if (e != UNCURL_OK) return e;

	//we expect a 101 response code from the server
	e = uncurl_read_header(ucc);
	if (e != UNCURL_OK) return e;

	//make sure we have a 101 from the server
	int32_t status_code = 0;
	e = uncurl_get_status_code(ucc, &status_code);
	if (e != UNCURL_OK) return e;
	if (status_code != 101) return UNCURL_WS_ERR_REPLY;

	//body needs to be read as there is an extra \r\n in the response
	uint32_t body_len = 0;
	char *body = NULL;
	e = uncurl_read_body_all(ucc, &body, &body_len);
	free(body);

	return e;
}

UNCURL_EXPORT int32_t uncurl_ws_write(struct uncurl_conn *ucc, char *buf, uint32_t buf_len, int32_t opcode)
{
	struct ws_header h;
	memset(&h, 0, sizeof(struct ws_header));

	h.fin = 1;
	h.mask = 1;
	h.opcode = (uint8_t) opcode;
	h.payload_len = buf_len;

	//serialize the payload into a websocket conformant message
	uint64_t size = 0;
	char *netbuf = ws_serialize(&h, &ucc->seed, buf, &size);

	//write full network buffer
	int32_t e = ucc->write(ucc->ctx, netbuf, (uint32_t) size);

	free(netbuf);

	return e;
}

UNCURL_EXPORT int32_t uncurl_ws_poll(struct uncurl_conn *ucc, int32_t timeout_ms)
{
	return net_poll(ucc->net, NET_POLLIN, timeout_ms);
}

UNCURL_EXPORT int32_t uncurl_ws_read(struct uncurl_conn *ucc, char *buf, uint32_t buf_len, uint8_t *opcode)
{
	int32_t e;
	char header_buf[WS_HEADER_SIZE];
	struct ws_header h;

	//first two bytes contain most control information
	e = ucc->read(ucc->ctx, header_buf, 2);
	if (e != UNCURL_OK) return e;
	ws_parse_header0(&h, header_buf);
	*opcode = h.opcode;

	//read the payload size and mask
	e = ucc->read(ucc->ctx, header_buf, h.addtl_bytes);
	if (e != UNCURL_OK) return e;
	ws_parse_header1(&h, header_buf);

	//check bounds
	if (h.payload_len > ucc->opts.max_body) return UNCURL_ERR_MAX_BODY;
	if (h.payload_len > buf_len) return UNCURL_ERR_BUFFER;

	return ucc->read(ucc->ctx, buf, (uint32_t) h.payload_len);
}


/*** HELPERS ***/

UNCURL_EXPORT int32_t uncurl_get_status_code(struct uncurl_conn *ucc, int32_t *status_code)
{
	*status_code = 0;
	return http_get_status_code(ucc->hres, status_code);
}

UNCURL_EXPORT int32_t uncurl_get_header(struct uncurl_conn *ucc, char *key, int32_t *val_int, char **val_str)
{
	return http_get_header(ucc->hres, key, val_int, val_str);
}

UNCURL_EXPORT int32_t uncurl_parse_url(char *url, struct uncurl_info *uci)
{
	memset(uci, 0, sizeof(struct uncurl_info));

	return http_parse_url(url, &uci->scheme, &uci->host, &uci->port, &uci->path);
}

UNCURL_EXPORT int8_t uncurl_check_header(struct uncurl_conn *ucc, char *name, char *subval)
{
	int32_t e;
	char *val = NULL;

	e = uncurl_get_header_str(ucc, name, &val);
	if (e == UNCURL_OK && strstr(http_lc(val), subval)) return 1;

	return 0;
}

UNCURL_EXPORT void uncurl_free_info(struct uncurl_info *uci)
{
	free(uci->host);
	free(uci->path);
}
