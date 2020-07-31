// Copyright (c) 2017-2020 Christopher D. Dickson <cdd@matoya.group>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#if !defined(UNCURL_EXPORT)
	#define UNCURL_EXPORT
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


#define UNCURL_PORT    80
#define UNCURL_PORT_S  443

enum uncurl_status {
	UNCURL_OK                    = 0,

	UNCURL_ERR_DEFAULT           = -50001,

	UNCURL_NET_ERR_SOCKET        = -50010,
	UNCURL_NET_ERR_BLOCKMODE     = -50011,
	UNCURL_NET_ERR_CONNECT       = -50012,
	UNCURL_NET_ERR_CONNECT_FINAL = -50013,
	UNCURL_NET_ERR_WRITE         = -50014,
	UNCURL_NET_ERR_READ          = -50015,
	UNCURL_NET_ERR_CLOSED        = -50016,
	UNCURL_NET_ERR_RESOLVE       = -50017,
	UNCURL_NET_ERR_NTOP          = -50018,
	UNCURL_NET_ERR_TIMEOUT       = -50019,
	UNCURL_NET_ERR_POLL          = -50020,
	UNCURL_NET_ERR_BIND          = -50021,
	UNCURL_NET_ERR_LISTEN        = -50022,
	UNCURL_NET_ERR_ACCEPT        = -50023,

	UNCURL_TLS_ERR_CONTEXT       = -51000,
	UNCURL_TLS_ERR_SSL           = -51001,
	UNCURL_TLS_ERR_FD            = -51002,
	UNCURL_TLS_ERR_HANDSHAKE     = -51003,
	UNCURL_TLS_ERR_WRITE         = -51004,
	UNCURL_TLS_ERR_READ          = -51005,
	UNCURL_TLS_ERR_CLOSED        = -51006,
	UNCURL_TLS_ERR_CACERT        = -51007,
	UNCURL_TLS_ERR_CIPHER        = -51008,
	UNCURL_TLS_ERR_CERT          = -51009,
	UNCURL_TLS_ERR_KEY           = -51010,

	UNCURL_HTTP_ERR_PARSE_STATUS = -52000,
	UNCURL_HTTP_ERR_PARSE_HEADER = -52001,
	UNCURL_HTTP_ERR_PARSE_SCHEME = -52002,
	UNCURL_HTTP_ERR_PARSE_HOST   = -52003,
	UNCURL_HTTP_ERR_NOT_FOUND    = -52004,

	UNCURL_ERR_NO_BODY           = -53000,
	UNCURL_ERR_MAX_CHUNK         = -53001,
	UNCURL_ERR_MAX_BODY          = -53002,
	UNCURL_ERR_MAX_HEADER        = -53003,
	UNCURL_ERR_BUFFER            = -53004,
	UNCURL_ERR_PROXY             = -53005,

	UNCURL_WS_ERR_STATUS         = -54000,
	UNCURL_WS_ERR_KEY            = -54001,
	UNCURL_WS_ERR_ORIGIN         = -54002,
};

enum uncurl_scheme {
	UNCURL_NONE  = 0,
	UNCURL_HTTP  = 1,
	UNCURL_HTTPS = 2,
	UNCURL_WS    = 3,
	UNCURL_WSS   = 4,
};

enum uncurl_header_type {
	UNCURL_REQUEST  = 0,
	UNCURL_RESPONSE = 1,
};

enum ws_opcode {
	UNCURL_WSOP_CONTINUE = 0x0,
	UNCURL_WSOP_TEXT     = 0x1,
	UNCURL_WSOP_BINARY   = 0x2,
	UNCURL_WSOP_CLOSE    = 0x8,
	UNCURL_WSOP_PING     = 0x9,
	UNCURL_WSOP_PONG     = 0xa,
};

enum ws_status_code {
	UNCURL_CLOSE_NORMAL           = 1000,
	UNCURL_CLOSE_GOING_AWAY       = 1001,
	UNCURL_CLOSE_PROTOCOL         = 1002,
	UNCURL_CLOSE_DATA_TYPE        = 1003,
	UNCURL_CLOSE_NO_STATUS_CODE   = 1005,
	UNCURL_CLOSE_ABNORMAL_CLOSE   = 1006,
	UNCURL_CLOSE_DATA_CONSISTENCY = 1007,
	UNCURL_CLOSE_POLICY           = 1008,
	UNCURL_CLOSE_TOO_BIG          = 1009,
	UNCURL_CLOSE_EXTENSION        = 1010,
	UNCURL_CLOSE_UNEXPECTED       = 1011,
	UNCURL_CLOSE_TLS_HANDSHAKE    = 1015,
};


// TLS Context

struct uncurl_tls_ctx;

UNCURL_EXPORT void
uncurl_free_tls_ctx(struct uncurl_tls_ctx *uc_tls);

UNCURL_EXPORT int32_t
uncurl_new_tls_ctx(struct uncurl_tls_ctx **uc_tls_in);

UNCURL_EXPORT int32_t
uncurl_set_cacert(struct uncurl_tls_ctx *uc_tls, char *cacert, size_t size);

UNCURL_EXPORT int32_t
uncurl_set_cacert_file(struct uncurl_tls_ctx *uc_tls, char *cacert_file);

UNCURL_EXPORT int32_t
uncurl_set_cert_and_key(struct uncurl_tls_ctx *uc_tls, char *cert,
	size_t cert_size, char *key, size_t key_size);


// Connection

struct uncurl_conn;

UNCURL_EXPORT struct uncurl_conn *
uncurl_new_conn(void);

UNCURL_EXPORT int32_t
uncurl_connect(struct uncurl_tls_ctx *uc_tls, struct uncurl_conn *ucc,
	int32_t scheme, char *host, uint16_t port, bool verify_host, char *proxy_host,
	uint16_t proxy_port, int32_t timeout_ms);

UNCURL_EXPORT int32_t
uncurl_listen(struct uncurl_conn *ucc, char *bind_ip4, uint16_t port);

UNCURL_EXPORT int32_t
uncurl_accept(struct uncurl_tls_ctx *uc_tls, struct uncurl_conn *ucc,
	struct uncurl_conn **ucc_new_in, int32_t scheme, int32_t timeout_ms);

UNCURL_EXPORT void
uncurl_close(struct uncurl_conn *ucc);

UNCURL_EXPORT int32_t
uncurl_poll(struct uncurl_conn *ucc, int32_t timeout_ms);

UNCURL_EXPORT void
uncurl_get_socket(struct uncurl_conn *ucc, void *socket);


// Request

UNCURL_EXPORT void
uncurl_set_header_str(struct uncurl_conn *ucc, char *name, char *value);

UNCURL_EXPORT void
uncurl_set_header_int(struct uncurl_conn *ucc, char *name, int32_t value);

UNCURL_EXPORT void
uncurl_free_header(struct uncurl_conn *ucc);

UNCURL_EXPORT int32_t
uncurl_write_header(struct uncurl_conn *ucc, char *str0, char *str1, int32_t type);

UNCURL_EXPORT int32_t
uncurl_write_body(struct uncurl_conn *ucc, char *body, uint32_t body_len);


// Response

#define uncurl_get_header_int(ucc, key, val_int) uncurl_get_header(ucc, key, val_int, NULL)
#define uncurl_get_header_str(ucc, key, val_str) uncurl_get_header(ucc, key, NULL, val_str)

UNCURL_EXPORT
int32_t uncurl_read_header(struct uncurl_conn *ucc, int32_t timeout_ms);

UNCURL_EXPORT int32_t
uncurl_read_body_all(struct uncurl_conn *ucc, char **body, uint32_t *body_len,
	int32_t timeout_ms, size_t max_body);

UNCURL_EXPORT int32_t
uncurl_get_status_code(struct uncurl_conn *ucc, int32_t *status_code);

UNCURL_EXPORT int8_t
uncurl_check_header(struct uncurl_conn *ucc, char *name, char *subval);

UNCURL_EXPORT int32_t
uncurl_get_header(struct uncurl_conn *ucc, char *key, int32_t *val_int, char **val_str);


// Websockets

UNCURL_EXPORT int32_t
uncurl_ws_connect(struct uncurl_conn *ucc, char *path, char *origin,
	int32_t timeout_ms, int32_t *upgrade_status);

UNCURL_EXPORT int32_t
uncurl_ws_accept(struct uncurl_conn *ucc, char **origins,
	int32_t n_origins, bool secure, int32_t timeout_ms);

UNCURL_EXPORT int32_t
uncurl_ws_write(struct uncurl_conn *ucc, char *buf, uint32_t buf_len, uint8_t opcode);

UNCURL_EXPORT int32_t
uncurl_ws_read(struct uncurl_conn *ucc, char *buf, uint32_t buf_len, uint8_t *opcode, int32_t timeout_ms);

UNCURL_EXPORT int32_t
uncurl_ws_close(struct uncurl_conn *ucc, uint16_t status_code);


// Helpers

struct uncurl_info {
	int32_t scheme;
	char *host;
	uint16_t port;
	char *path;
};

UNCURL_EXPORT int32_t
uncurl_parse_url(char *url, struct uncurl_info *uci);

UNCURL_EXPORT void
uncurl_free_info(struct uncurl_info *uci);


#ifdef __cplusplus
}
#endif
