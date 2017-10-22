#ifndef __UNCURL_H
#define __UNCURL_H

#if defined(UNCURL_MAKE_SHARED)
	#define UNCURL_EXPORT __declspec(dllexport)
#else
	#define UNCURL_EXPORT
#endif

#include <stdint.h>
#include <stddef.h>

#include "status.h"
#include "const.h"

struct uncurl_tls_ctx;
struct uncurl_conn;

struct uncurl_info {
	int32_t scheme;
	char *host;
	uint16_t port;
	char *path;
};

#ifdef __cplusplus
extern "C" {
#endif

/*** TLS CONTEXT **/
UNCURL_EXPORT void uncurl_free_tls_ctx(struct uncurl_tls_ctx *uc_tls);
UNCURL_EXPORT int32_t uncurl_new_tls_ctx(struct uncurl_tls_ctx **uc_tls_in);
UNCURL_EXPORT int32_t uncurl_set_cacert(struct uncurl_tls_ctx *uc_tls, char *cacert, size_t size);
UNCURL_EXPORT int32_t uncurl_set_cacert_file(struct uncurl_tls_ctx *uc_tls, char *cacert_file);

/*** CONNECTION ***/
UNCURL_EXPORT struct uncurl_conn *uncurl_new_conn(struct uncurl_conn *parent);
UNCURL_EXPORT int32_t uncurl_connect(struct uncurl_tls_ctx *uc_tls, struct uncurl_conn *ucc,
	int32_t scheme, char *host, uint16_t port);
UNCURL_EXPORT int32_t uncurl_listen(struct uncurl_conn *ucc, uint16_t port);
UNCURL_EXPORT int32_t uncurl_accept(struct uncurl_tls_ctx *uc_tls, struct uncurl_conn *ucc,
	struct uncurl_conn **ucc_new_in, int32_t scheme);
UNCURL_EXPORT void uncurl_close(struct uncurl_conn *ucc);
UNCURL_EXPORT void uncurl_set_option(struct uncurl_conn *ucc, int32_t opt, int32_t val);

/*** REQUEST ***/
UNCURL_EXPORT void uncurl_set_header_str(struct uncurl_conn *ucc, char *name, char *value);
UNCURL_EXPORT void uncurl_set_header_int(struct uncurl_conn *ucc, char *name, int32_t value);
UNCURL_EXPORT void uncurl_free_header(struct uncurl_conn *ucc);
UNCURL_EXPORT int32_t uncurl_write_header(struct uncurl_conn *ucc, char *str0, char *str1, int32_t type);
UNCURL_EXPORT int32_t uncurl_write_body(struct uncurl_conn *ucc, char *body, uint32_t body_len);

/*** RESPONSE ***/
UNCURL_EXPORT int32_t uncurl_read_header(struct uncurl_conn *ucc);
UNCURL_EXPORT int32_t uncurl_read_body_all(struct uncurl_conn *ucc, char **body, uint32_t *body_len);
//XXX uncurl_read_body(struct uncurl_conn *ucc, char *buf, uint32_t buf_len, uint32_t *bytes_read);
UNCURL_EXPORT int32_t uncurl_get_status_code(struct uncurl_conn *ucc, int32_t *status_code);
UNCURL_EXPORT int8_t uncurl_check_header(struct uncurl_conn *ucc, char *name, char *subval);
UNCURL_EXPORT int32_t uncurl_get_header(struct uncurl_conn *ucc, char *key, int32_t *val_int, char **val_str);
#define uncurl_get_header_int(ucc, key, val_int) uncurl_get_header(ucc, key, val_int, NULL)
#define uncurl_get_header_str(ucc, key, val_str) uncurl_get_header(ucc, key, NULL, val_str)

/*** WEBSOCKETS ***/
UNCURL_EXPORT int32_t uncurl_ws_connect(struct uncurl_conn *ucc, char *path, char *origin);
UNCURL_EXPORT int32_t uncurl_ws_accept(struct uncurl_conn *ucc);
UNCURL_EXPORT int32_t uncurl_ws_write(struct uncurl_conn *ucc, char *buf, uint32_t buf_len, int32_t opcode);
UNCURL_EXPORT int32_t uncurl_ws_poll(struct uncurl_conn *ucc, int32_t timeout_ms);
UNCURL_EXPORT void uncurl_ws_get_socket(struct uncurl_conn *ucc, void *socket);
UNCURL_EXPORT int32_t uncurl_ws_read(struct uncurl_conn *ucc, char *buf, uint32_t buf_len, uint8_t *opcode);
#define uncurl_ws_close(ucc) uncurl_ws_write(ucc, NULL, 0, UNCURL_WSOP_CLOSE)

/*** HELPERS ***/
UNCURL_EXPORT int32_t uncurl_parse_url(char *url, struct uncurl_info *uci);
UNCURL_EXPORT void uncurl_free_info(struct uncurl_info *uci);

#ifdef __cplusplus
}
#endif

#endif
