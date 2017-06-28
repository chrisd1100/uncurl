#ifndef __UNCURL_H
#define __UNCURL_H

#if defined(UNCURL_MAKE_SHARED)
	#define UNCURL_EXPORT __declspec(dllexport)
#else
	#define UNCURL_EXPORT
#endif

#include <stdint.h>

#include "status.h"

struct uncurl;
struct uncurl_conn;

#ifdef __cplusplus
extern "C" {
#endif

UNCURL_EXPORT int32_t uncurl_init(struct uncurl **uc_in);
UNCURL_EXPORT int32_t uncurl_connect(struct uncurl *uc, struct uncurl_conn **ucc_in,
	int32_t scheme, char *host, uint16_t port);
//XXX uncurl_set_req_header_field(struct uncurl_conn *ucc, char *fmt, ...);
//XXX uncurl_send_req_header(struct uncurl_conn *ucc, char *method, char *path);
//XXX uncurl_send_req_body(struct uncurl_conn *ucc, char *body, uint32_t body_len);
UNCURL_EXPORT int32_t uncurl_read_response_header(struct uncurl_conn *ucc);
UNCURL_EXPORT int32_t uncurl_get_status_code(struct uncurl_conn *ucc, int32_t *status_code);
//XXX uncurl_read_res_body(struct uncurl_conn *ucc, char *buf, uint32_t buf_len, uint32_t *bytes_read);
//XXX uncurl_read_res_body_all(struct uncurl_conn *ucc, char **body, uint32_t *body_len);
UNCURL_EXPORT void uncurl_close(struct uncurl_conn *ucc);
UNCURL_EXPORT void uncurl_destroy(struct uncurl *uc);

//XXX uncurl_parse_url(char *url, struct uncurl_info *info);
//XXX uncurl_clear_req_header(struct uncurl_conn *ucc);
//XXX uncurl_get_res_header_field_int(struct uncurl_conn *ucc, char *name, int32_t *value);
//XXX uncurl_get_res_header_field_str(struct uncurl_conn *ucc, char *name, char **value);

UNCURL_EXPORT void uncurl_set_request_header(struct uncurl_conn *ucc, ...);
UNCURL_EXPORT int32_t uncurl_send_request(struct uncurl_conn *ucc, char *method, char *path, char *body, uint32_t body_len);
UNCURL_EXPORT int32_t uncurl_read_response_body(struct uncurl_conn *ucc, char **body, uint32_t *body_len);
UNCURL_EXPORT int32_t uncurl_parse_url(char *url, int32_t *scheme, char **host, uint16_t *port, char **path);

#ifdef __cplusplus
}
#endif

#endif
