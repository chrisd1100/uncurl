#ifndef __UNCURL_H
#define __UNCURL_H

#if defined(UNCURL_MAKE_SHARED)
	#define DLL_EXPORT __declspec(dllexport)
#else
	#define DLL_EXPORT
#endif

#include <stdint.h>

#include "status.h"

struct uncurl;

#ifdef __cplusplus
extern "C" {
#endif

DLL_EXPORT int32_t uncurl_init(struct uncurl **uc_in);
DLL_EXPORT void uncurl_destroy(struct uncurl *uc);

DLL_EXPORT int32_t uncurl_connect(struct uncurl *uc, int32_t scheme, char *host, uint16_t port);
DLL_EXPORT void uncurl_close(struct uncurl *uc);

DLL_EXPORT void uncurl_set_request_header(struct uncurl *uc, ...);
DLL_EXPORT int32_t uncurl_send_request(struct uncurl *uc, char *method, char *path, char *body, uint32_t body_len);

DLL_EXPORT int32_t uncurl_read_response_header(struct uncurl *uc);
DLL_EXPORT int32_t uncurl_read_response_body(struct uncurl *uc, char **body, uint32_t *body_len);

DLL_EXPORT int32_t uncurl_get_status_code(struct uncurl *uc, int32_t *status_code);
DLL_EXPORT int32_t uncurl_parse_url(char *url, int32_t *scheme, char **host, uint16_t *port, char **path);

#ifdef __cplusplus
}
#endif

#endif
