#ifndef __HTTP_H
#define __HTTP_H

#include <stdint.h>

struct http_header;

#ifdef __cplusplus
extern "C" {
#endif

char *http_request(char *method, char *host, char *path, char *header, uint32_t body_len);
char *http_lc(char *str);
struct http_header *http_parse_header(char *header);
void http_free_header(struct http_header *h);
int32_t http_get_header_int(struct http_header *h, char *key, int32_t *val_int);
int32_t http_get_header_str(struct http_header *h, char *key, char **val_str);
int32_t http_get_status_code(struct http_header *h, int32_t *status_code);
char *http_request_header(char *header, char *field);
int32_t http_parse_url(char *url_in, int32_t *scheme, char **host, uint16_t *port, char **path);

#ifdef __cplusplus
}
#endif

#endif
