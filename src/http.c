#include "http.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "uncurl/status.h"
#include "uncurl/const.h"

#if defined(__WINDOWS__)
	#define strtok_r(a, b, c) strtok_s(a, b, c)
	#define strdup(a) _strdup(a)
#endif

struct http_pair {
	char *key;
	char *val;
};

struct http_header {
	char *first_line;
	struct http_pair *pairs;
	uint32_t npairs;
};

static const char HTTP_REQUEST_FMT[] =
	"%s %s HTTP/1.1\r\n"
	"Host: %s\r\n"
	"%s"
	"\r\n";

static const char HTTP_RESPONSE_FMT[] =
	"HTTP/1.1 %s %s\r\n"
	"%s"
	"\r\n";

char *http_request(char *method, char *host, char *path, char *fields)
{
	if (!fields) fields = "";

	size_t len = sizeof(HTTP_REQUEST_FMT) + strlen(method) + strlen(host) +
		strlen(path) + strlen(fields) + 1;
	char *final = malloc(len);

	snprintf(final, len, HTTP_REQUEST_FMT, method, path, host, fields);

	return final;
}

char *http_response(char *code, char *msg, char *fields)
{
	if (!fields) fields = "";

	size_t len = sizeof(HTTP_RESPONSE_FMT) + strlen(code) + strlen(msg) +
		strlen(fields) + 1;
	char *final = malloc(len);

	snprintf(final, len, HTTP_RESPONSE_FMT, code, msg, fields);

	return final;
}

char *http_lc(char *str)
{
	for (int32_t i = 0; str[i]; i++) str[i] = (char) tolower(str[i]);

	return str;
}

struct http_header *http_parse_header(char *header)
{
	char *line, *ptr = NULL;

	struct http_header *h = calloc(1, sizeof(struct http_header));

	//http header lines are delimited by "\r\n"
	line = strtok_r(header, "\r\n", &ptr);

	for (int8_t first = 1; line; first = 0) {

		//first line is special and is stored seperately
		if (first) {
			h->first_line = strdup(line);

		//all lines following the first are in the "key: val" format
		} else {

			char *delim = strpbrk(line, ": ");
			if (delim) {

				//make room for key:val pairs
				h->pairs = realloc(h->pairs, sizeof(struct http_pair) * (h->npairs + 1));

				//place a null character to separate the line
				char save = delim[0];
				delim[0] = '\0';

				//save the key and remove the null character
				h->pairs[h->npairs].key = strdup(http_lc(line));
				delim[0] = save;

				//advance the val past whitespace or the : character
				while (*delim && (*delim == ':' || *delim == ' ')) delim++;

				//store the val and increment npairs
				h->pairs[h->npairs].val = strdup(delim);
				h->npairs++;
			}
		}

		line = strtok_r(NULL, "\r\n", &ptr);
	}

	return h;
}

void http_free_header(struct http_header *h)
{
	if (!h) return;

	for (uint32_t x = 0; x < h->npairs; x++) {
		free(h->pairs[x].key);
		free(h->pairs[x].val);
	}

	free(h->first_line);
	free(h->pairs);
	free(h);
}

int32_t http_get_header(struct http_header *h, char *key, int32_t *val_int, char **val_str)
{
	int32_t r = UNCURL_ERR_DEFAULT;

	char *lc_key = strdup(key);

	//loop through header pairs and strcmp the key
	for (uint32_t x = 0; x < h->npairs; x++) {
		if (!strcmp(http_lc(lc_key), h->pairs[x].key)) {

			//set val to key str directly if requesting string
			if (val_str) {
				*val_str = h->pairs[x].val;
				r = UNCURL_OK;

			//convert val to int if requesting int
			} else if (val_int) {
				char *endptr = h->pairs[x].val;
				*val_int = strtol(h->pairs[x].val, &endptr, 10);

				if (endptr == h->pairs[x].val) {
					r = UNCURL_HTTP_ERR_PARSE_HEADER;
				} else r = UNCURL_OK;
			}

			goto http_get_header_end;
		}
	}

	r = UNCURL_HTTP_ERR_NOT_FOUND;

	http_get_header_end:

	free(lc_key);

	return r;
}

int32_t http_get_status_code(struct http_header *h, int32_t *status_code)
{
	int32_t r = UNCURL_ERR_DEFAULT;
	char *tok, *ptr = NULL;

	char *tmp_first_line = strdup(h->first_line);

	tok = strtok_r(tmp_first_line, " ", &ptr);
	if (!tok) {r = UNCURL_HTTP_ERR_PARSE_STATUS; goto http_get_status_code_end;};

	tok = strtok_r(NULL, " ", &ptr);
	if (!tok) {r = UNCURL_HTTP_ERR_PARSE_STATUS; goto http_get_status_code_end;};

	*status_code = strtol(tok, NULL, 10);

	r = UNCURL_OK;

	http_get_status_code_end:

	free(tmp_first_line);

	return r;
}

char *http_set_header(char *header, char *name, int32_t type, void *value)
{
	size_t val_len = (type == HTTP_INT) ? 10 : strlen((char *) value);
	size_t len = header ? strlen(header) : 0;
	size_t new_len = len + strlen(name) + 2 + val_len + 3; //existing len, name len, ": ", val_len, "\r\n\0"

	header = realloc(header, new_len);

	if (type == HTTP_INT) {
		int32_t *val_int = (int32_t *) value;
		snprintf(header + len, new_len, "%s: %d\r\n", name, *val_int);

	} else if (type == HTTP_STRING) {
		snprintf(header + len, new_len, "%s: %s\r\n", name, (char *) value);
	}

	return header;
}

int32_t http_parse_url(char *url_in, int32_t *scheme, char **host, uint16_t *port, char **path)
{
	int32_t r = UNCURL_ERR_DEFAULT;
	char *tok, *ptr = NULL;
	char *tok2, *ptr2 = NULL;

	char *url = strdup(url_in);

	*host = NULL;
	*path = NULL;
	*scheme = UNCURL_NONE;
	*port = 0;

	//scheme
	tok = strtok_r(url, ":", &ptr);
	if (!tok) {r = UNCURL_HTTP_ERR_PARSE_SCHEME; goto http_parse_url_end;}
	http_lc(tok);
	if (!strcmp(tok, "https")) {
		*scheme = UNCURL_HTTPS;
	} else if (!strcmp(tok, "http")) {
		*scheme = UNCURL_HTTP;
	} else if (!strcmp(tok, "ws")) {
		*scheme = UNCURL_WS;
	} else if (!strcmp(tok, "wss")) {
		*scheme = UNCURL_WSS;
	} else {r = UNCURL_HTTP_ERR_PARSE_SCHEME; goto http_parse_url_end;}

	//host + port
	tok = strtok_r(NULL, "/", &ptr);
	if (!tok) {r = UNCURL_HTTP_ERR_PARSE_HOST; goto http_parse_url_end;}

	//try to find a port
	*host = strdup(tok);
	tok2 = strtok_r(*host, ":", &ptr2);
	tok2 = strtok_r(NULL, ":", &ptr2);
	if (tok2) { //we have a port
		*port = (uint16_t) atoi(tok2);
	} else {
		*port = (*scheme == UNCURL_HTTPS) ? UNCURL_PORT_S : UNCURL_PORT;
	}

	//path
	tok = strtok_r(NULL, "", &ptr);
	if (!tok) tok = "";
	size_t path_len = strlen(tok) + 2;
	*path = malloc(strlen(tok) + 2);
	snprintf(*path, path_len, "/%s", tok);

	r = UNCURL_OK;

	http_parse_url_end:

	free(url);

	return r;
}
