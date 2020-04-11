#include "uncurl/uncurl.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "../cacert/cacert.h"

#if defined(__WINDOWS__)
	#include <winsock2.h>
#endif

int32_t uncurl_request(struct uncurl_tls_ctx *uc_tls, char *method, char *url, char *body,
	char *proxy_host, uint16_t proxy_port)
{
	int32_t r = UNCURL_ERR_DEFAULT;
	int32_t e;

	struct uncurl_conn *ucc = NULL;

	//parse the URL
	struct uncurl_info uci;
	e = uncurl_parse_url(url, &uci);

	if (e == UNCURL_OK) {
		//create connection object
		ucc = uncurl_new_conn();

		//make the socket/TLS connection
		e = uncurl_connect(uc_tls, ucc, uci.scheme, uci.host, uci.port, true,
			proxy_host, proxy_port, 10000);
		if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}

		//set request headers
		uncurl_set_header_str(ucc, "User-Agent", "uncurl/0.0");
		if (body && body[0]) {
			uncurl_set_header_str(ucc, "Content-Type", "application/json");
			uncurl_set_header_int(ucc, "Content-Length", (uint32_t) strlen(body));
		}

		//write the request header and body
		e = uncurl_write_header(ucc, method, uci.path, UNCURL_REQUEST);
		if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}

		//write body
		if (body && body[0]) {
			e = uncurl_write_body(ucc, body, (uint32_t) strlen(body));
			if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}
		}

		//read the response header
		e = uncurl_read_header(ucc, 10000);
		if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}

		//get the status code
		int32_t status_code = 0;
		e = uncurl_get_status_code(ucc, &status_code);
		if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}

		//read the response body
		char *response = NULL;
		uint32_t response_len = 0;
		e = uncurl_read_body_all(ucc, &response, &response_len, 10000, 1024 * 1024 * 10);
		if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}

		fprintf(stderr, "%s : %d\n\n", url, status_code);
		fprintf(stdout, "%s\n", response);
		free(response);

		r = UNCURL_OK;

		uncurl_get_end:

		uncurl_close(ucc);

	} else r = e;

	uncurl_free_info(&uci);

	return r;
}

int32_t main(int32_t argc, char **argv)
{
	int32_t e;

	if (argc < 3) {
		printf("Usage: uncurl method url [body] [proxy-host] [proxy-port]\n");
		return 0;
	}

	//windows global network init
	#if defined(__WINDOWS__)
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
	#endif

	//the master context
	struct uncurl_tls_ctx *uc_tls = NULL;
	e = uncurl_new_tls_ctx(&uc_tls);

	if (e == UNCURL_OK) {
		//root CA certs
		uncurl_set_cacert(uc_tls, (char *) CACERT, sizeof(CACERT));

		uint16_t proxy_port = 0;
		if (argc > 5)
			proxy_port = (uint16_t) atoi(argv[5]);

		e = uncurl_request(uc_tls, argv[1], argv[2], (argc > 3) ? argv[3] : NULL,
			argc > 4 ? argv[4] : NULL, proxy_port);
		if (e != UNCURL_OK) printf("uncurl_get error: %d\n", e);

		uncurl_free_tls_ctx(uc_tls);
	}


	return 0;
}
