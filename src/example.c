#include "uncurl/uncurl.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "../cacert/cacert.h"

#if defined(__WINDOWS__)
	#include <winsock2.h>
#endif

int32_t uncurl_get(struct uncurl *uc, char *url)
{
	int32_t r = UNCURL_ERR_DEFAULT;
	int32_t e;

	struct uncurl_conn *ucc = NULL;

	//parse the URL
	struct uncurl_info uci;
	e = uncurl_parse_url(url, &uci);

	if (e == UNCURL_OK) {
		//make the socket/TLS connection
		e = uncurl_connect(uc, &ucc, uci.scheme, uci.host, uci.port);
		if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}

		//set request headers
		uncurl_set_header_str(ucc, "User-Agent", "uncurl/0.0");
		uncurl_set_header_str(ucc, "Referer", "https://www.google.com/");

		//write the request header and body
		e = uncurl_write_header(ucc, "GET", uci.path);
		if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}

		//read the response header
		e = uncurl_read_header(ucc);
		if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}

		//get the status code
		int32_t status_code = 0;
		e = uncurl_get_status_code(ucc, &status_code);
		if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}

		//read the response body
		char *response = NULL;
		uint32_t response_len = 0;
		e = uncurl_read_body_all(ucc, &response, &response_len);
		if (e != UNCURL_OK) {r = e; goto uncurl_get_end;}

		fprintf(stderr, "%s : %d\n", url, status_code);
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

	if (argc < 2) {
		printf("Usage: uncurl [url]\n");
		return 0;
	}

	//windows global network init
	#if defined(__WINDOWS__)
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
	#endif

	//the master context
	struct uncurl *uc = NULL;
	e = uncurl_init(&uc);

	//if making HTTPS requests, set root certs from buffer or file
	uncurl_set_cacert(uc, (char **) CACERT, sizeof(CACERT) / sizeof(const char *));
	//uncurl_set_cacert_file(uc, "../cacert/cacert.pem");

	//set options here
	uncurl_set_option(uc, UNCURL_NOPT_CONNECT_TIMEOUT, 10000);

	if (e == UNCURL_OK) {
		e = uncurl_get(uc, argv[1]);
		if (e != UNCURL_OK) printf("uncurl_get error: %d\n", e);

		uncurl_destroy(uc);
	}


	return 0;
}
