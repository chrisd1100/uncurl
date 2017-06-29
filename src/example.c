#include "uncurl/uncurl.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(__WINDOWS__)
	#include <winsock2.h>
#endif

int32_t uncurl_get(struct uncurl *uc, char *url)
{
	int32_t status_code = 0;
	int32_t e;

	//parse the URL
	struct uncurl_info uci;
	e = uncurl_parse_url(url, &uci);

	if (e == UNCURL_OK) {
		struct uncurl_conn *ucc;

		//make the socket/TLS connection
		e = uncurl_connect(uc, &ucc, uci.scheme, uci.host, uci.port);
		if (e == UNCURL_OK) {

			//set request headers
			uncurl_set_header_str(ucc, "User-Agent", "uncurl/0.0");
			uncurl_set_header_str(ucc, "Referer", "https://www.google.com/");

			//write the request header and body
			e = uncurl_write_header(ucc, "GET", uci.path);
			if (e == UNCURL_OK) {

				//read the response header
				e = uncurl_read_header(ucc);
				if (e == UNCURL_OK) {
					//get the status code
					e = uncurl_get_status_code(ucc, &status_code);

					//read the response body
					char *response = NULL;
					uint32_t response_len = 0;
					e = uncurl_read_body_all(ucc, &response, &response_len);
					if (e == UNCURL_OK) {
						printf("%s\n", response);
						free(response);
					}
				}
			}

			uncurl_close(ucc);
		}
	}

	uncurl_free_info(&uci);

	return status_code;
}

int32_t main(int32_t argc, char **argv)
{
	int32_t e;

	argv, argc;

	//windows global network init
	#if defined(__WINDOWS__)
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
	#endif

	struct uncurl *uc = NULL;
	e = uncurl_init(&uc);

	if (e == UNCURL_OK) {

		//multiple requests can be made with the same uncurl handle
		uncurl_get(uc, "https://example.com");

		uncurl_destroy(uc);
	}


	return 0;
}
