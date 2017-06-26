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
	uint16_t port;
	int32_t scheme;
	char *host = NULL, *path = NULL;
	e = uncurl_parse_url(url, &scheme, &host, &port, &path);
	if (e == UNCURL_OK) {

		//make the socket/TLS connection
		e = uncurl_connect(uc, scheme, host, port);
		if (e == UNCURL_OK) {

			//set request headers
			uncurl_set_request_header(uc,
				"User-Agent: uncurl/0.0",
				"Referer: https://www.google.com/",
			NULL);

			//send the request header and body
			e = uncurl_send_request(uc, "GET", path, NULL, 0);
			if (e == UNCURL_OK) {

				//read the response header
				e = uncurl_read_response_header(uc);
				if (e == UNCURL_OK) {
					//get the status code
					e = uncurl_get_status_code(uc, &status_code);

					//read the response body
					char *response = NULL;
					uint32_t response_len = 0;
					e = uncurl_read_response_body(uc, &response, &response_len);
					if (e == UNCURL_OK) {
						printf("%s\n", response);
						free(response);
					}
				}
			}

			uncurl_close(uc);
		}
	}

	free(host);
	free(path);

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
		uncurl_get(uc, "https://www.google.com");

		uncurl_destroy(uc);
	}


	return 0;
}
