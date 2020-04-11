#include "uncurl/uncurl.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(__WINDOWS__)
	#include <winsock2.h>
#endif

static void client(void)
{
	struct uncurl_tls_ctx *uc_tls = NULL;
	uncurl_new_tls_ctx(&uc_tls);

	struct uncurl_conn *ucc = uncurl_new_conn();
	uncurl_connect(uc_tls, ucc, UNCURL_WS, "54.242.16.17", 5250, true, NULL, 0, 10000);

	int32_t status = -1;
	uncurl_set_header_str(ucc, "User-Agent", "uncurl/0.0");
	uncurl_ws_connect(ucc, "/", "https://cdd.com", 10000, &status);

	int32_t buf_len = 1024;
	char *buf = calloc(1, buf_len);

	while (1) {
		uint8_t opcode = 0;
		uncurl_ws_write(ucc, "chris", 5, UNCURL_WSOP_TEXT);
		uncurl_ws_read(ucc, buf, buf_len, &opcode, 10000);
		printf("%u %s\n", opcode, buf);
		if (opcode != 1) break;
	}

	uncurl_ws_close(ucc, 1000);
}

static void server(void)
{
	struct uncurl_conn *ucc = uncurl_new_conn();
	uncurl_listen(ucc, "127.0.0.1", 5250);

	printf("listen\n");

	while (1) {
		int32_t e;

		struct uncurl_conn *client = NULL;
		e = uncurl_accept(NULL, ucc, &client, UNCURL_WS, 10000);
		if (e == UNCURL_OK) {
			printf("accept\n");

			e = uncurl_ws_accept(client, NULL, 0, false, 10000);
			printf("uncurl_ws_accept: %d\n", e);

			char buf[128];
			memset(buf, 0, 128);
			uint8_t opcode = 0;
			e = uncurl_ws_read(client, buf, 128, &opcode, 10000);
			printf("uncurl_ws_read: %d\n", e);
			printf("%u %s\n", opcode, buf);

			char *msg = "Reply from C!";
			uncurl_ws_write(client, msg, (uint32_t) strlen(msg), UNCURL_WSOP_TEXT);

			uncurl_ws_close(client, 1000);
			uncurl_close(client);
		}

		printf("timeout\n");
	}

	uncurl_close(ucc);
}

int32_t main(int32_t argc, char **argv)
{
	argc, argv;

	//windows global network init
	#if defined(__WINDOWS__)
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
	#endif

	client();

	return 0;
}
