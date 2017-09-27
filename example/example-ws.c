#include "uncurl/uncurl.h"

#include <stdlib.h>
#include <stdio.h>

#if defined(__WINDOWS__)
	#include <winsock2.h>
#endif

int32_t main(int32_t argc, char **argv)
{
	argc, argv;

	//windows global network init
	#if defined(__WINDOWS__)
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
	#endif

	struct uncurl_tls_ctx *uc_tls = NULL;
	uncurl_new_tls_ctx(&uc_tls);

	struct uncurl_conn *ucc = uncurl_new_conn();
	uncurl_connect(uc_tls, ucc, UNCURL_WS, "54.242.16.17", 5250);

	uncurl_set_header_str(ucc, "User-Agent", "uncurl/0.0");
	uncurl_ws_connect(ucc, "/");

	int32_t buf_len = 1024;
	char *buf = calloc(1, buf_len);

	while (1) {
		uint8_t opcode = 0;
		uncurl_ws_write(ucc, "chris", 5, UNCURL_WSOP_TEXT);
		uncurl_ws_read(ucc, buf, buf_len, &opcode);
		printf("%u %s\n", opcode, buf);
		if (opcode != 1) break;
	}

	uncurl_ws_close(ucc);

	return 0;
}
