// Copyright (c) 2017-2020 Christopher D. Dickson <cdd@matoya.group>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "net.h"

#include <stdlib.h>
#include <string.h>

#include "uncurl.h"

#if defined(_WIN32)
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#define SHUT_RDWR 2
	#define poll WSAPoll
	#define usleep(ns) Sleep((ns) / 1000000)
	#define socket_error() WSAGetLastError()
	#define SOCKET_WOULD_BLOCK WSAEWOULDBLOCK
	#define SOCKET_IN_PROGRESS WSAEWOULDBLOCK
	#define SOCKET_BAD_FD WSAENOTSOCK
	typedef int32_t socklen_t;

#else
	#include <fcntl.h>
	#include <unistd.h>
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <netinet/tcp.h>
	#include <poll.h>
	#include <errno.h>
	#include <netdb.h>
	#define socket_error() errno
	#define SOCKET_WOULD_BLOCK EAGAIN
	#define SOCKET_IN_PROGRESS EINPROGRESS
	#define SOCKET_BAD_FD EBADF
	#define INVALID_SOCKET -1
	#define closesocket close
	typedef int32_t SOCKET;
#endif

struct net_context {
	SOCKET s;
};

static int32_t net_set_nonblocking(SOCKET s)
{
	#if defined(_WIN32)
		u_long mode = 1;
		return ioctlsocket(s, FIONBIO, &mode);

	#else
		return fcntl(s, F_SETFL, O_NONBLOCK);
	#endif
}

static int32_t net_get_error(SOCKET s)
{
	int32_t opt = 0;
	socklen_t size = sizeof(int32_t);
	int32_t e = getsockopt(s, SOL_SOCKET, SO_ERROR, (char *) &opt, &size);

	return e ? e : opt;
}

int32_t net_error(void)
{
	return socket_error();
}

int32_t net_would_block(void)
{
	return SOCKET_WOULD_BLOCK;
}

int32_t net_in_progress(void)
{
	return SOCKET_IN_PROGRESS;
}

int32_t net_bad_fd(void)
{
	return SOCKET_BAD_FD;
}

void net_close(struct net_context *nc)
{
	if (!nc) return;

	if (nc->s != INVALID_SOCKET) {
		shutdown(nc->s, SHUT_RDWR);
		closesocket(nc->s);
	}

	free(nc);
}

static void net_set_sockopt(SOCKET s, int32_t level, int32_t opt_name, int32_t val)
{
	setsockopt(s, level, opt_name, (const char *) &val, sizeof(int32_t));
}

static void net_set_options(SOCKET s)
{
	net_set_sockopt(s, SOL_SOCKET, SO_RCVBUF, 64 * 1024);
	net_set_sockopt(s, SOL_SOCKET, SO_SNDBUF, 64 * 1024);
	net_set_sockopt(s, SOL_SOCKET, SO_KEEPALIVE, 1);
	net_set_sockopt(s, IPPROTO_TCP, TCP_NODELAY, 1);
	net_set_sockopt(s, SOL_SOCKET, SO_REUSEADDR, 1);
}

int32_t net_poll(struct net_context *nc, int32_t net_event, int32_t timeout_ms)
{
	struct pollfd fd;
	memset(&fd, 0, sizeof(struct pollfd));

	fd.fd = nc->s;
	fd.events = (net_event == NET_POLLIN) ? POLLIN : (net_event == NET_POLLOUT) ? POLLOUT : 0;

	int32_t e = poll(&fd, 1, timeout_ms);

	return (e == 0) ? UNCURL_NET_ERR_TIMEOUT : (e < 0) ? UNCURL_NET_ERR_POLL : UNCURL_OK;
}

int32_t net_getip4(char *host, char *ip4, uint32_t ip4_len)
{
	int32_t r = UNCURL_OK;
	struct addrinfo hints;
	struct addrinfo *servinfo = NULL;

	//set to request only IP4, TCP
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	int32_t e = getaddrinfo(host, NULL, &hints, &servinfo);
	if (e != 0) {r = UNCURL_NET_ERR_RESOLVE; goto except;}

	//attempt to convert the first returned address into string
	struct sockaddr_in *addr = (struct sockaddr_in *) servinfo->ai_addr;
	const char *dst = inet_ntop(AF_INET, &addr->sin_addr, ip4, ip4_len);
	if (!dst) {r = UNCURL_NET_ERR_NTOP; goto except;}

	except:

	if (servinfo)
		freeaddrinfo(servinfo);

	return r;
}

static int32_t net_setup(struct net_context *nc, char *ip4, uint16_t port, struct sockaddr_in *addr)
{
	nc->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (nc->s == INVALID_SOCKET) return UNCURL_NET_ERR_SOCKET;

	//put socket in nonblocking mode, allows us to implement connection timeout
	int32_t e = net_set_nonblocking(nc->s);
	if (e != 0) return UNCURL_NET_ERR_BLOCKMODE;

	net_set_options(nc->s);

	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);

	if (ip4) {
		inet_pton(AF_INET, ip4, &addr->sin_addr);
	} else {
		addr->sin_addr.s_addr = INADDR_ANY;
	}

	return UNCURL_OK;
}

int32_t net_connect(struct net_context **nc_out, char *ip4, uint16_t port, int32_t timeout_ms)
{
	int32_t r = UNCURL_OK;

	struct net_context *nc = *nc_out = calloc(1, sizeof(struct net_context));

	struct sockaddr_in addr;
	int32_t e = net_setup(nc, ip4, port, &addr);
	if (e != UNCURL_OK) {r = e; goto except;}

	//initiate the socket connection
	e = connect(nc->s, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));

	//initial socket state must be 'in progress' for nonblocking connect
	if (net_error() != net_in_progress()) {r = UNCURL_NET_ERR_CONNECT; goto except;}

	//wait for socket to be ready to write
	e = net_poll(nc, NET_POLLOUT, timeout_ms);
	if (e != UNCURL_OK) {r = e; goto except;}

	//if the socket is clear of errors, we made a successful connection
	if (net_get_error(nc->s) != 0) {r = UNCURL_NET_ERR_CONNECT_FINAL; goto except;}

	except:

	if (r != UNCURL_OK) {
		net_close(nc);
		*nc_out = NULL;
	}

	return r;
}

int32_t net_listen(struct net_context **nc_out, char *bind_ip4, uint16_t port)
{
	int32_t r = UNCURL_OK;

	struct net_context *nc = *nc_out = calloc(1, sizeof(struct net_context));

	struct sockaddr_in addr;
	int32_t e = net_setup(nc, bind_ip4, port, &addr);
	if (e != UNCURL_OK) {r = e; goto except;}

	e = bind(nc->s, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
	if (e != 0) {r = UNCURL_NET_ERR_BIND; goto except;}

	e = listen(nc->s, SOMAXCONN);
	if (e != 0) {r = UNCURL_NET_ERR_LISTEN; goto except;}

	except:

	if (r != UNCURL_OK) {
		net_close(nc);
		*nc_out = NULL;
	}

	return r;
}

int32_t net_accept(struct net_context *nc, struct net_context **child, int32_t timeout_ms)
{
	int32_t e = net_poll(nc, NET_POLLIN, timeout_ms);

	if (e == UNCURL_OK) {
		SOCKET s = accept(nc->s, NULL, NULL);
		if (s == INVALID_SOCKET) return UNCURL_NET_ERR_ACCEPT;

		e = net_set_nonblocking(s);
		if (e != 0) return UNCURL_NET_ERR_BLOCKMODE;

		net_set_options(s);

		struct net_context *new = *child = calloc(1, sizeof(struct net_context));
		new->s = s;

		return UNCURL_OK;
	}

	return e;
}

int32_t net_write(void *ctx, char *buf, size_t size)
{
	struct net_context *nc = (struct net_context *) ctx;

	for (size_t total = 0; total < size;) {
		int32_t n = send(nc->s, buf + total, (int32_t) (size - total), 0);
		if (n <= 0) return UNCURL_NET_ERR_WRITE;

		total += n;
	}

	return UNCURL_OK;
}

int32_t net_read(void *ctx, char *buf, size_t size, int32_t timeout_ms)
{
	struct net_context *nc = (struct net_context *) ctx;

	for (size_t total = 0; total < size;) {
		int32_t e = net_poll(nc, NET_POLLIN, timeout_ms);
		if (e != UNCURL_OK) return e;

		int32_t n = recv(nc->s, buf + total, (int32_t) (size - total), 0);
		if (n <= 0) {
			if (net_error() == net_would_block()) continue;

			return (n == 0) ? UNCURL_NET_ERR_CLOSED : UNCURL_NET_ERR_READ;
		}

		total += n;
	}

	return UNCURL_OK;
}

void net_get_socket(struct net_context *nc, void *socket)
{
	SOCKET *s = (SOCKET *) socket;

	*s = nc->s;
}
