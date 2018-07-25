#include "net.h"

#include <stdlib.h>
#include <string.h>

#include "uncurl/status.h"

#if defined(__WINDOWS__)
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

#elif defined(__UNIXY__)
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

#define net_set_sockopt(s, level, opt_name, opt) \
	setsockopt(s, level, opt_name, (const char *) &opt, sizeof(opt))

struct net_context {
	struct net_opts opts;
	struct sockaddr_in addr;
	SOCKET s;
};

static int32_t net_set_nonblocking(SOCKET s)
{
	#if defined(__WINDOWS__)
		u_long mode = 1;
		return ioctlsocket(s, FIONBIO, &mode);

	#elif defined(__UNIXY__)
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

int32_t net_error()
{
	return socket_error();
}

int32_t net_would_block()
{
	return SOCKET_WOULD_BLOCK;
}

int32_t net_in_progress()
{
	return SOCKET_IN_PROGRESS;
}

int32_t net_bad_fd()
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

static void net_set_options(SOCKET s, struct net_opts *opts)
{
	net_set_sockopt(s, SOL_SOCKET, SO_RCVBUF, opts->read_buf);
	net_set_sockopt(s, SOL_SOCKET, SO_SNDBUF, opts->write_buf);
	net_set_sockopt(s, SOL_SOCKET, SO_KEEPALIVE, opts->keepalive);
	net_set_sockopt(s, IPPROTO_TCP, TCP_NODELAY, opts->tcp_nodelay);
	net_set_sockopt(s, SOL_SOCKET, SO_REUSEADDR, opts->reuseaddr);
}

void net_default_opts(struct net_opts *opts)
{
	opts->read_timeout = 5000;
	opts->connect_timeout = 5000;
	opts->accept_timeout = 5000;
	opts->read_buf = 64 * 1024;
	opts->write_buf = 64 * 1024;
	opts->keepalive = 1;
	opts->tcp_nodelay = 1;
	opts->reuseaddr = 1;
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
	int32_t r = UNCURL_ERR_DEFAULT;
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

	r = UNCURL_OK;

	except:

	if (servinfo) freeaddrinfo(servinfo);

	return r;
}

static int32_t net_setup(struct net_context *nc, char *ip4, uint16_t port, struct net_opts *opts)
{
	//set options
	memcpy(&nc->opts, opts, sizeof(struct net_opts));

	nc->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (nc->s == INVALID_SOCKET) return UNCURL_NET_ERR_SOCKET;

	//set options
	net_set_options(nc->s, &nc->opts);

	//put socket in nonblocking mode, allows us to implement connection timeout
	int32_t e = net_set_nonblocking(nc->s);
	if (e != 0) return UNCURL_NET_ERR_BLOCKMODE;

	memset(&nc->addr, 0, sizeof(struct sockaddr_in));
	nc->addr.sin_family = AF_INET;
	nc->addr.sin_port = htons(port);

	if (ip4) {
		inet_pton(AF_INET, ip4, &nc->addr.sin_addr);
	} else {
		nc->addr.sin_addr.s_addr = INADDR_ANY;
	}

	return UNCURL_OK;
}

int32_t net_connect(struct net_context **nc_in, char *ip4, uint16_t port, struct net_opts *opts)
{
	int32_t r = UNCURL_ERR_DEFAULT;

	int32_t timeout_rem = opts->connect_timeout;
	int32_t interval = 5000;
	int32_t this_try = interval;

	do {
		int8_t do_wait = 0;
		struct net_context *nc = *nc_in = calloc(1, sizeof(struct net_context));

		int32_t e = net_setup(nc, ip4, port, opts);
		if (e != UNCURL_OK) {r = e; do_wait = 1; goto except;}

		//initiate the socket connection
		e = connect(nc->s, (struct sockaddr *) &nc->addr, sizeof(struct sockaddr_in));

		//initial socket state must be 'in progress' for nonblocking connect
		if (net_error() != net_in_progress()) {r = UNCURL_NET_ERR_CONNECT; do_wait = 1; goto except;}

		//wait for socket to be ready to write
		e = net_poll(nc, NET_POLLOUT, this_try);
		if (e == UNCURL_NET_ERR_TIMEOUT) {r = e; timeout_rem -= this_try; goto except;}
		if (e != UNCURL_OK) {r = e; do_wait = 1; goto except;}

		//if the socket is clear of errors, we made a successful connection
		if (net_get_error(nc->s) != 0) {r = UNCURL_NET_ERR_CONNECT_FINAL; do_wait = 1; goto except;}

		//success
		return UNCURL_OK;

		except:

		net_close(nc);
		*nc_in = NULL;

		if (do_wait) {
			timeout_rem -= this_try - interval;
			if (timeout_rem > 0)
				usleep(1000 * this_try);
		}

		this_try += interval;

	} while (timeout_rem > 0);

	return r;
}

int32_t net_listen(struct net_context **nc_in, char *bind_ip4, uint16_t port, struct net_opts *opts)
{
	int32_t r = UNCURL_ERR_DEFAULT;

	struct net_context *nc = *nc_in = calloc(1, sizeof(struct net_context));

	int32_t e = net_setup(nc, bind_ip4, port, opts);
	if (e != UNCURL_OK) {r = e; goto except;}

	e = bind(nc->s, (struct sockaddr *) &nc->addr, sizeof(struct sockaddr_in));
	if (e != 0) {r = UNCURL_NET_ERR_BIND; goto except;}

	e = listen(nc->s, SOMAXCONN);
	if (e != 0) {r = UNCURL_NET_ERR_LISTEN; goto except;}

	return UNCURL_OK;

	except:

	net_close(nc);
	*nc_in = NULL;

	return r;
}

int32_t net_accept(struct net_context *nc, struct net_context **nc_in)
{
	int32_t e = net_poll(nc, NET_POLLIN, nc->opts.accept_timeout);

	if (e == UNCURL_OK) {
		SOCKET s = accept(nc->s, NULL, NULL);
		if (s == INVALID_SOCKET) return UNCURL_NET_ERR_ACCEPT;

		e = net_set_nonblocking(s);
		if (e != 0) return UNCURL_NET_ERR_BLOCKMODE;

		net_set_options(s, &nc->opts);

		struct net_context *new = *nc_in = calloc(1, sizeof(struct net_context));
		memcpy(new, nc, sizeof(struct net_context));
		new->s = s;

		return UNCURL_OK;
	}

	return e;
}

int32_t net_write(void *ctx, char *buf, uint32_t buf_size)
{
	struct net_context *nc = (struct net_context *) ctx;

	uint32_t total = 0;

	while (total < buf_size) {
		int32_t n = send(nc->s, buf + total, buf_size - total, 0);
		if (n <= 0) return UNCURL_NET_ERR_WRITE;
		total += n;
	}

	return UNCURL_OK;
}

int32_t net_read(void *ctx, char *buf, uint32_t buf_size)
{
	struct net_context *nc = (struct net_context *) ctx;

	uint32_t total = 0;

	while (total < buf_size) {
		int32_t e = net_poll(nc, NET_POLLIN, nc->opts.read_timeout);
		if (e != UNCURL_OK) return e;

		int32_t n = recv(nc->s, buf + total, buf_size - total, 0);
		if (n <= 0) {
			if (net_error() == net_would_block()) continue;
			if (n == 0) return UNCURL_NET_ERR_CLOSED;
			return UNCURL_NET_ERR_READ;
		}

		total += n;
	}

	return UNCURL_OK;
}

void net_get_opts(struct net_context *nc, struct net_opts *opts)
{
	memcpy(opts, &nc->opts, sizeof(struct net_opts));
}

void net_get_socket(struct net_context *nc, void *socket)
{
	SOCKET *s = (SOCKET *) socket;

	*s = nc->s;
}
