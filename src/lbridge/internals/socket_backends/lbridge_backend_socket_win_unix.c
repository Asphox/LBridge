// Feature test macros for POSIX functions (getaddrinfo, etc.)
// Must be defined before including any system headers
#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#endif

#include "../lbridge_internal.h"
#include "lbridge_socket_win_unix.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(LBRIDGE_ENABLE_TCP_CLIENT)

bool lbridge_tcp_client_impl_connect(struct lbridge_client* p_client, void* arg)
{
	INIT_SOCKET_IF_NEEDED();
	p_client->connection.as_ptr = NULL;
	const struct lbridge_tcp_connection_data* connection_data = arg;

	struct addrinfo hints, *result, *rp;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	char port_str[6];
	snprintf(port_str, sizeof(port_str), "%u", connection_data->port);

	if (getaddrinfo(connection_data->host, port_str, &hints, &result) != 0)
	{
		p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
		return false;
	}

	socket_t s = INVALID_SOCK;
	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (!IS_VALID_SOCKET(s))
			continue;

		if (!lbridge_socket_set_nonblocking(s, true))
		{
			CLOSE_SOCKET(s);
			s = INVALID_SOCK;
			continue;
		}

		if (connect(s, rp->ai_addr, (int)rp->ai_addrlen) != 0)
		{
			const int err_connection = GET_LAST_SOCKET_ERROR();
			if (err_connection != LBRIDGE_EINPROGRESS && err_connection != LBRIDGE_EWOULDBLOCK)
			{
				CLOSE_SOCKET(s);
				s = INVALID_SOCK;
				continue;
			}
		}
		break; // Successfully initiated connection
	}

	freeaddrinfo(result);

	if (!IS_VALID_SOCKET(s))
	{
		p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
		return false;
	}
	// connect with timeout
	fd_set wfds, efds;
	FD_ZERO(&wfds);
	FD_ZERO(&efds);
	FD_SET(s, &wfds);
	FD_SET(s, &efds);
	struct timeval tv;
	struct timeval* tv_ptr = NULL;
	if (p_client->base.timeout_ms >= 0)
	{
		tv.tv_sec = p_client->base.timeout_ms / 1000;
		tv.tv_usec = (p_client->base.timeout_ms % 1000) * 1000;
		tv_ptr = &tv;
	}
	const int rc = select((int)(s + 1), NULL, &wfds, &efds, tv_ptr);
	if (rc == 0)
	{
		p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_TIMEOUT;
		CLOSE_SOCKET(s);
		return false;
	}
	if (rc < 0 || FD_ISSET(s, &efds))
	{
		p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
		CLOSE_SOCKET(s);
		return false;
	}
	int err_select = 0;
	socklen_t len = sizeof(err_select);
	getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err_select, &len);
	if (err_select != 0)
	{
		switch (err_select)
		{
		case LBRIDGE_ECONNREFUSED:
			p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
			break;
		case LBRIDGE_ETIMEDOUT:
			p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_TIMEOUT;
			break;
		default:
			p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_UNKNOWN;
			break;
		}

		CLOSE_SOCKET(s);
		return false;
	}

	p_client->connection.as_ptr = SOCKET_TO_PTR(s);
	return true;
}

bool lbridge_tcp_client_impl_cleanup(struct lbridge_client* p_client)
{
	if (p_client->connection.connected)
	{
		socket_t s = PTR_TO_SOCKET(p_client->connection.as_ptr);
		if (IS_VALID_SOCKET(s))
		{
			CLOSE_SOCKET(s);
			p_client->connection.as_ptr = NULL;
		}
	}
	return true;
}

#endif // LBRIDGE_ENABLE_TCP_CLIENT
#if defined(LBRIDGE_ENABLE_TCP_SERVER)

bool lbridge_tcp_server_impl_open(struct lbridge_server* p_server, void* arg)
{
	INIT_SOCKET_IF_NEEDED();

	const struct lbridge_tcp_connection_data* connection_data = arg;

	struct addrinfo hints, *result, *rp;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;     // For binding

	char port_str[6];
	snprintf(port_str, sizeof(port_str), "%u", connection_data->port);

	if (getaddrinfo(connection_data->host, port_str, &hints, &result) != 0)
	{
		p_server->base.last_error = LBRIDGE_ERROR_BAD_ARGUMENT;
		return false;
	}

	socket_t s = INVALID_SOCK;
	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (!IS_VALID_SOCKET(s))
			continue;

		// Set socket options (reuse address)
		int opt = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#if defined(SO_REUSEPORT) && !defined(_WIN32)
		// On Linux/macOS, SO_REUSEPORT allows binding to a port in TIME_WAIT state
		setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char*)&opt, sizeof(opt));
#endif

		// Enable dual-stack for IPv6 sockets (accept both IPv4 and IPv6)
		if (rp->ai_family == AF_INET6)
		{
			int v6only = 0;
			setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6only, sizeof(v6only));
		}

		if (bind(s, rp->ai_addr, (int)rp->ai_addrlen) != 0)
		{
			CLOSE_SOCKET(s);
			s = INVALID_SOCK;
			continue;
		}
		break; // Successfully bound
	}

	freeaddrinfo(result);

	if (!IS_VALID_SOCKET(s))
	{
		p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		return false;
	}
	// Set non-blocking
	if (!lbridge_socket_set_nonblocking(s, true))
	{
		CLOSE_SOCKET(s);
		p_server->base.last_error = LBRIDGE_ERROR_UNKNOWN;
		return false;
	}

	if (listen(s, SOMAXCONN) != 0)
	{
		p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		CLOSE_SOCKET(s);
		return false;
	}

	p_server->backend_data = SOCKET_TO_PTR(s);
	return true;
}
bool lbridge_tcp_server_impl_cleanup(struct lbridge_server* p_server)
{
	socket_t s = PTR_TO_SOCKET(p_server->backend_data);
	if (IS_VALID_SOCKET(s))
	{
		CLOSE_SOCKET(s);
		p_server->backend_data = NULL;
	}
	return true;
}

bool lbridge_tcp_server_impl_accept(struct lbridge_server* p_server, void* arg)
{
	struct lbridge_server_accept_data* accept_data = (struct lbridge_server_accept_data*)arg;
	accept_data->new_client_accepted = false;
	socket_t server_socket = PTR_TO_SOCKET(p_server->backend_data);
	if (!IS_VALID_SOCKET(server_socket))
	{
		p_server->base.last_error = LBRIDGE_ERROR_NOT_CONNECTED;
		return false;
	}
	struct sockaddr_storage client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	socklen_t client_addr_len = sizeof(client_addr);
	socket_t client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
	if (!IS_VALID_SOCKET(client_socket))
	{
		const int err = GET_LAST_SOCKET_ERROR();
		if (err == LBRIDGE_EWOULDBLOCK)
			return true; // no waiting client

		return false;
	}
	if (!lbridge_socket_set_nonblocking(client_socket, true))
	{
		int err = GET_LAST_SOCKET_ERROR();
		(void)err;
		CLOSE_SOCKET(client_socket);
		return false;
	}
	accept_data->new_connection->as_ptr = SOCKET_TO_PTR(client_socket);
	accept_data->new_client_accepted = true;
	return true;
}

#endif // LBRIDGE_ENABLE_TCP_SERVER

bool lbridge_socket_impl_send_data(struct lbridge_object* p_object, void* arg)
{
	const struct lbridge_object_send_data* send_data = (const struct lbridge_object_send_data*)arg;
	const struct lbridge_connection* connection = send_data->connection;
	socket_t s = PTR_TO_SOCKET(connection->as_ptr);
	if (!IS_VALID_SOCKET(s))
	{
		p_object->last_error = LBRIDGE_ERROR_NOT_CONNECTED;
		return false;
	}
	// send with timeout
	size_t total_sent = 0;
	while (total_sent < send_data->size)
	{
		fd_set wfds;
		FD_ZERO(&wfds);
		FD_SET(s, &wfds);
		struct timeval tv;
		struct timeval* tv_ptr = NULL;
		if (p_object->timeout_ms >= 0)
		{
			tv.tv_sec = p_object->timeout_ms / 1000;
			tv.tv_usec = (p_object->timeout_ms % 1000) * 1000;
			tv_ptr = &tv;
		}
		const int rc = select((int)(s + 1), NULL, &wfds, NULL, tv_ptr);
		if (rc == 0)
		{
			p_object->last_error = LBRIDGE_ERROR_SEND_TIMEOUT;
			return false;
		}
		int sent = send(s, (const char*)(send_data->data + total_sent), (int)(send_data->size - total_sent), 0);
		if (sent < 0)
		{
			const int err = GET_LAST_SOCKET_ERROR();
			if (err == LBRIDGE_ECONNABORTED)
			{
				p_object->last_error = LBRIDGE_ERROR_CONNECTION_LOST;
			}
			return false;
		}
		total_sent += (size_t)sent;
	}

	return true;
}

bool lbridge_socket_impl_receive_data(struct lbridge_object* p_object, void* arg)
{
	struct lbridge_object_receive_data* receive_data = (struct lbridge_object_receive_data*)arg;
	const struct lbridge_connection* connection = receive_data->connection;
	socket_t s = PTR_TO_SOCKET(connection->as_ptr);
	if (!IS_VALID_SOCKET(s))
	{
		p_object->last_error = LBRIDGE_ERROR_NOT_CONNECTED;
		return false;
	}

	// if non-blocking and no data available, return immediately
	if(!(receive_data->flags & LBRIDGE_RECEIVE_BLOCKING))
	{
		char peek_byte;
		int peek_result = recv(s, &peek_byte, 1, MSG_PEEK);
		if (peek_result <= 0)
		{
			// No data available (EWOULDBLOCK/EAGAIN) or connection closed
			receive_data->received_size = 0;
			return true;
		}
	}

	uint32_t total_received = 0;
	while (total_received < receive_data->requested_size)
	{
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(s, &rfds);
		struct timeval tv;
		struct timeval* tv_ptr = NULL;
		if (p_object->timeout_ms >= 0)
		{
			tv.tv_sec = p_object->timeout_ms / 1000;
			tv.tv_usec = (p_object->timeout_ms % 1000) * 1000;
			tv_ptr = &tv;
		}
		const int rc = select((int)(s + 1), &rfds, NULL, NULL, tv_ptr);
		if (rc == 0)
		{
			p_object->last_error = LBRIDGE_ERROR_RECEIVE_TIMEOUT;
			return false;
		}
		int received = recv(s, (char*)(receive_data->data + total_received), (int)(receive_data->requested_size - total_received), 0);
		if (received < 0)
		{
			int err = GET_LAST_SOCKET_ERROR();
			(void)err;
			return false;
		}
		else if (received == 0)
		{
			// connection closed
			break;
		}
		total_received += (uint32_t)received;
	}
	receive_data->received_size = total_received;
	return true;
}

bool lbridge_socket_impl_connection_close(struct lbridge_object* p_object, void* arg)
{
	LBRIDGE_UNUSED(p_object);
	const struct lbridge_connection* connection = (const struct lbridge_connection*)arg;
	socket_t s = PTR_TO_SOCKET(connection->as_ptr);
	if (IS_VALID_SOCKET(s))
	{
		CLOSE_SOCKET(s);
	}
	return true;
}

bool lbridge_backend_tcp_impl(enum lbridge_backend_operation op, lbridge_object_t p_object, void* arg)
{
	switch (op)
	{
#if defined(LBRIDGE_ENABLE_TCP_CLIENT)
	case LBRIDGE_OP_NONE:
		return true;
	case LBRIDGE_OP_CLIENT_CONNECT:
		return lbridge_tcp_client_impl_connect(p_object, arg);
	case LBRIDGE_OP_CLIENT_CLEANUP:
		return lbridge_tcp_client_impl_cleanup(p_object);
#endif
#if defined(LBRIDGE_ENABLE_TCP_SERVER)
	case LBRIDGE_OP_SERVER_OPEN:
		return lbridge_tcp_server_impl_open(p_object, arg);
	case LBRIDGE_OP_SERVER_CLEANUP:
		return lbridge_tcp_server_impl_cleanup(p_object);
	case LBRIDGE_OP_SERVER_ACCEPT:
		return lbridge_tcp_server_impl_accept(p_object, arg);
#endif
	case LBRIDGE_OP_SEND_DATA:
		return lbridge_socket_impl_send_data(p_object, arg);
	case LBRIDGE_OP_RECEIVE_DATA:
		return lbridge_socket_impl_receive_data(p_object, arg);
	case LBRIDGE_OP_CONNECTION_CLOSE:
		return lbridge_socket_impl_connection_close(p_object, arg);
	default:
		return false;
	}
}

// ============================================================================
// Unix Domain Socket Implementation
// ============================================================================

#if defined(LBRIDGE_ENABLE_UNIX_CLIENT)

bool lbridge_unix_client_impl_connect(struct lbridge_client* p_client, void* arg)
{
	INIT_SOCKET_IF_NEEDED();
	p_client->connection.as_ptr = NULL;
	const struct lbridge_unix_connection_data* connection_data = arg;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	// Copy socket path (ensure null termination)
	size_t path_len = strlen(connection_data->socket_path);
	if (path_len >= sizeof(addr.sun_path))
	{
		p_client->base.last_error = LBRIDGE_ERROR_BAD_ARGUMENT;
		return false;
	}
	memcpy(addr.sun_path, connection_data->socket_path, path_len);
	addr.sun_path[path_len] = '\0';

	socket_t s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (!IS_VALID_SOCKET(s))
	{
		p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
		return false;
	}

	if (!lbridge_socket_set_nonblocking(s, true))
	{
		CLOSE_SOCKET(s);
		p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_UNKNOWN;
		return false;
	}

	if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		const int err_connection = GET_LAST_SOCKET_ERROR();
		if (err_connection != LBRIDGE_EINPROGRESS && err_connection != LBRIDGE_EWOULDBLOCK)
		{
			CLOSE_SOCKET(s);
			p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
			return false;
		}
	}

	// connect with timeout
	fd_set wfds, efds;
	FD_ZERO(&wfds);
	FD_ZERO(&efds);
	FD_SET(s, &wfds);
	FD_SET(s, &efds);
	struct timeval tv;
	struct timeval* tv_ptr = NULL;
	if (p_client->base.timeout_ms >= 0)
	{
		tv.tv_sec = p_client->base.timeout_ms / 1000;
		tv.tv_usec = (p_client->base.timeout_ms % 1000) * 1000;
		tv_ptr = &tv;
	}
	const int rc = select((int)(s + 1), NULL, &wfds, &efds, tv_ptr);
	if (rc == 0)
	{
		p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_TIMEOUT;
		CLOSE_SOCKET(s);
		return false;
	}
	if (rc < 0 || FD_ISSET(s, &efds))
	{
		p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
		CLOSE_SOCKET(s);
		return false;
	}

	int err_select = 0;
	socklen_t len = sizeof(err_select);
	getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err_select, &len);
	if (err_select != 0)
	{
		switch (err_select)
		{
		case LBRIDGE_ECONNREFUSED:
			p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
			break;
		case LBRIDGE_ETIMEDOUT:
			p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_TIMEOUT;
			break;
		default:
			p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_UNKNOWN;
			break;
		}
		CLOSE_SOCKET(s);
		return false;
	}

	p_client->connection.as_ptr = SOCKET_TO_PTR(s);
	return true;
}

bool lbridge_unix_client_impl_cleanup(struct lbridge_client* p_client)
{
	if (p_client->connection.connected)
	{
		socket_t s = PTR_TO_SOCKET(p_client->connection.as_ptr);
		if (IS_VALID_SOCKET(s))
		{
			CLOSE_SOCKET(s);
			p_client->connection.as_ptr = NULL;
		}
	}
	return true;
}

#endif // LBRIDGE_ENABLE_UNIX_CLIENT

#if defined(LBRIDGE_ENABLE_UNIX_SERVER)

bool lbridge_unix_server_impl_open(struct lbridge_server* p_server, void* arg)
{
	INIT_SOCKET_IF_NEEDED();

	const struct lbridge_unix_server_data* server_data = arg;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	// Copy socket path (ensure null termination)
	size_t path_len = strlen(server_data->socket_path);
	if (path_len >= sizeof(addr.sun_path))
	{
		p_server->base.last_error = LBRIDGE_ERROR_BAD_ARGUMENT;
		return false;
	}
	memcpy(addr.sun_path, server_data->socket_path, path_len);
	addr.sun_path[path_len] = '\0';

	// Remove existing socket file if present
#if defined(_WIN32)
	DeleteFileA(server_data->socket_path);
#else
	unlink(server_data->socket_path);
#endif

	socket_t s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (!IS_VALID_SOCKET(s))
	{
		p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		return false;
	}

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		CLOSE_SOCKET(s);
		return false;
	}

	// Set non-blocking
	if (!lbridge_socket_set_nonblocking(s, true))
	{
		CLOSE_SOCKET(s);
		p_server->base.last_error = LBRIDGE_ERROR_UNKNOWN;
		return false;
	}

	if (listen(s, SOMAXCONN) != 0)
	{
		p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		CLOSE_SOCKET(s);
		return false;
	}

	p_server->backend_data = SOCKET_TO_PTR(s);
	return true;
}

bool lbridge_unix_server_impl_cleanup(struct lbridge_server* p_server)
{
	socket_t s = PTR_TO_SOCKET(p_server->backend_data);
	if (IS_VALID_SOCKET(s))
	{
		CLOSE_SOCKET(s);
		p_server->backend_data = NULL;
	}
	return true;
}

bool lbridge_unix_server_impl_accept(struct lbridge_server* p_server, void* arg)
{
	struct lbridge_server_accept_data* accept_data = (struct lbridge_server_accept_data*)arg;
	accept_data->new_client_accepted = false;
	socket_t server_socket = PTR_TO_SOCKET(p_server->backend_data);
	if (!IS_VALID_SOCKET(server_socket))
	{
		p_server->base.last_error = LBRIDGE_ERROR_NOT_CONNECTED;
		return false;
	}

	struct sockaddr_un client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	socklen_t client_addr_len = sizeof(client_addr);
	socket_t client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
	if (!IS_VALID_SOCKET(client_socket))
	{
		const int err = GET_LAST_SOCKET_ERROR();
		if (err == LBRIDGE_EWOULDBLOCK)
			return true; // no waiting client
		return false;
	}

	if (!lbridge_socket_set_nonblocking(client_socket, true))
	{
		CLOSE_SOCKET(client_socket);
		return false;
	}

	accept_data->new_connection->as_ptr = SOCKET_TO_PTR(client_socket);
	accept_data->new_client_accepted = true;
	return true;
}

#endif // LBRIDGE_ENABLE_UNIX_SERVER

#if defined(LBRIDGE_ENABLE_UNIX_CLIENT) || defined(LBRIDGE_ENABLE_UNIX_SERVER)

bool lbridge_backend_unix_impl(enum lbridge_backend_operation op, lbridge_object_t p_object, void* arg)
{
	switch (op)
	{
#if defined(LBRIDGE_ENABLE_UNIX_CLIENT)
	case LBRIDGE_OP_NONE:
		return true;
	case LBRIDGE_OP_CLIENT_CONNECT:
		return lbridge_unix_client_impl_connect(p_object, arg);
	case LBRIDGE_OP_CLIENT_CLEANUP:
		return lbridge_unix_client_impl_cleanup(p_object);
#endif
#if defined(LBRIDGE_ENABLE_UNIX_SERVER)
	case LBRIDGE_OP_SERVER_OPEN:
		return lbridge_unix_server_impl_open(p_object, arg);
	case LBRIDGE_OP_SERVER_CLEANUP:
		return lbridge_unix_server_impl_cleanup(p_object);
	case LBRIDGE_OP_SERVER_ACCEPT:
		return lbridge_unix_server_impl_accept(p_object, arg);
#endif
	case LBRIDGE_OP_SEND_DATA:
		return lbridge_socket_impl_send_data(p_object, arg);
	case LBRIDGE_OP_RECEIVE_DATA:
		return lbridge_socket_impl_receive_data(p_object, arg);
	case LBRIDGE_OP_CONNECTION_CLOSE:
		return lbridge_socket_impl_connection_close(p_object, arg);
	default:
		return false;
	}
}

#endif // LBRIDGE_ENABLE_UNIX_CLIENT || LBRIDGE_ENABLE_UNIX_SERVER

#ifdef __cplusplus
}
#endif