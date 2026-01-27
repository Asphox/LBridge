#include "../lbridge_internal.h"
#include "lbridge_socket_win_unix.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(LBRIDGE_ENABLE_TCP_CLIENT)

bool lbridge_tcp_client_impl_connect(struct lbridge_client* p_client, void* arg)
{
	INIT_SOCKET_IF_NEEDED();
	p_client->connection.as_ptr = NULL;
	const struct lbridge_tcp_connection_data* connection_data = arg;
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(connection_data->port);
	inet_pton(AF_INET, connection_data->host, &addr.sin_addr);
	socket_t s = socket(AF_INET, SOCK_STREAM, 0);
	if (!IS_VALID_SOCKET(s))
	{
		int err = GET_LAST_SOCKET_ERROR();
		err = err;
		return false;
	}
	if (!lbridge_socket_set_nonblocking(s, true))
	{
		int err = GET_LAST_SOCKET_ERROR();
		err = err;
		CLOSE_SOCKET(s);
		return false;
	}
	if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		const int err_connection = GET_LAST_SOCKET_ERROR();
		if (err_connection != LBRIDGE_EINPROGRESS && err_connection != LBRIDGE_EWOULDBLOCK)
		{
			CLOSE_SOCKET(s);
			return false;
		}
	}
	// connect with timeout
	fd_set wfds;
	FD_ZERO(&wfds);
	FD_SET(s, &wfds);
	struct timeval tv;
	tv.tv_sec = p_client->timeout_ms / 1000;
	tv.tv_usec = (p_client->timeout_ms % 1000) * 1000;
	const int rc = select((int)(s + 1), NULL, &wfds, NULL, (p_client->timeout_ms >= 0 ? &tv : NULL));
	if (rc == 0)
	{
		p_client->last_error = LBRIDGE_ERROR_CONNECTION_TIMEOUT;
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
			p_client->last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
			break;
		case LBRIDGE_ETIMEDOUT:
			p_client->last_error = LBRIDGE_ERROR_CONNECTION_TIMEOUT;
			break;
		default:
			p_client->last_error = LBRIDGE_ERROR_CONNECTION_UNKNOWN;
			break;
		}

		CLOSE_SOCKET(s);
		return false;
	}

	p_client->connection.as_ptr = (void*)s;
	return true;
}

bool lbridge_tcp_client_impl_disconnect(struct lbridge_client* p_client)
{
	socket_t s = (socket_t)(p_client->connection.as_ptr);
	if(IS_VALID_SOCKET(s))
	{
		CLOSE_SOCKET(s);
		p_client->connection.as_ptr = NULL;
	}
	return true;
}

bool lbridge_tcp_client_impl_cleanup(struct lbridge_client* p_client)
{
	memset(&p_client->connection, 0, sizeof(p_client->connection));
	return true;
}

#endif // LBRIDGE_ENABLE_TCP_CLIENT
#if defined(LBRIDGE_ENABLE_TCP_SERVER)

bool lbridge_tcp_server_impl_open(struct lbridge_server* p_server, void* arg)
{
	INIT_SOCKET_IF_NEEDED();

	const struct lbridge_tcp_connection_data* connection_data = arg;
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(connection_data->port);
	if (inet_pton(AF_INET, connection_data->host, &addr.sin_addr) <= 0)
	{
		p_server->last_error = LBRIDGE_ERROR_BAD_ARGUMENT;
		return false;
	}

	socket_t s = socket(AF_INET, SOCK_STREAM, 0);
	if (!IS_VALID_SOCKET(s))
	{
		p_server->last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		return false;
	}

	// Set socket options (reuse address)
	int opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		p_server->last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		CLOSE_SOCKET(s);
		return false;
	}
	// Set non-blocking
	if (!lbridge_socket_set_nonblocking(s, true))
	{
		CLOSE_SOCKET(s);
		p_server->last_error = LBRIDGE_ERROR_UNKNOWN;
		return false;
	}

	if (listen(s, SOMAXCONN) != 0)
	{
		p_server->last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		CLOSE_SOCKET(s);
		return false;
	}

	p_server->backend_data = (void*)s;
	return true;
}

bool lbridge_tcp_server_impl_disconnect(struct lbridge_server* p_server)
{
	socket_t s = (socket_t)(p_server->backend_data);
	if (IS_VALID_SOCKET(s))
	{
		CLOSE_SOCKET(s);
		p_server->backend_data = NULL;
	}
	return true;
}

bool lbridge_tcp_server_impl_cleanup(struct lbridge_server* p_server)
{
	p_server->backend_data = NULL;
	return true;
}

bool lbridge_tcp_server_impl_accept(struct lbridge_server* p_server, void* arg)
{
	struct lbridge_server_accept_data* accept_data = (struct lbridge_server_accept_data*)arg;
	accept_data->new_client_accepted = false;
	socket_t server_socket = (socket_t)(p_server->backend_data);
	if (!IS_VALID_SOCKET(server_socket))
	{
		p_server->last_error = LBRIDGE_ERROR_NOT_CONNECTED;
		return false;
	}
	struct sockaddr_in client_addr;
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
		err = err;
		CLOSE_SOCKET(client_socket);
		return false;
	}
	accept_data->new_connection->as_ptr = (void*)client_socket;
	accept_data->new_client_accepted = true;
	return true;
}

#endif // LBRIDGE_ENABLE_TCP_SERVER

bool lbridge_socket_impl_send_data(struct lbridge_object* p_object, void* arg)
{
	const struct lbridge_object_send_data* send_data = (const struct lbridge_object_send_data*)arg;
	const struct lbridge_connection* connection = send_data->connection;
	socket_t s = (socket_t)(connection->as_ptr);
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
		tv.tv_sec = p_object->timeout_ms / 1000;
		tv.tv_usec = (p_object->timeout_ms % 1000) * 1000;
		const int rc = select((int)(s + 1), NULL, &wfds, NULL, (p_object->timeout_ms >= 0 ? &tv : NULL));
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
	socket_t s = (socket_t)(connection->as_ptr);
	if (!IS_VALID_SOCKET(s))
	{
		p_object->last_error = LBRIDGE_ERROR_NOT_CONNECTED;
		return false;
	}

	// if non-blocking and no data available, return immediately
	if(!(receive_data->flags & LBRIDGE_RECEIVE_BLOCKING))
	{
		unsigned long bytes_available = 0;
		int result = IOCTL(s, FIONREAD, &bytes_available);
		if (result != 0 || bytes_available < receive_data->requested_size)
		{
			receive_data->received_size = 0;
			return true;
		}
	}

	const struct lbridge_client_receive_data* data_buffer = (const struct lbridge_client_receive_data*)arg;
	uint32_t total_received = 0;
	while (total_received < receive_data->requested_size)
	{
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(s, &rfds);
		struct timeval tv;
		tv.tv_sec = p_object->timeout_ms/ 1000;
		tv.tv_usec = (p_object->timeout_ms % 1000) * 1000;
		const int rc = select((int)(s + 1), &rfds, NULL, NULL, (p_object->timeout_ms >= 0 ? &tv : NULL));
		if (rc == 0)
		{
			p_object->last_error = LBRIDGE_ERROR_RECEIVE_TIMEOUT;
			return false;
		}
		int received = recv(s, (char*)(receive_data->data + total_received), (int)(receive_data->requested_size - total_received), 0);
		if (received < 0)
		{
			int err = GET_LAST_SOCKET_ERROR();
			err = err;
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

bool lbridge_backend_tcp_impl(enum lbridge_backend_operation op, lbridge_object_t p_object, void* arg)
{
	switch (op)
	{
#if defined(LBRIDGE_ENABLE_TCP_CLIENT)
	case LBRIDGE_OP_NONE:
		return true;
	case LBRIDGE_OP_CLIENT_CONNECT:
		return lbridge_tcp_client_impl_connect(p_object, arg);
	case LBRIDGE_OP_CLIENT_CLOSE:
		return lbridge_tcp_client_impl_disconnect(p_object);
	case LBRIDGE_OP_CLIENT_CLEANUP:
		return lbridge_tcp_client_impl_cleanup(p_object);
#endif
#if defined(LBRIDGE_ENABLE_TCP_SERVER)
	case LBRIDGE_OP_SERVER_CLOSE:
		return lbridge_tcp_server_impl_disconnect(p_object);
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
		p_client->last_error = LBRIDGE_ERROR_BAD_ARGUMENT;
		return false;
	}
	memcpy(addr.sun_path, connection_data->socket_path, path_len);
	addr.sun_path[path_len] = '\0';

	socket_t s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (!IS_VALID_SOCKET(s))
	{
		p_client->last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
		return false;
	}

	if (!lbridge_socket_set_nonblocking(s, true))
	{
		CLOSE_SOCKET(s);
		p_client->last_error = LBRIDGE_ERROR_CONNECTION_UNKNOWN;
		return false;
	}

	if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		const int err_connection = GET_LAST_SOCKET_ERROR();
		if (err_connection != LBRIDGE_EINPROGRESS && err_connection != LBRIDGE_EWOULDBLOCK)
		{
			CLOSE_SOCKET(s);
			p_client->last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
			return false;
		}
	}

	// connect with timeout
	fd_set wfds;
	FD_ZERO(&wfds);
	FD_SET(s, &wfds);
	struct timeval tv;
	tv.tv_sec = p_client->timeout_ms / 1000;
	tv.tv_usec = (p_client->timeout_ms % 1000) * 1000;
	const int rc = select((int)(s + 1), NULL, &wfds, NULL, (p_client->timeout_ms >= 0 ? &tv : NULL));
	if (rc == 0)
	{
		p_client->last_error = LBRIDGE_ERROR_CONNECTION_TIMEOUT;
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
			p_client->last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
			break;
		case LBRIDGE_ETIMEDOUT:
			p_client->last_error = LBRIDGE_ERROR_CONNECTION_TIMEOUT;
			break;
		default:
			p_client->last_error = LBRIDGE_ERROR_CONNECTION_UNKNOWN;
			break;
		}
		CLOSE_SOCKET(s);
		return false;
	}

	p_client->connection.as_ptr = (void*)s;
	return true;
}

bool lbridge_unix_client_impl_disconnect(struct lbridge_client* p_client)
{
	socket_t s = (socket_t)(p_client->connection.as_ptr);
	if (IS_VALID_SOCKET(s))
	{
		CLOSE_SOCKET(s);
		p_client->connection.as_ptr = NULL;
	}
	return true;
}

bool lbridge_unix_client_impl_cleanup(struct lbridge_client* p_client)
{
	memset(&p_client->connection, 0, sizeof(p_client->connection));
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
		p_server->last_error = LBRIDGE_ERROR_BAD_ARGUMENT;
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
		p_server->last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		return false;
	}

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		p_server->last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		CLOSE_SOCKET(s);
		return false;
	}

	// Set non-blocking
	if (!lbridge_socket_set_nonblocking(s, true))
	{
		CLOSE_SOCKET(s);
		p_server->last_error = LBRIDGE_ERROR_UNKNOWN;
		return false;
	}

	if (listen(s, SOMAXCONN) != 0)
	{
		p_server->last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
		CLOSE_SOCKET(s);
		return false;
	}

	p_server->backend_data = (void*)s;
	return true;
}

bool lbridge_unix_server_impl_disconnect(struct lbridge_server* p_server)
{
	socket_t s = (socket_t)(p_server->backend_data);
	if (IS_VALID_SOCKET(s))
	{
		CLOSE_SOCKET(s);
		p_server->backend_data = NULL;
	}
	return true;
}

bool lbridge_unix_server_impl_cleanup(struct lbridge_server* p_server)
{
	p_server->backend_data = NULL;
	return true;
}

bool lbridge_unix_server_impl_accept(struct lbridge_server* p_server, void* arg)
{
	struct lbridge_server_accept_data* accept_data = (struct lbridge_server_accept_data*)arg;
	accept_data->new_client_accepted = false;
	socket_t server_socket = (socket_t)(p_server->backend_data);
	if (!IS_VALID_SOCKET(server_socket))
	{
		p_server->last_error = LBRIDGE_ERROR_NOT_CONNECTED;
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

	accept_data->new_connection->as_ptr = (void*)client_socket;
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
	case LBRIDGE_OP_CLIENT_CLOSE:
		return lbridge_unix_client_impl_disconnect(p_object);
	case LBRIDGE_OP_CLIENT_CLEANUP:
		return lbridge_unix_client_impl_cleanup(p_object);
#endif
#if defined(LBRIDGE_ENABLE_UNIX_SERVER)
	case LBRIDGE_OP_SERVER_CLOSE:
		return lbridge_unix_server_impl_disconnect(p_object);
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
	default:
		return false;
	}
}

#endif // LBRIDGE_ENABLE_UNIX_CLIENT || LBRIDGE_ENABLE_UNIX_SERVER

#ifdef __cplusplus
}
#endif