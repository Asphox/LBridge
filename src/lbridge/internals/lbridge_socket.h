#ifndef LBRIDGE_SOCKET_H
#define LBRIDGE_SOCKET_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(LBRIDGE_ENABLE_TCP_CLIENT) || defined(LBRIDGE_ENABLE_TCP_SERVER)
bool lbridge_backend_tcp_impl(enum lbridge_backend_operation op, lbridge_object_t p_object, void* arg);
#endif

#ifdef LBRIDGE_ENABLE_TCP_CLIENT
struct lbridge_tcp_client_impl_data_s
{
	const char* host;
	uint16_t	port;
	void*		data;
};

struct lbridge_tcp_connection_data
{
	const char* host;
	uint16_t	port;
};

#endif // LBRIDGE_ENABLE_TCP_CLIENT
#ifdef LBRIDGE_ENABLE_TCP_SERVER

struct lbridge_tcp_server_impl_data_s
{
	uint16_t	port;
	void*		data;
};

#endif // LBRIDGE_ENABLE_TCP_SERVER

#if defined(LBRIDGE_ENABLE_UNIX_CLIENT) || defined(LBRIDGE_ENABLE_UNIX_SERVER)
bool lbridge_backend_unix_impl(enum lbridge_backend_operation op, lbridge_object_t p_object, void* arg);
#endif

#ifdef LBRIDGE_ENABLE_UNIX_CLIENT
struct lbridge_unix_connection_data
{
	const char* socket_path;
};
#endif // LBRIDGE_ENABLE_UNIX_CLIENT

#ifdef LBRIDGE_ENABLE_UNIX_SERVER
struct lbridge_unix_server_data
{
	const char* socket_path;
};
#endif // LBRIDGE_ENABLE_UNIX_SERVER

#ifdef __cplusplus
}
#endif

#endif // LBRIDGE_SOCKET_H