// Feature test macros for POSIX functions
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

#if defined(LBRIDGE_ENABLE_BLUETOOTH_CLIENT) || defined(LBRIDGE_ENABLE_BLUETOOTH_SERVER)

#include "lbridge_socket_bluetooth.h"
#include "lbridge_socket_win_unix.h"
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Bluetooth Client Implementation
// ============================================================================

#if defined(LBRIDGE_ENABLE_BLUETOOTH_CLIENT)

bool lbridge_bluetooth_client_impl_connect(struct lbridge_client* p_client, void* arg)
{
    INIT_SOCKET_IF_NEEDED();
    p_client->connection.as_ptr = NULL;
    const struct lbridge_bluetooth_connection_data* connection_data = arg;

    if (connection_data->channel < 1 || connection_data->channel > 30)
    {
        p_client->base.last_error = LBRIDGE_ERROR_BAD_ARGUMENT;
        return false;
    }

#if defined(_WIN32)
    // Windows Bluetooth implementation
    BTH_ADDR bt_addr;
    if (lbridge_bt_str_to_addr(connection_data->address, &bt_addr) != 0)
    {
        p_client->base.last_error = LBRIDGE_ERROR_BAD_ARGUMENT;
        return false;
    }

    bt_socket_t s = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
    if (!BT_IS_VALID_SOCKET(s))
    {
        p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
        return false;
    }

    SOCKADDR_BTH addr;
    memset(&addr, 0, sizeof(addr));
    addr.addressFamily = AF_BTH;
    addr.btAddr = bt_addr;
    addr.port = connection_data->channel;

    // Set non-blocking mode
    u_long mode = 1;
    if (ioctlsocket(s, FIONBIO, &mode) != 0)
    {
        BT_CLOSE_SOCKET(s);
        p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_UNKNOWN;
        return false;
    }

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        int err = BT_GET_LAST_ERROR();
        if (err != WSAEINPROGRESS && err != WSAEWOULDBLOCK)
        {
            BT_CLOSE_SOCKET(s);
            p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
            return false;
        }
    }

    // Wait for connection with timeout using select
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

    int rc = select((int)(s + 1), NULL, &wfds, &efds, tv_ptr);
    if (rc == 0)
    {
        p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_TIMEOUT;
        BT_CLOSE_SOCKET(s);
        return false;
    }
    if (rc < 0 || FD_ISSET(s, &efds))
    {
        p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
        BT_CLOSE_SOCKET(s);
        return false;
    }

    // Check for connection errors
    int err_select = 0;
    int len = sizeof(err_select);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err_select, &len);
    if (err_select != 0)
    {
        p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
        BT_CLOSE_SOCKET(s);
        return false;
    }

    p_client->connection.as_ptr = SOCKET_TO_PTR(s);
    return true;

#elif defined(__linux__)
    // Linux BlueZ implementation
    bdaddr_t bt_addr;
    if (lbridge_bt_str_to_addr(connection_data->address, &bt_addr) != 0)
    {
        p_client->base.last_error = LBRIDGE_ERROR_BAD_ARGUMENT;
        return false;
    }

    bt_socket_t s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (!BT_IS_VALID_SOCKET(s))
    {
        p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
        return false;
    }

    struct sockaddr_rc addr;
    memset(&addr, 0, sizeof(addr));
    addr.rc_family = AF_BLUETOOTH;
    addr.rc_bdaddr = bt_addr;
    addr.rc_channel = connection_data->channel;

    // Set non-blocking mode
    if (lbridge_bt_socket_set_nonblocking(s, 1) != 0)
    {
        BT_CLOSE_SOCKET(s);
        p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_UNKNOWN;
        return false;
    }

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        int err = BT_GET_LAST_ERROR();
        if (err != EINPROGRESS && err != EWOULDBLOCK)
        {
            BT_CLOSE_SOCKET(s);
            p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
            return false;
        }
    }

    // Wait for connection with timeout using select
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

    int rc = select(s + 1, NULL, &wfds, &efds, tv_ptr);
    if (rc == 0)
    {
        p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_TIMEOUT;
        BT_CLOSE_SOCKET(s);
        return false;
    }
    if (rc < 0 || FD_ISSET(s, &efds))
    {
        p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
        BT_CLOSE_SOCKET(s);
        return false;
    }

    // Check for connection errors
    int err_select = 0;
    socklen_t len = sizeof(err_select);
    getsockopt(s, SOL_SOCKET, SO_ERROR, &err_select, &len);
    if (err_select != 0)
    {
        p_client->base.last_error = LBRIDGE_ERROR_CONNECTION_FAILED;
        BT_CLOSE_SOCKET(s);
        return false;
    }

    p_client->connection.as_ptr = SOCKET_TO_PTR(s);
    return true;

#else
    (void)connection_data;
    p_client->base.last_error = LBRIDGE_ERROR_UNKNOWN;
    return false;
#endif
}

bool lbridge_bluetooth_client_impl_cleanup(struct lbridge_client* p_client)
{
    if (p_client->connection.connected)
    {
        bt_socket_t s = PTR_TO_SOCKET(p_client->connection.as_ptr);
        if (BT_IS_VALID_SOCKET(s))
        {
            BT_CLOSE_SOCKET(s);
            p_client->connection.as_ptr = NULL;
        }
    }
    return true;
}

#endif // LBRIDGE_ENABLE_BLUETOOTH_CLIENT

// ============================================================================
// Bluetooth Server Implementation
// ============================================================================

#if defined(LBRIDGE_ENABLE_BLUETOOTH_SERVER)

bool lbridge_bluetooth_server_impl_open(struct lbridge_server* p_server, void* arg)
{
    INIT_SOCKET_IF_NEEDED();

    const struct lbridge_bluetooth_server_data* server_data = arg;

    if (server_data->channel < 1 || server_data->channel > 30)
    {
        p_server->base.last_error = LBRIDGE_ERROR_BAD_ARGUMENT;
        return false;
    }

#if defined(_WIN32)
    // Windows Bluetooth server implementation
    bt_socket_t s = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
    if (!BT_IS_VALID_SOCKET(s))
    {
        p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
        return false;
    }

    SOCKADDR_BTH addr;
    memset(&addr, 0, sizeof(addr));
    addr.addressFamily = AF_BTH;
    addr.btAddr = BTH_ADDR_NULL;  // Listen on all local adapters
    addr.port = server_data->channel;

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        int err = BT_GET_LAST_ERROR();
        if (err == WSAEADDRINUSE)
            p_server->base.last_error = LBRIDGE_ERROR_RESSOURCE_UNAVAILABLE;
        else
            p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
        BT_CLOSE_SOCKET(s);
        return false;
    }

    // Set non-blocking mode
    u_long mode = 1;
    if (ioctlsocket(s, FIONBIO, &mode) != 0)
    {
        BT_CLOSE_SOCKET(s);
        p_server->base.last_error = LBRIDGE_ERROR_UNKNOWN;
        return false;
    }

    if (listen(s, SOMAXCONN) != 0)
    {
        p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
        BT_CLOSE_SOCKET(s);
        return false;
    }

    p_server->base.backend_data = SOCKET_TO_PTR(s);
    return true;

#elif defined(__linux__)
    // Linux BlueZ server implementation
    bt_socket_t s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (!BT_IS_VALID_SOCKET(s))
    {
        p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
        return false;
    }

    struct sockaddr_rc addr;
    memset(&addr, 0, sizeof(addr));
    addr.rc_family = AF_BLUETOOTH;
    addr.rc_bdaddr = *BDADDR_ANY;  // Listen on all local adapters
    addr.rc_channel = server_data->channel;

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        int err = BT_GET_LAST_ERROR();
        if (err == EADDRINUSE)
            p_server->base.last_error = LBRIDGE_ERROR_RESSOURCE_UNAVAILABLE;
        else
            p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
        BT_CLOSE_SOCKET(s);
        return false;
    }

    // Set non-blocking mode
    if (lbridge_bt_socket_set_nonblocking(s, 1) != 0)
    {
        BT_CLOSE_SOCKET(s);
        p_server->base.last_error = LBRIDGE_ERROR_UNKNOWN;
        return false;
    }

    if (listen(s, SOMAXCONN) != 0)
    {
        p_server->base.last_error = LBRIDGE_ERROR_SERVER_OPEN_FAILED;
        BT_CLOSE_SOCKET(s);
        return false;
    }

    p_server->base.backend_data = SOCKET_TO_PTR(s);
    return true;

#else
    (void)server_data;
    p_server->base.last_error = LBRIDGE_ERROR_UNKNOWN;
    return false;
#endif
}

bool lbridge_bluetooth_server_impl_cleanup(struct lbridge_server* p_server)
{
    bt_socket_t s = PTR_TO_SOCKET(p_server->base.backend_data);
    if (BT_IS_VALID_SOCKET(s))
    {
        BT_CLOSE_SOCKET(s);
        p_server->base.backend_data = NULL;
    }
    return true;
}

bool lbridge_bluetooth_server_impl_accept(struct lbridge_server* p_server, void* arg)
{
    struct lbridge_server_accept_data* accept_data = (struct lbridge_server_accept_data*)arg;
    accept_data->new_client_accepted = false;

    bt_socket_t server_socket = PTR_TO_SOCKET(p_server->base.backend_data);
    if (!BT_IS_VALID_SOCKET(server_socket))
    {
        p_server->base.last_error = LBRIDGE_ERROR_NOT_CONNECTED;
        return false;
    }

#if defined(_WIN32)
    SOCKADDR_BTH client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    int client_addr_len = sizeof(client_addr);
    bt_socket_t client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);

    if (!BT_IS_VALID_SOCKET(client_socket))
    {
        int err = BT_GET_LAST_ERROR();
        if (err == WSAEWOULDBLOCK)
            return true;  // No pending client
        return false;
    }

    // Set non-blocking mode
    u_long mode = 1;
    if (ioctlsocket(client_socket, FIONBIO, &mode) != 0)
    {
        BT_CLOSE_SOCKET(client_socket);
        return false;
    }

#elif defined(__linux__)
    struct sockaddr_rc client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t client_addr_len = sizeof(client_addr);
    bt_socket_t client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);

    if (!BT_IS_VALID_SOCKET(client_socket))
    {
        int err = BT_GET_LAST_ERROR();
        if (err == EWOULDBLOCK || err == EAGAIN)
            return true;  // No pending client
        return false;
    }

    // Set non-blocking mode
    if (lbridge_bt_socket_set_nonblocking(client_socket, 1) != 0)
    {
        BT_CLOSE_SOCKET(client_socket);
        return false;
    }

#else
    return false;
#endif

    accept_data->new_connection->as_ptr = SOCKET_TO_PTR(client_socket);
    accept_data->new_client_accepted = true;
    return true;
}

#endif // LBRIDGE_ENABLE_BLUETOOTH_SERVER

// ============================================================================
// Bluetooth Backend Dispatcher
// ============================================================================

bool lbridge_backend_bluetooth_impl(enum lbridge_backend_operation op, lbridge_object_t p_object, void* arg)
{
    switch (op)
    {
#if defined(LBRIDGE_ENABLE_BLUETOOTH_CLIENT)
    case LBRIDGE_OP_NONE:
        return true;
    case LBRIDGE_OP_CLIENT_CONNECT:
        return lbridge_bluetooth_client_impl_connect(p_object, arg);
    case LBRIDGE_OP_CLIENT_CLEANUP:
        return lbridge_bluetooth_client_impl_cleanup(p_object);
#endif
#if defined(LBRIDGE_ENABLE_BLUETOOTH_SERVER)
    case LBRIDGE_OP_SERVER_OPEN:
        return lbridge_bluetooth_server_impl_open(p_object, arg);
    case LBRIDGE_OP_SERVER_CLEANUP:
        return lbridge_bluetooth_server_impl_cleanup(p_object);
    case LBRIDGE_OP_SERVER_ACCEPT:
        return lbridge_bluetooth_server_impl_accept(p_object, arg);
#endif
    // Reuse socket send/receive from the win_unix backend (same socket API)
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

#ifdef __cplusplus
}
#endif

#endif // LBRIDGE_ENABLE_BLUETOOTH_CLIENT || LBRIDGE_ENABLE_BLUETOOTH_SERVER
