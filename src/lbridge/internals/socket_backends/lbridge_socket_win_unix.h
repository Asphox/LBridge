#ifndef LBRIDGE_SOCKET_WIN_UNIX_H
#define LBRIDGE_SOCKET_WIN_UNIX_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <afunix.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#endif

typedef SOCKET socket_t;
#define POLL_SOCKET WSAPoll
#define CLOSE_SOCKET closesocket
#define INVALID_SOCK INVALID_SOCKET
#define IS_VALID_SOCKET(s) ((s) != INVALID_SOCKET)
#define GET_LAST_SOCKET_ERROR() WSAGetLastError()
#define INIT_SOCKET_IF_NEEDED() lbridge_win_wsa_init()
#define IOCTL(s, cmd, arg) ioctlsocket((s), (cmd), (arg))
extern _Bool lbridge_win_wsa_init();
#define LBRIDGE_EINPROGRESS WSAEINPROGRESS
#define LBRIDGE_EWOULDBLOCK WSAEWOULDBLOCK 
#define LBRIDGE_ECONNREFUSED WSAECONNREFUSED
#define LBRIDGE_ETIMEDOUT WSAETIMEDOUT
#define LBRIDGE_ECONNABORTED WSAECONNABORTED

inline _Bool lbridge_socket_set_nonblocking(socket_t s, _Bool nonblocking)
{
	u_long mode = nonblocking ? 1 : 0;
	int result = ioctlsocket(s, FIONBIO, &mode);
	return (result == 0);
}

#elif defined(__unix__) || defined(__APPLE__)

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

typedef int socket_t;
#define POLL_SOCKET poll
#define CLOSE_SOCKET close
#define INVALID_SOCK -1
#define IS_VALID_SOCKET(s) ((s) >= 0)
#define GET_LAST_SOCKET_ERROR() errno
#define INIT_SOCKET_IF_NEEDED() (true)
#define IOCTL(s, cmd, arg) ioctl((s), (cmd), (arg))

#define LBRIDGE_EINPROGRESS EINPROGRESS
#define LBRIDGE_EWOULDBLOCK EWOULDBLOCK 
#define LBRIDGE_ECONNREFUSED ECONNREFUSED
#define LBRIDGE_ETIMEDOUT ETIMEDOUT
#define LBRIDGE_ECONNABORTED ECONNABORTED

inline _Bool lbridge_socket_set_nonblocking(socket_t s, _Bool nonblocking)
{
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0)
        return false;

    if (nonblocking)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    return fcntl(s, F_SETFL, flags) == 0;
}

#endif

#ifdef __cplusplus
}
#endif

#endif // LBRIDGE_SOCKET_WIN_UNIX_H
