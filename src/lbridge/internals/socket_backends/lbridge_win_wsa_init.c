#ifdef _WIN32

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "lbridge_socket_win_unix.h"

static _Bool g_lbridge_wsa_initialized = false;

_Bool lbridge_win_wsa_init()
{
	if (g_lbridge_wsa_initialized)
	{
		return true;
	}
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		return false;
	}
	g_lbridge_wsa_initialized = true;
	return true;
}

#ifdef __cplusplus
}
#endif

#endif // _WIN32