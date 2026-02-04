#ifndef LBRIDGE_SOCKET_BLUETOOTH_H
#define LBRIDGE_SOCKET_BLUETOOTH_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
// Windows Bluetooth headers
#include <winsock2.h>
#include <ws2bth.h>
#include <bluetoothapis.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bthprops.lib")

typedef SOCKET bt_socket_t;
#define BT_INVALID_SOCKET INVALID_SOCKET
#define BT_IS_VALID_SOCKET(s) ((s) != INVALID_SOCKET)
#define BT_CLOSE_SOCKET closesocket
#define BT_GET_LAST_ERROR() WSAGetLastError()

// Parse Bluetooth address from string "XX:XX:XX:XX:XX:XX" to BTH_ADDR (uint64)
static inline int lbridge_bt_str_to_addr(const char* str, BTH_ADDR* addr)
{
    unsigned int b[6];
    if (sscanf_s(str, "%02X:%02X:%02X:%02X:%02X:%02X",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
    {
        return -1;
    }
    *addr = 0;
    for (int i = 0; i < 6; i++)
    {
        *addr = (*addr << 8) | (uint8_t)b[i];
    }
    return 0;
}

#elif defined(__linux__)
// Linux BlueZ headers
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

typedef int bt_socket_t;
#define BT_INVALID_SOCKET -1
#define BT_IS_VALID_SOCKET(s) ((s) >= 0)
#define BT_CLOSE_SOCKET close
#define BT_GET_LAST_ERROR() errno

// Parse Bluetooth address from string using BlueZ str2ba
static inline int lbridge_bt_str_to_addr(const char* str, bdaddr_t* addr)
{
    return str2ba(str, addr);
}

static inline int lbridge_bt_socket_set_nonblocking(bt_socket_t s, int nonblocking)
{
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (nonblocking)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    return fcntl(s, F_SETFL, flags);
}

#endif // __linux__

#ifdef __cplusplus
}
#endif

#endif // LBRIDGE_SOCKET_BLUETOOTH_H
