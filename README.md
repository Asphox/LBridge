# LBridge

**LBridge** is a lightweight, cross-platform RPC (Remote Procedure Call) library written in C, designed for embedded systems, IoT devices, and inter-process communication.

## Features

- **Minimal footprint** - Small memory and code size
- **Cross-platform** - Windows (WinSock2) and Unix (POSIX sockets)
- **Multiple transports** - TCP/IP and Unix domain sockets (Windows 10 1803+, Linux, macOS)
- **Optional encryption** - ChaCha20-Poly1305 AEAD cipher
- **Message fragmentation** - Large payloads split across multiple frames
- **Custom allocators** - Bring your own malloc/free
- **Simple API** - Blocking client, event-driven server
- **Client timeout** - Automatic disconnection of inactive clients

## Table of Contents

- [Building](#building)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Protocol Specification](#protocol-specification)
  - [Frame Format](#frame-format)
  - [Command Frames](#command-frames)
  - [Handshake](#handshake)
  - [RPC Call Flow](#rpc-call-flow)
  - [Fragmentation](#fragmentation)
  - [Encryption](#encryption)
- [Sequence Diagrams](#sequence-diagrams)
- [Error Codes](#error-codes)
- [License](#license)

---

## Building

### CMake

```bash
# Configure
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release

# Run tests
./build/bin/lbridge_test
```

### Compile-time Options

| Define | Description |
|--------|-------------|
| `LBRIDGE_ENABLE_CLIENT` | Enable client functionality (default: enabled) |
| `LBRIDGE_ENABLE_SERVER` | Enable server functionality (default: enabled) |
| `LBRIDGE_ENABLE_SECURE` | Enable ChaCha20-Poly1305 encryption (default: enabled) |
| `LBRIDGE_ENABLE_TCP_CLIENT` | Enable TCP client transport |
| `LBRIDGE_ENABLE_TCP_SERVER` | Enable TCP server transport |
| `LBRIDGE_ENABLE_UNIX_CLIENT` | Enable Unix domain socket client transport |
| `LBRIDGE_ENABLE_UNIX_SERVER` | Enable Unix domain socket server transport |

---

## Quick Start

### Server

```c
#include "lbridge.h"

bool on_rpc_call(const lbridge_rpc_context_t ctx, const uint8_t* data, uint32_t size)
{
    uint16_t rpc_id = lbridge_rpc_context_get_rpc_id(ctx);

    // Process request and send response
    uint8_t response[] = { 0x01, 0x02, 0x03 };
    lbridge_rpc_context_send_response(ctx, response, sizeof(response));
    return true;
}

int main()
{
    struct lbridge_context_params params = {
        .fp_generate_nonce = my_nonce_generator,  // Required if encryption enabled
        .fp_malloc = NULL,      // NULL = use standard malloc
        .fp_free = NULL,        // NULL = use standard free
        .fp_get_time_ms = NULL  // NULL = disable client timeout feature
    };

    lbridge_context_t ctx = lbridge_context_create(&params);
    lbridge_server_t server = lbridge_server_create(ctx, 1024, 65536, on_rpc_call);

    lbridge_server_listen_tcp(server, "127.0.0.1", 26412, 10);  // max 10 clients

    // Optional: disconnect inactive clients after 30 seconds
    // Requires fp_get_time_ms to be set in context params
    lbridge_server_set_client_timeout(server, 30000);

    while (1) {
        lbridge_server_update(server);
    }

    lbridge_server_destroy(server);
    lbridge_context_destroy(ctx);
}
```

### Client

```c
#include "lbridge.h"

int main()
{
    struct lbridge_context_params params = {
        .fp_generate_nonce = my_nonce_generator,
    };

    lbridge_context_t ctx = lbridge_context_create(&params);
    lbridge_client_t client = lbridge_client_create(ctx, 1024, 65536);

    if (lbridge_client_connect_tcp(client, "127.0.0.1", 26412))
    {
        uint8_t buffer[256] = { 0xAA, 0xBB, 0xCC };
        uint32_t size = 3;

        if (lbridge_client_call_rpc(client, 0x1234, buffer, &size, sizeof(buffer)))
        {
            // buffer now contains response, size is response length
        }
    }

    lbridge_client_destroy(client);
    lbridge_context_destroy(ctx);
}
```

### Unix Domain Socket (Server)

```c
#include "lbridge.h"

// Same RPC callback as TCP...

int main()
{
    struct lbridge_context_params params = {
        .fp_generate_nonce = my_nonce_generator,
        .fp_get_time_ms = NULL
    };

    lbridge_context_t ctx = lbridge_context_create(&params);
    lbridge_server_t server = lbridge_server_create(ctx, 1024, 65536, on_rpc_call);

    // Listen on Unix domain socket
    // On Windows: use a path like "C:\\temp\\myapp.sock"
    // On Linux/macOS: use a path like "/tmp/myapp.sock"
    lbridge_server_listen_unix(server, "/tmp/myapp.sock", 10);

    while (1) {
        lbridge_server_update(server);
    }

    lbridge_server_destroy(server);
    lbridge_context_destroy(ctx);
}
```

### Unix Domain Socket (Client)

```c
#include "lbridge.h"

int main()
{
    struct lbridge_context_params params = {
        .fp_generate_nonce = my_nonce_generator,
    };

    lbridge_context_t ctx = lbridge_context_create(&params);
    lbridge_client_t client = lbridge_client_create(ctx, 1024, 65536);

    if (lbridge_client_connect_unix(client, "/tmp/myapp.sock"))
    {
        uint8_t buffer[256] = { 0xAA, 0xBB, 0xCC };
        uint32_t size = 3;

        if (lbridge_client_call_rpc(client, 0x1234, buffer, &size, sizeof(buffer)))
        {
            // buffer now contains response
        }
    }

    lbridge_client_destroy(client);
    lbridge_context_destroy(ctx);
}
```

---

## API Reference

### Context

```c
lbridge_context_t lbridge_context_create(struct lbridge_context_params* params);
void lbridge_context_destroy(lbridge_context_t context);
```

### Client

```c
lbridge_client_t lbridge_client_create(lbridge_context_t ctx, uint16_t max_frame_payload_size, uint32_t max_payload_size);
void lbridge_client_destroy(lbridge_client_t client);
bool lbridge_client_connect_tcp(lbridge_client_t client, const char* host, uint16_t port);
bool lbridge_client_connect_unix(lbridge_client_t client, const char* socket_path);
bool lbridge_client_call_rpc(lbridge_client_t client, uint16_t rpc_id, uint8_t* inout_data, uint32_t* inout_size, uint32_t max_out_size);
bool lbridge_client_ping(lbridge_client_t client);
```

> **Note:** `lbridge_client_connect_unix()` connects via Unix domain socket. On Windows, Unix domain sockets are supported since Windows 10 version 1803.

> **Note:** `lbridge_client_ping()` sends a lightweight keep-alive command to the server to refresh the inactivity timeout. Useful when the server has client timeout enabled and the client needs to stay connected without sending actual RPCs.

### Server

```c
lbridge_server_t lbridge_server_create(lbridge_context_t ctx, uint16_t max_frame_payload_size, uint32_t max_payload_size, fp_rpc_call callback);
void lbridge_server_destroy(lbridge_server_t server);
bool lbridge_server_listen_tcp(lbridge_server_t server, const char* address, uint16_t port, uint32_t max_clients);
bool lbridge_server_listen_unix(lbridge_server_t server, const char* socket_path, uint32_t max_clients);
bool lbridge_server_update(lbridge_server_t server);
void lbridge_server_set_client_timeout(lbridge_server_t server, uint32_t timeout_ms);
```

> **Note:** The `max_clients` parameter is passed to `lbridge_server_listen_tcp()` / `lbridge_server_listen_unix()` rather than `lbridge_server_create()` because the maximum number of connections is transport-specific. For example, serial transports only support a single connection.

> **Note:** `lbridge_server_listen_unix()` creates a Unix domain socket at the specified path. If a socket file already exists at that path, it will be removed before creating the new socket. On Windows, Unix domain sockets are supported since Windows 10 version 1803.

> **Note:** `lbridge_server_set_client_timeout()` sets the inactivity timeout for clients. If a client doesn't send any data for the specified duration, it will be automatically disconnected. This feature requires `fp_get_time_ms` to be set in the context params. Set to 0 to disable (default).

### RPC Context (Server Callbacks)

```c
uint16_t lbridge_rpc_context_get_rpc_id(const lbridge_rpc_context_t ctx);
bool lbridge_rpc_context_send_response(const lbridge_rpc_context_t ctx, const uint8_t* data, uint32_t size);
bool lbridge_rpc_context_send_error(const lbridge_rpc_context_t ctx, enum lbridge_protocol_error error);
```

> **Note:** These functions are used within RPC callbacks on the server side. `lbridge_rpc_context_send_error()` sends a CLOSE frame with the specified protocol error and disconnects the client.

### Common

```c
void lbridge_set_timeout(lbridge_object_t object, int32_t timeout_ms);
void lbridge_activate_encryption(lbridge_object_t object, const uint8_t* key_256bits);
enum lbridge_error_code lbridge_get_last_error(const lbridge_object_t object);
```

---

## Protocol Specification

### Frame Format

Every LBridge message consists of one or more **frames**. Each frame has a 4-byte (32-bit) header followed by an optional payload.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|S|E|N|C|         RPC_ID / CMD_DATA           |  PAYLOAD_LEN    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         PAYLOAD (0-4095 bytes)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Header Fields

| Bit(s) | Name | Description |
|--------|------|-------------|
| 0 | **S** (START) | First frame of a message sequence |
| 1 | **E** (END) | Last frame of a message sequence |
| 2 | **N** (NO_RESPONSE) | RPC does not expect a response (fire-and-forget) |
| 3 | **C** (CMD) | Command frame (not an RPC) |
| 4-19 | **RPC_ID** / **CMD_DATA** | 16-bit RPC identifier, or command-specific data if C=1 |
| 20-31 | **PAYLOAD_LEN** | Payload length in bytes (0-4095) |

#### Frame Types

| S | E | Type | Description |
|---|---|------|-------------|
| 1 | 1 | Single | Complete message in one frame |
| 1 | 0 | Start | First frame of a fragmented message |
| 0 | 0 | Continue | Middle frame of a fragmented message |
| 0 | 1 | End | Last frame of a fragmented message |

---

### Command Frames

When **C=1**, the frame is a command frame. The RPC_ID field becomes CMD_DATA with the following format:

```
CMD_DATA (16 bits):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  OPCODE |     OPCODE DATA     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  4 bits        12 bits
```

#### Opcodes

| Opcode | Name | Description |
|--------|------|-------------|
| 0x0 | **HELLO** | Handshake command |
| 0x1 | **CLOSE** | Connection close command |
| 0x2 | **PING** | Keep-alive / refresh timeout |

#### HELLO Command (Opcode 0x0)

Used during handshake to negotiate parameters.

```
CMD_DATA for HELLO:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| 0x0 |E|      Reserved         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ^
       Encryption flag (1 = encryption requested)

PAYLOAD_LEN field: max_frame_payload_size supported by sender
```

If encryption is requested, 12 bytes of nonce follow the header.

#### CLOSE Command (Opcode 0x1)

Used to gracefully close a connection.

```
CMD_DATA for CLOSE:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| 0x1 | Reserved |    ERROR      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  4b     4 bits     8 bits

ERROR: lbridge_protocol_error code (0 = no error)
```

#### PING Command (Opcode 0x2)

Used to refresh the server's inactivity timeout without sending RPC data.

```
CMD_DATA for PING:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| 0x2 |        Reserved         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  4b          12 bits

PAYLOAD_LEN: 0 (no payload)
```

No response is sent by the server. The client can use `lbridge_client_ping()` to send this command.

---

### Handshake

The handshake establishes connection parameters and optionally sets up encryption.

#### Without Encryption

```
Client                                          Server
   |                                               |
   |  HELLO (S=1,E=1,C=1,enc=0,plen=max_frame)    |
   |---------------------------------------------->|
   |                                               |
   |  HELLO (S=1,E=1,C=1,enc=0,plen=negotiated)   |
   |<----------------------------------------------|
   |                                               |
   |            Connection Established             |
```

#### With Encryption

```
Client                                          Server
   |                                               |
   |  HELLO (enc=1,plen=max_frame) + client_nonce |
   |---------------------------------------------->|
   |                                               |
   |  HELLO (enc=1,plen=negotiated) + server_nonce|
   |<----------------------------------------------|
   |                                               |
   |     shared_nonce = client_nonce XOR server_nonce
   |     send_nonce = shared_nonce
   |     recv_nonce = shared_nonce XOR (1 << 63)
   |                                               |
   |         Encrypted Connection Established      |
```

The negotiated `max_frame_payload_size` is `min(client_max, server_max)`.

---

### RPC Call Flow

#### Request with Response

```
Client                                          Server
   |                                               |
   |  RPC Request (rpc_id=X, data)                |
   |---------------------------------------------->|
   |                                               |
   |                                    [callback(rpc_id, data)]
   |                                               |
   |  RPC Response (rpc_id=X, response_data)      |
   |<----------------------------------------------|
   |                                               |
```

#### Fire-and-Forget (NO_RESPONSE=1)

```
Client                                          Server
   |                                               |
   |  RPC Request (rpc_id=X, N=1, data)           |
   |---------------------------------------------->|
   |                                               |
   |                                    [callback(rpc_id, data)]
   |                                               |
   |              (no response sent)               |
```

---

### Fragmentation

Messages larger than `max_frame_payload_size` are split into multiple frames.

```
Original message: [AAAAABBBBBCCC] (13 bytes, max_frame=5)

Frame 1 (START):    S=1, E=0, plen=5, payload=[AAAAA]
Frame 2 (CONTINUE): S=0, E=0, plen=5, payload=[BBBBB]
Frame 3 (END):      S=0, E=1, plen=3, payload=[CCC]
```

All frames in a sequence share the same `RPC_ID`.

---

### Encryption

LBridge uses **ChaCha20-Poly1305** AEAD encryption when enabled.

#### Key Setup

- Both client and server must have the same 256-bit (32-byte) pre-shared key
- Call `lbridge_activate_encryption(object, key)` before connecting

#### Nonce Management

- 12-byte (96-bit) nonce per message
- Nonce = `base_nonce || counter` where counter is 64-bit
- Send and receive use different counters (bit 63 flipped)
- Counter increments after each successful message

#### Authenticated Data

Frame headers are included as **Additional Authenticated Data (AAD)**:

```
AAD = header_frame1 || header_frame2 || ... || header_frameN
```

This ensures frame headers cannot be tampered with.

#### Ciphertext Format

```
+------------------+---------------------+
|  Encrypted Data  |  Auth Tag (8 bytes) |
+------------------+---------------------+
```

The authentication tag is truncated to 8 bytes (64 bits) for efficiency.

#### Encryption Flow

```
1. Build all frame headers for the message
2. Initialize ChaCha20-Poly1305 with key and nonce
3. Add all headers to AAD
4. Encrypt plaintext data
5. Generate and truncate auth tag to 8 bytes
6. Append tag to ciphertext
7. Send frames with encrypted payload
8. Increment nonce counter
```

---

## Sequence Diagrams

### Full Connection Lifecycle

```
Client                                          Server
   |                                               |
   |================ TCP CONNECT ==================|
   |                                               |
   |  HELLO (max_frame=1024, enc=1, nonce_c)      |
   |---------------------------------------------->|
   |                                               |
   |  HELLO (max_frame=512, enc=1, nonce_s)       |
   |<----------------------------------------------|
   |                                               |
   |  [negotiated: max_frame=512, encrypted]       |
   |                                               |
   |  RPC #1 Request (rpc_id=0xABCD)              |
   |---------------------------------------------->|
   |  RPC #1 Response                              |
   |<----------------------------------------------|
   |                                               |
   |  RPC #2 Request (rpc_id=0x1234, N=1)         |
   |---------------------------------------------->|
   |              (no response - fire & forget)    |
   |                                               |
   |  CLOSE (error=0)                              |
   |---------------------------------------------->|
   |                                               |
   |=============== TCP DISCONNECT ================|
```

### Fragmented Message

```
Client                                          Server
   |                                               |
   |  Frame 1: S=1,E=0,rpc=0x100,plen=512,[data]  |
   |---------------------------------------------->|
   |                                               |
   |  Frame 2: S=0,E=0,rpc=0x100,plen=512,[data]  |
   |---------------------------------------------->|
   |                                               |
   |  Frame 3: S=0,E=1,rpc=0x100,plen=200,[data]  |
   |---------------------------------------------->|
   |                                               |
   |                         [reassemble & decrypt]|
   |                         [callback(0x100, data)]
   |                                               |
   |  Response: S=1,E=1,rpc=0x100,plen=50,[resp]  |
   |<----------------------------------------------|
```

---

## Error Codes

### API Error Codes (`lbridge_error_code`)

| Code | Name | Description |
|------|------|-------------|
| 0 | `LBRIDGE_ERROR_NONE` | No error |
| 1 | `LBRIDGE_ERROR_BAD_ALLOC` | Memory allocation failed |
| 2 | `LBRIDGE_ERROR_BAD_ARGUMENT` | Invalid argument |
| 3 | `LBRIDGE_ERROR_CONNECTION_TIMEOUT` | Connection timed out |
| 4 | `LBRIDGE_ERROR_CONNECTION_FAILED` | Connection refused |
| 5 | `LBRIDGE_ERROR_CONNECTION_UNKNOWN` | Unknown connection error |
| 6 | `LBRIDGE_ERROR_NOT_CONNECTED` | Not connected |
| 7 | `LBRIDGE_ERROR_CONNECTION_LOST` | Connection lost |
| 8 | `LBRIDGE_ERROR_SEND_TIMEOUT` | Send timed out |
| 9 | `LBRIDGE_ERROR_SEND_FAILED` | Send failed |
| 10 | `LBRIDGE_ERROR_SEND_UNKNOWN` | Unknown send error |
| 11 | `LBRIDGE_ERROR_RECEIVE_TIMEOUT` | Receive timed out |
| 12 | `LBRIDGE_ERROR_SERVER_OPEN_FAILED` | Server bind failed |
| 13 | `LBRIDGE_ERROR_HANDSHAKE_FAILED` | Handshake failed |
| 14 | `LBRIDGE_ERROR_TOO_MUCH_DATA` | Payload too large |
| 15 | `LBRIDGE_ERROR_AUTHENTICATION_FAILED` | Decryption auth failed |
| 255 | `LBRIDGE_ERROR_UNKNOWN` | Unknown error |

### Protocol Error Codes (`lbridge_protocol_error`)

Sent in CLOSE frames to indicate why a connection was terminated.

| Code | Name | Description |
|------|------|-------------|
| 0 | `LBRIDGE_PROTOCOL_ERROR_NONE` | Normal close |
| 1 | `LBRIDGE_PROTOCOL_ERROR_UNKNOWN` | Unknown error |
| 2 | `LBRIDGE_PROTOCOL_ERROR_INTERNAL` | Internal error |
| 3 | `LBRIDGE_PROTOCOL_ERROR_INVALID_PAYLOAD_LENGTH` | Invalid payload length |
| 4 | `LBRIDGE_PROTOCOL_ERROR_AUTHENTICATION_FAILED` | Auth tag mismatch |
| 5 | `LBRIDGE_PROTOCOL_ERROR_INVALID_FRAME_FLAG` | Invalid frame flags |
| 6 | `LBRIDGE_PROTOCOL_ERROR_INVALID_OPCODE_HANDSHAKE` | Invalid handshake opcode |
| 7 | `LBRIDGE_PROTOCOL_ERROR_ENCRYPTION_NOT_ACTIVATED_ON_SERVER` | Server has no key |
| 8 | `LBRIDGE_PROTOCOL_ERROR_ENCRYPTION_NOT_SUPPORTED_ON_SERVER` | Server compiled without encryption |
| 9 | `LBRIDGE_PROTOCOL_ERROR_HANDSHAKE_ERROR` | Generic handshake error |
| 10 | `LBRIDGE_PROTOCOL_ERROR_INVALID_COMMAND` | Unknown command opcode |
| 11 | `LBRIDGE_PROTOCOL_ERROR_PAYLOAD_TOO_LARGE` | Payload exceeds max size |

---

## Security Considerations

1. **Pre-shared key** - LBridge does not perform key exchange. Keys must be provisioned out-of-band.

2. **Truncated auth tag** - The 8-byte (64-bit) authentication tag provides less security than the standard 16-byte tag. This is a trade-off for efficiency in resource-constrained environments.

3. **No replay protection across sessions** - Nonces reset on reconnection. An attacker could replay captured messages from a previous session if the same key is used.

4. **No forward secrecy** - Compromise of the pre-shared key allows decryption of all past and future messages.

For high-security applications, consider:
- Using unique keys per session
- Implementing key rotation
- Adding session tokens to the handshake

---

## License

MIT License - See LICENSE file for details.

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

## Latest Tests

| Platform | Compiler | Status |
|----------|----------|--------|
| Windows | MSVC 2022 | [![Windows MSVC](https://github.com/Asphox/LBridge/actions/workflows/test-windows-msvc.yml/badge.svg)](https://github.com/Asphox/LBridge/actions/workflows/test-windows-msvc.yml) |
| Windows | Clang | [![Windows Clang](https://github.com/Asphox/LBridge/actions/workflows/test-windows-clang.yml/badge.svg)](https://github.com/Asphox/LBridge/actions/workflows/test-windows-clang.yml) |
| Windows | MinGW | [![Windows MinGW](https://github.com/Asphox/LBridge/actions/workflows/test-windows-mingw.yml/badge.svg)](https://github.com/Asphox/LBridge/actions/workflows/test-windows-mingw.yml) |
| Linux | GCC | [![Linux GCC](https://github.com/Asphox/LBridge/actions/workflows/test-linux-gcc.yml/badge.svg)](https://github.com/Asphox/LBridge/actions/workflows/test-linux-gcc.yml) |
| Linux | Clang | [![Linux Clang](https://github.com/Asphox/LBridge/actions/workflows/test-linux-clang.yml/badge.svg)](https://github.com/Asphox/LBridge/actions/workflows/test-linux-clang.yml) |
| macOS | Apple Clang | [![macOS](https://github.com/Asphox/LBridge/actions/workflows/test-macos.yml/badge.svg)](https://github.com/Asphox/LBridge/actions/workflows/test-macos.yml) |
