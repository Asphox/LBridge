#ifndef LBRIDGE_H
#define	LBRIDGE_H

#ifndef LBRIDGE_ENABLE_CLIENT
#define LBRIDGE_ENABLE_CLIENT
#endif

#ifndef LBRIDGE_ENABLE_SERVER
#define LBRIDGE_ENABLE_SERVER
#endif

#ifndef LBRIDGE_ENABLE_SECURE
#define LBRIDGE_ENABLE_SECURE
#endif

#if defined(LBRIDGE_ENABLE_CLIENT)

#ifndef LBRIDGE_ENABLE_TCP_CLIENT
#define LBRIDGE_ENABLE_TCP_CLIENT
#endif

#ifndef LBRIDGE_ENABLE_UNIX_CLIENT
#define LBRIDGE_ENABLE_UNIX_CLIENT
#endif

#ifndef LBRIDGE_ENABLE_BLE_CLIENT
#define LBRIDGE_ENABLE_BLE_CLIENT
#endif

#ifndef LBRIDGE_ENABLE_SERIAL_CLIENT
#define LBRIDGE_ENABLE_SERIAL_CLIENT
#endif

#endif // LBRIDGE_ENABLE_CLIENT

#ifdef LBRIDGE_ENABLE_SERVER

#ifndef LBRIDGE_ENABLE_TCP_SERVER
#define LBRIDGE_ENABLE_TCP_SERVER
#endif

#ifndef LBRIDGE_ENABLE_UNIX_SERVER
#define LBRIDGE_ENABLE_UNIX_SERVER
#endif

#endif // LBRIDGE_ENABLE_SERVER

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER)
	// Microsoft Visual C++
#define LBRIDGE_API __cdecl
#elif defined(__GNUC__) || defined(__clang__)
	// GCC or Clang - cdecl only meaningful on x86
#if defined(__i386__)
#define LBRIDGE_API __attribute__((cdecl))
#else
#define LBRIDGE_API
#endif
#else
	// Fallback for other compilers
#define LBRIDGE_API
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Error codes returned by LBridge functions.
 *
 * Use lbridge_get_last_error() to retrieve the last error code after a function returns false.
 */
enum lbridge_error_code
{
	LBRIDGE_ERROR_NONE,                  /**< No error occurred. */
	LBRIDGE_ERROR_BAD_ALLOC,             /**< Memory allocation failed. */
	LBRIDGE_ERROR_BAD_ARGUMENT,          /**< Invalid argument passed to a function. */
	LBRIDGE_ERROR_CONNECTION_TIMEOUT,    /**< Connection attempt timed out. */
	LBRIDGE_ERROR_CONNECTION_FAILED,     /**< Connection was refused by the remote host. */
	LBRIDGE_ERROR_CONNECTION_UNKNOWN,    /**< Unknown error during connection. */
	LBRIDGE_ERROR_NOT_CONNECTED,         /**< Operation attempted on a disconnected object. */
	LBRIDGE_ERROR_CONNECTION_LOST,       /**< Connection was lost during operation. */
	LBRIDGE_ERROR_SEND_TIMEOUT,          /**< Send operation timed out. */
	LBRIDGE_ERROR_SEND_FAILED,           /**< Send operation failed. */
	LBRIDGE_ERROR_SEND_UNKNOWN,          /**< Unknown error during send operation. */
	LBRIDGE_ERROR_RECEIVE_TIMEOUT,       /**< Receive operation timed out. */
	LBRIDGE_ERROR_SERVER_OPEN_FAILED,    /**< Server failed to bind or listen on the specified address/port. */
	LBRIDGE_ERROR_RESSOURCE_UNAVAILABLE,  /**< Required resource is unavailable. */
	LBRIDGE_ERROR_HANDSHAKE_FAILED,      /**< Protocol handshake with remote peer failed. */
	LBRIDGE_ERROR_TOO_MUCH_DATA,         /**< Payload size exceeds the maximum allowed size. */
	LBRIDGE_ERROR_AUTHENTICATION_FAILED, /**< Encryption authentication tag verification failed. */
	LRBDIGE_ERROR_PROTOCOL_VIOLATION,    /**< Protocol violation detected. */
	LBRIDGE_ERROR_INVALID_RPC_ID,       /**< Invalid RPC ID specified. */
	LBRIDGE_ERROR_UNKNOWN = 255,         /**< Unknown or unspecified error. */
};

/**
 * @brief Protocol error codes sent in CLOSE frames.
 *
 * These codes indicate why a connection was terminated and are sent
 * to the remote peer in a CLOSE command frame.
 */
enum lbridge_protocol_error
{
	LBRIDGE_PROTOCOL_ERROR_NONE = 0,                          /**< Normal close, no error. */
	LBRIDGE_PROTOCOL_ERROR_UNKNOWN,                           /**< Unknown error. */
	LBRIDGE_PROTOCOL_ERROR_INTERNAL,                          /**< Internal server error. */
	LBRIDGE_PROTOCOL_ERROR_INVALID_PAYLOAD_LENGTH,            /**< Invalid payload length in frame. */
	LBRIDGE_PROTOCOL_ERROR_AUTHENTICATION_FAILED,             /**< Encryption authentication tag mismatch. */
	LBRIDGE_PROTOCOL_ERROR_INVALID_FRAME_FLAG,                /**< Invalid frame flags combination. */
	LBRIDGE_PROTOCOL_ERROR_INVALID_OPCODE_HANDSHAKE,          /**< Invalid opcode during handshake. */
	LBRIDGE_PROTOCOL_ERROR_ENCRYPTION_NOT_ACTIVATED_ON_SERVER,/**< Server has no encryption key configured. */
	LBRIDGE_PROTOCOL_ERROR_ENCRYPTION_NOT_SUPPORTED_ON_SERVER,/**< Server compiled without encryption support. */
	LBRIDGE_PROTOCOL_ERROR_HANDSHAKE_ERROR,                   /**< Generic handshake error. */
	LBRIDGE_PROTOCOL_ERROR_INVALID_COMMAND,                   /**< Unknown command opcode received. */
	LBRIDGE_PROTOCOL_ERROR_PAYLOAD_TOO_LARGE,                 /**< Payload exceeds maximum allowed size. */
	LBRIDGE_PROTOCOL_ERROR_INACTIVITY_TIMEOUT,                /**< Client disconnected due to inactivity. */
	LBRIDGE_PROTOCOL_ERROR_INVALID_RPC_ID,                    /**< Invalid RPC ID received. */
};

/**
 * @brief Transport types supported by LBridge.
 *
 * Indicates the underlying transport layer used by a client or server.
 */
enum lbridge_type
{
	LBRIDGE_TYPE_UNKNOWN = 0, /**< Unknown or uninitialized transport type. */
	LBRIDGE_TYPE_TCP,         /**< TCP/IP socket transport. */
	LBRIDGE_TYPE_UNIX,        /**< Unix domain socket transport (not yet implemented). */
	LBRIDGE_TYPE_BLE,         /**< Bluetooth Low Energy transport (not yet implemented). */
	LBRIDGE_TYPE_SERIAL       /**< Serial port transport (not yet implemented). */
};

/**
 * @brief Opaque handle to the global LBridge context.
 *
 * Created by lbridge_create_context() and used internally by the library.
 * Objects that live in different threads MUST use separate contexts.
 */
typedef struct lbridge_context* lbridge_context_t;

/**
 * @brief Parameters for initializing the LBridge context.
 *
 * Must be provided when creating a new LBridge context with lbridge_context_create().
 * fp_generate_nonce is required if LBRIDGE_ENABLE_SECURE is defined.
 * fp_get_time_ms is optional but required for server-side client timeout feature.
 */
struct lbridge_context_params
{
#if defined(LBRIDGE_ENABLE_SECURE)
	bool (*fp_generate_nonce)(lbridge_context_t context, uint8_t out_nonce[12]);
#endif // LBRIDGE_ENABLE_SECURE
	void* (*fp_malloc)(size_t size);
	void  (*fp_free)(void* ptr);
	/**
	 * @brief Optional callback to get monotonic time in milliseconds.
	 *
	 * This callback is required for server-side client timeout feature.
	 * The returned time should be monotonic (not affected by system clock changes).
	 * If NULL, server client timeout feature will be disabled.
	 *
	 * @param context The LBridge context.
	 * @return Current time in milliseconds (monotonic).
	 */
	uint64_t (*fp_get_time_ms)(lbridge_context_t context);
};

/**
 * @brief Initializes the LBridge library and creates a global context.
 *
 * Must be called before any other LBridge functions.
 * Objects that live in different threads MUST use separate contexts.
 *
 * @return A handle to the global LBridge context.
 */
lbridge_context_t LBRIDGE_API lbridge_context_create(struct lbridge_context_params* p_params);

/**
 * @brief Destroys a previously created LBridge context and frees all associated resources.
 *
 * @param context The LBridge context to destroy.
 * 
 * @note All clients and servers created with this context must be destroyed BEFORE calling this function.
 */
void LBRIDGE_API lbridge_context_destroy(lbridge_context_t context);

/**
 * @brief Opaque handle to a generic LBridge object (client or server).
 *
 * Used by functions that operate on both clients and servers, such as
 * lbridge_get_last_error(), lbridge_set_timeout(), and lbridge_activate_encryption().
 */
typedef void* lbridge_object_t;

/**
 * @brief Opaque handle to an RPC context.
 *
 * Passed to RPC callback functions on the server side. Contains information about
 * the current RPC invocation and the connection it originated from.
 */
typedef struct lbridge_rpc_context* lbridge_rpc_context_t;

/**
 * @brief Callback function type for handling incoming RPC calls on the server.
 *
 * @param ctx  The RPC context for this call. Use lbridge_rpc_context_get_rpc_id() to get the RPC ID.
 * @param data Pointer to the received data payload.
 * @param size Size of the received data payload in bytes.
 *
 * @return true if the RPC was handled successfully, false otherwise.
 *
 * @note The callback must call lbridge_rpc_context_send_response() to send a response back to the client,
 *       unless the client specified that no response is expected.
 */
typedef bool(*fp_rpc_call)(const lbridge_rpc_context_t ctx, const uint8_t* data, uint32_t size);

/**
 * @brief Retrieves the RPC ID from an RPC context.
 *
 * @param ctx The RPC context provided to the RPC callback.
 *
 * @return The 16-bit RPC identifier for this call.
 */
uint16_t LBRIDGE_API lbridge_rpc_context_get_rpc_id(const lbridge_rpc_context_t ctx);

/**
 * @brief Retrieves the last error code for a given LBridge object.
 *
 * @param object The LBridge object (client or server) to query.
 *
 * @return The last error code, or LBRIDGE_ERROR_NONE if no error occurred.
 */
enum lbridge_error_code LBRIDGE_API lbridge_get_last_error(const lbridge_object_t object);

/**
 * @brief Sends a response to an RPC call from within a server callback.
 *
 * @param ctx  The RPC context provided to the RPC callback.
 * @param data Pointer to the response data to send.
 * @param size Size of the response data in bytes.
 *
 * @return true if the response was sent successfully, false otherwise.
 *
 * @note This function must be called from within an RPC callback on the server side.
 */
bool LBRIDGE_API lbridge_rpc_context_send_response(const lbridge_rpc_context_t ctx, const uint8_t* data, uint32_t size);

/**
 * @brief Sends an error to the client from within an RPC callback.
 *
 * This function sends a CLOSE command frame with the specified protocol error code
 * and disconnects the client.
 *
 * @param ctx   The RPC context provided to the RPC callback.
 * @param error The protocol error code to send to the client.
 *
 * @return true if the error was sent successfully, false otherwise.
 *
 * @note This function must be called from within an RPC callback on the server side.
 * @note After calling this function, the client connection will be closed.
 */
bool LBRIDGE_API lbridge_rpc_context_send_error(const lbridge_rpc_context_t ctx, enum lbridge_protocol_error error);

/**
 * @brief Sets the timeout for operations on a LBridge object.
 *
 * @param object     The LBridge object (client or server) to configure.
 * @param timeout_ms Timeout in milliseconds. Use -1 for infinite timeout, 0 for non-blocking.
 */
void LBRIDGE_API lbridge_set_timeout(lbridge_object_t object, int32_t timeout_ms);

#if defined(LBRIDGE_ENABLE_SECURE)
/**
 * @brief Activates ChaCha20-Poly1305 encryption for a LBridge object.
 *
 * Once activated, all subsequent communication will be encrypted and authenticated.
 * Both client and server must use the same key for successful communication.
 *
 * @param object      The LBridge object (client or server) to configure.
 * @param key_256bits Pointer to a 256-bit (32-byte) encryption key.
 *
 * @warning The key must remain valid and unchanged for the lifetime of the connection.
 */
void LBRIDGE_API lbridge_activate_encryption(lbridge_object_t object, const uint8_t key_256bits[32]);
#endif // LBRIDGE_ENABLE_SECURE

#if defined(LBRIDGE_ENABLE_CLIENT)

/**
 * @brief Opaque handle to an LBridge client.
 */
typedef struct lbridge_client* lbridge_client_t;

/**
 * @brief Creates a new LBridge client instance.
 *
 * @param context                The LBridge context to use for this client.
 * @param max_frame_payload_size Maximum payload size for a single frame (max 4095 bytes).
 * @param max_payload_size       Maximum total payload size for an RPC call (can span multiple frames).
 *
 * @return A new client handle, or NULL if creation failed.
 *
 * @note The client must be destroyed with lbridge_client_destroy() when no longer needed.
 */
lbridge_client_t LBRIDGE_API lbridge_client_create(lbridge_context_t context, uint16_t max_frame_payload_size, uint32_t max_payload_size);

/**
 * @brief Destroys an LBridge client and frees all associated resources.
 *
 * @param client The client to destroy.
 *
 * @note If the client is connected, the connection will be closed.
 */
void LBRIDGE_API lbridge_client_destroy(lbridge_client_t client);

/**
 * @brief Gets the transport type of a connected client.
 *
 * @param client The client to query.
 *
 * @return The transport type, or LBRIDGE_TYPE_UNKNOWN if not connected.
 */
enum lbridge_type LBRIDGE_API lbridge_client_get_type(const lbridge_client_t client);

/**
 * @brief Calls an RPC on the connected server.
 *
 * @param client       The LBridge client object.
 * @param rpc_id       The ID of the RPC to call.
 * @param inout_data   Pointer to the input data buffer. On return, it contains the response data.
 * @param inout_size   Pointer to the size of the input data buffer. On return, it contains the size of the response data.
 * @param max_out_size The maximum size of the output data buffer. If 0, the RPC call will NOT expect a response.
 *
 * @return true if the RPC call was successful, false otherwise.
 *
 * @note If max_out_size is 0, this performs a one-way RPC call (fire-and-forget).
 */
bool LBRIDGE_API lbridge_client_call_rpc(lbridge_client_t client, uint16_t rpc_id, uint8_t* inout_data, uint32_t* inout_size, uint32_t max_out_size);

/**
 * @brief Sends a ping to the server to refresh the inactivity timeout.
 *
 * This is a lightweight command that resets the server's inactivity timer
 * for this client without sending any RPC data.
 *
 * @param client The LBridge client object.
 *
 * @return true if the ping was sent successfully, false otherwise.
 *
 * @note This function is useful when the server has client timeout enabled
 *       and the client needs to stay connected without sending actual RPCs.
 */
bool LBRIDGE_API lbridge_client_ping(lbridge_client_t client);

#if defined(LBRIDGE_ENABLE_TCP_CLIENT)
/**
 * @brief Connects a client to a remote server via TCP.
 *
 * @param client The client to connect.
 * @param host   The hostname or IP address of the server.
 * @param port   The TCP port number of the server.
 *
 * @return true if the connection was established successfully, false otherwise.
 *
 * @note Use lbridge_get_last_error() to retrieve the error code on failure.
 */
bool LBRIDGE_API lbridge_client_connect_tcp(lbridge_client_t client, const char* host, uint16_t port);
#endif

#if defined(LBRIDGE_ENABLE_UNIX_CLIENT)
/**
 * @brief Connects a client to a server via Unix domain socket.
 *
 * @param client      The client to connect.
 * @param socket_path The path to the Unix domain socket file.
 *
 * @return true if the connection was established successfully, false otherwise.
 *
 * @note Use lbridge_get_last_error() to retrieve the error code on failure.
 * @note On Windows, Unix domain sockets are supported since Windows 10 version 1803.
 */
bool LBRIDGE_API lbridge_client_connect_unix(lbridge_client_t client, const char* socket_path);
#endif

#endif // LBRIDGE_ENABLE_CLIENT

#if defined(LBRIDGE_ENABLE_SERVER)

/**
 * @brief Opaque handle to an LBridge server.
 */
typedef struct lbridge_server* lbridge_server_t;

/**
 * @brief Creates a new LBridge server instance.
 *
 * @param context                The LBridge context to use for this server.
 * @param max_frame_payload_size Maximum payload size for a single frame (max 4095 bytes).
 * @param max_payload_size       Maximum total payload size for an RPC call (can span multiple frames).
 * @param on_rpc_call            Callback function invoked when an RPC call is received.
 *
 * @return A new server handle, or NULL if creation failed.
 *
 * @note The server must be destroyed with lbridge_server_destroy() when no longer needed.
 * @note Call a listen function (e.g., lbridge_server_listen_tcp()) to start accepting connections.
 */
lbridge_server_t LBRIDGE_API lbridge_server_create(lbridge_context_t context, uint16_t max_frame_payload_size, uint32_t max_payload_size, fp_rpc_call on_rpc_call);

/**
 * @brief Destroys an LBridge server and frees all associated resources.
 *
 * @param server The server to destroy.
 *
 * @note All active client connections will be closed.
 */
void LBRIDGE_API lbridge_server_destroy(lbridge_server_t server);

/**
 * @brief Processes pending events on the server.
 *
 * This function must be called regularly to accept new connections,
 * receive incoming RPC calls, and process client disconnections.
 *
 * @param server The server to update.
 *
 * @return true if the update was successful, false if an error occurred.
 *
 * @note This function is non-blocking and should be called in a loop.
 */
bool LBRIDGE_API lbridge_server_update(lbridge_server_t server);

/**
 * @brief Sets the client inactivity timeout for the server.
 *
 * When a client has not sent any data for the specified duration,
 * it will be automatically disconnected.
 *
 * @param server     The server to configure.
 * @param timeout_ms Timeout in milliseconds. Use 0 to disable timeout (default).
 *
 * @note This feature requires fp_get_time_ms to be set in the context params.
 *       If fp_get_time_ms is NULL, this function has no effect.
 */
void LBRIDGE_API lbridge_server_set_client_timeout(lbridge_server_t server, uint32_t timeout_ms);

#if defined(LBRIDGE_ENABLE_TCP_SERVER)
/**
 * @brief Starts the server listening for TCP connections.
 *
 * @param server         The server to start.
 * @param address        The IP address to bind to (e.g., "0.0.0.0" for all interfaces, "127.0.0.1" for localhost only).
 * @param port           The TCP port number to listen on.
 * @param max_nb_clients Maximum number of simultaneous client connections.
 *
 * @return true if the server started successfully, false otherwise.
 *
 * @note Use lbridge_get_last_error() to retrieve the error code on failure.
 */
bool LBRIDGE_API lbridge_server_listen_tcp(lbridge_server_t server, const char* address, uint16_t port, uint32_t max_nb_clients);
#endif // LBRIDGE_ENABLE_TCP_SERVER

#if defined(LBRIDGE_ENABLE_UNIX_SERVER)
/**
 * @brief Starts the server listening for Unix domain socket connections.
 *
 * @param server         The server to start.
 * @param socket_path    The path to the Unix domain socket file to create.
 * @param max_nb_clients Maximum number of simultaneous client connections.
 *
 * @return true if the server started successfully, false otherwise.
 *
 * @note Use lbridge_get_last_error() to retrieve the error code on failure.
 * @note The socket file will be created at the specified path. If a file already exists, it will be removed.
 * @note On Windows, Unix domain sockets are supported since Windows 10 version 1803.
 */
bool LBRIDGE_API lbridge_server_listen_unix(lbridge_server_t server, const char* socket_path, uint32_t max_nb_clients);
#endif // LBRIDGE_ENABLE_UNIX_SERVER

#endif // LBRIDGE_ENABLE_SERVER

#ifdef __cplusplus
}
#endif

#endif // LBRIDGE_H
