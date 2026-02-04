#ifndef LBRIDGE_CUSTOM_BACKEND_H
#define LBRIDGE_CUSTOM_BACKEND_H

/**
 * @file lbridge_custom_backend.h
 * @brief Custom backend interface for LBridge.
 *
 * This header provides the types and structures needed to implement
 * custom transport backends (e.g., SPI, UART, I2C) for LBridge.
 *
 * Custom backends receive operation callbacks and decide how to handle
 * each operation based on their specific transport requirements.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

// Forward declaration (actual definition is internal)
struct lbridge_connection;

// =============================================================================
// Backend Operations
// =============================================================================

/**
 * @brief Backend operation codes.
 *
 * These operations are sent to backend implementations (both internal and custom)
 * to perform transport-specific actions.
 */
enum lbridge_backend_operation
{
	LBRIDGE_OP_NONE = 0,         /**< No operation (placeholder). */
	LBRIDGE_OP_CLIENT_CONNECT,   /**< Client: establish connection. arg = user-provided connect arg. */
	LBRIDGE_OP_CLIENT_CLEANUP,   /**< Client: cleanup resources. arg = NULL. */
	LBRIDGE_OP_SERVER_OPEN,      /**< Server: start listening. arg = user-provided listen arg. */
	LBRIDGE_OP_SERVER_CLEANUP,   /**< Server: cleanup resources. arg = NULL. */
	LBRIDGE_OP_SERVER_ACCEPT,    /**< Server: accept new client. arg = struct lbridge_backend_accept_data*. */
	LBRIDGE_OP_SEND_DATA,        /**< Send data. arg = struct lbridge_backend_send_data*. */
	LBRIDGE_OP_RECEIVE_DATA,     /**< Receive data. arg = struct lbridge_backend_receive_data*. */
	LBRIDGE_OP_CONNECTION_CLOSE, /**< Close a connection. arg = struct lbridge_connection*. */
};

// =============================================================================
// Backend Data Structures
// =============================================================================

/**
 * @brief Flags for receive operations.
 */
enum lbridge_receive_flag
{
	LBRIDGE_RECEIVE_BLOCKING = 0x01, /**< Block until data is available. */
};

/**
 * @brief Data structure for LBRIDGE_OP_SEND_DATA operation.
 */
struct lbridge_backend_send_data
{
	struct lbridge_connection*	connection; /**< Connection to send data on. */
	const uint8_t*				data;       /**< Pointer to data to send. */
	uint32_t					size;       /**< Size of data to send in bytes. */
};

/**
 * @brief Data structure for LBRIDGE_OP_RECEIVE_DATA operation.
 */
struct lbridge_backend_receive_data
{
	struct lbridge_connection*	connection;      /**< Connection to receive data from. */
	uint8_t*					data;            /**< Buffer to store received data. */
	uint32_t					requested_size;  /**< Number of bytes to receive. */
	uint32_t					received_size;   /**< Output: actual bytes received. */
	enum lbridge_receive_flag	flags;           /**< Receive flags (blocking, etc.). */
};

/**
 * @brief Data structure for LBRIDGE_OP_SERVER_ACCEPT operation.
 */
struct lbridge_backend_accept_data
{
	struct lbridge_connection*	new_connection;      /**< Output: connection for the new client. */
	bool						new_client_accepted; /**< Output: true if a client was accepted. */
};

// =============================================================================
// Connection Handle Accessors
// =============================================================================

/**
 * @brief Gets the user handle stored in a connection.
 *
 * Custom backends use this to retrieve their transport-specific handle
 * (e.g., file descriptor, SPI device pointer) from a connection.
 *
 * @param connection The connection to query.
 * @return The user handle, or NULL if not set.
 */
void* lbridge_connection_get_handle(struct lbridge_connection* connection);

/**
 * @brief Sets the user handle in a connection.
 *
 * Custom backends use this to store their transport-specific handle
 * (e.g., file descriptor, SPI device pointer) in a connection.
 *
 * @param connection The connection to modify.
 * @param handle     The user handle to store.
 */
void lbridge_connection_set_handle(struct lbridge_connection* connection, void* handle);

// Note: lbridge_get_backend_data() and lbridge_set_backend_data() are declared
// in lbridge.h (after lbridge_object_t is defined).

// =============================================================================
// Custom Backend Callback
// =============================================================================

/**
 * @brief Backend callback function type.
 *
 * This callback is invoked for each transport operation. The implementation
 * should handle the operation based on the specific transport requirements.
 *
 * For operations that don't apply to your transport (e.g., ACCEPT for SPI),
 * simply return true without doing anything.
 *
 * @param op        The operation to perform.
 * @param object    The LBridge object (client or server).
 * @param arg       Operation-specific argument (see enum lbridge_backend_operation).
 *
 * @return true on success, false on failure.
 *
 * @note For LBRIDGE_OP_RECEIVE_DATA, returning true with received_size=0 means
 *       "no data available yet" (non-blocking behavior).
 *
 * Example implementation for SPI:
 * @code
 * bool my_spi_backend(enum lbridge_backend_operation op, void* object, void* arg)
 * {
 *     switch (op)
 *     {
 *     case LBRIDGE_OP_CLIENT_CONNECT:
 *         // SPI has no connection concept, just initialize if needed
 *         return true;
 *
 *     case LBRIDGE_OP_SEND_DATA: {
 *         struct lbridge_backend_send_data* d = arg;
 *         spi_write(d->data, d->size);
 *         return true;
 *     }
 *
 *     case LBRIDGE_OP_RECEIVE_DATA: {
 *         struct lbridge_backend_receive_data* d = arg;
 *         d->received_size = spi_read(d->data, d->requested_size);
 *         return true;
 *     }
 *
 *     default:
 *         return true; // Unhandled operations = success
 *     }
 * }
 * @endcode
 */
typedef bool (*lbridge_backend_fn)(
	enum lbridge_backend_operation op,
	void* object,
	void* arg
);

// Alias for custom backends (same signature)
typedef lbridge_backend_fn lbridge_custom_backend_fn;

#ifdef __cplusplus
}
#endif

#endif // LBRIDGE_CUSTOM_BACKEND_H
