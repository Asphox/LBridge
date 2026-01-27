#ifndef LBRIDGE_INTERNAL_H
#define	LBRIDGE_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "../lbridge.h"
#if defined(LBRIDGE_ENABLE_SECURE)
#include "../mbedtls-chachapoly/mbedtls/chachapoly.h"
#endif // LBRIDGE_ENABLE_SECURE

#define LBRIDGE_WRITE_BIT_U32(var, bit, state) \
    ((var) = ((var) & ~(1U << (bit))) | ((uint32_t)(state) << (bit)))

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

enum lbridge_backend_operation
{
	LBRIDGE_OP_NONE = 0,
	LBRIDGE_OP_CLIENT_CONNECT,
	LBRIDGE_OP_CLIENT_CLEANUP,
	LBRIDGE_OP_CLIENT_CLOSE,
	LBRIDGE_OP_SERVER_OPEN,
	LBRIDGE_OP_SERVER_CLEANUP,
	LBRIDGE_OP_SERVER_CLOSE,
	LBRIDGE_OP_SERVER_ACCEPT,
	LBRIDGE_OP_SEND_DATA,
	LBRIDGE_OP_RECEIVE_DATA,
};

enum lbridge_receive_flag
{
	LBRIDGE_RECEIVE_BLOCKING = 0x01,
};

struct lbridge_object_send_data
{
	struct lbridge_connection*		connection;
	const uint8_t*					data;
	uint32_t						size;
};

struct lbridge_object_receive_data
{
	struct lbridge_connection*	connection;
	uint8_t*					data;
	uint32_t					requested_size;
	uint32_t					received_size;
	enum lbridge_receive_flag 	flags;
};

struct lbridge_server_accept_data
{
	struct lbridge_connection* new_connection;
	bool new_client_accepted;
};

typedef uint32_t lbridge_frame_header_t;

// connection structure
// represents a connection to a client (server side) or to a server (client side)
// this structure does NOT manage a receive buffer for asynchronous operations ! see lbridge_connection_async for that
// this structure is mainly used by clients (blocking operations)
struct lbridge_connection
{
	// backend specific connection data
	union
	{
		void*		as_ptr;
		uintptr_t	as_int;
		uint8_t		as_bytes[sizeof(void*)];
	};
#if defined(LBRIDGE_ENABLE_SECURE)
	// encryption counters (nonces)
	struct
	{
		union
		{
			uint8_t full_nonce[12];
			struct
			{
				uint64_t value;
				uint32_t reserved_lsb_bytes;
			};
		}send;
		union
		{
			uint8_t full_nonce[12];
			struct
			{
				uint64_t value;
				uint32_t reserved_lsb_bytes;
			};
		}receive;
	}counters;
#endif // LBRIDGE_ENABLE_SECURE
	uint8_t connected : 1;
	uint8_t waiting_handshake : 1;
	uint8_t reserved : 6;
};

// asynchronous connection structure
// this structure manages a receive buffer for asynchronous operations
// used mainly by servers to manage multiple client connections
struct lbridge_connection_async
{
	struct lbridge_connection			base;
	uint8_t*							receive_buffer;
	uint32_t							receive_buffer_used_size;
	lbridge_frame_header_t				current_frame_header;
	uint64_t							last_activity_ms; // timestamp of last activity (for timeout)
#if defined(LBRIDGE_ENABLE_SECURE)
	mbedtls_chachapoly_context			chachapoly_ctx;
#endif // LBRIDGE_ENABLE_SECURE
};

struct lbridge_connection_async_vector
{
	struct lbridge_connection_async*	array;
	uint32_t							size;
	uint32_t							capacity;
};

enum lbridge_object_type
{
	LBRIDGE_CLIENT = 0,
	LBRIDGE_SERVER = 1,
};

typedef bool(*fp_backend)(enum lbridge_backend_operation op, lbridge_object_t p_object, void* arg);

struct lbridge_context
{
	struct lbridge_context_params params;
};

struct lbridge_object
{
	struct lbridge_context*		context;
	fp_backend					backend;
#if defined(LBRIDGE_ENABLE_SECURE)
	const uint8_t*				encryption_key_256bits;
#endif // LBRIDGE_ENABLE_SECURE
	enum lbridge_error_code		last_error;
	enum lbridge_type			type;
	int32_t 					timeout_ms;
	uint32_t					max_payload_size;	
	uint16_t					max_frame_payload_size;
	uint8_t						sequence_max_nb_frames; // max number of frames in a sequence (for fragmentation)
	uint8_t 					object_type;
};

struct lbridge_client
{
	struct lbridge_object		base;
	struct lbridge_connection	connection;
};

struct lbridge_server
{
	struct lbridge_object					base;
	struct lbridge_connection_async_vector	connections;
	void*									backend_data;
	fp_rpc_call								rpc_call;
	uint32_t								client_timeout_ms; // client inactivity timeout (0 = disabled)
};

#define LBRIDGE_OBJECT(obj_ptr) ((struct lbridge_object*)(obj_ptr))

struct lbridge_rpc_context
{
	lbridge_object_t			object;
	struct lbridge_connection*	connection;
	uint16_t					rpc_id;
};

typedef uint16_t lbridge_frame_header_cmd_data_t;
struct lbridge_frame
{
	lbridge_frame_header_t	header;
	uint8_t					data[];
};

#define LBRIDGE_FRAME_HEADER_START_OFFSET	0
#define LBRIDGE_FRAME_HEADER_START_MASK		(1U << LBRIDGE_FRAME_HEADER_START_OFFSET)
#define LBRIDGE_FRAME_HEADER_END_OFFSET		1
#define LBRIDGE_FRAME_HEADER_END_MASK		(1U << LBRIDGE_FRAME_HEADER_END_OFFSET)
#define LBRIDGE_FRAME_HEADER_RPC_NO_RESPONSE_OFFSET		2
#define LBRIDGE_FRAME_HEADER_RPC_NO_RESPONSE_MASK		(1U << LBRIDGE_FRAME_HEADER_RPC_NO_RESPONSE_OFFSET)
#define LBRIDGE_FRAME_HEADER_CMD_OFFSET		3
#define LBRIDGE_FRAME_HEADER_CMD_MASK		(1U << LBRIDGE_FRAME_HEADER_CMD_OFFSET)
#define LBRIDGE_FRAME_HEADER_RPC_ID_OFFSET	4
#define LBRIDGE_FRAME_HEADER_RPC_ID_MASK	(0xFFFF << LBRIDGE_FRAME_HEADER_RPC_ID_OFFSET)
#define LBRIDGE_FRAME_HEADER_CMD_DATA_MASK	LBRIDGE_FRAME_HEADER_RPC_ID_MASK // same as RPC_ID for command frames
#define LBRIDGE_FRAME_HEADER_PLEN_OFFSET	20
#define LBRIDGE_FRAME_HEADER_PLEN_MASK		(0xFFF << LBRIDGE_FRAME_HEADER_PLEN_OFFSET)

#define LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET 0
#define LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_MASK (0xF << LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET)
// handshake command
// opcode (4 bits): 0x0
// encryption (1 bit) : 0 = no encryption, 1 = encrypted
// reserved (11 bits)
#define LBRIDGE_FRAME_HEADER_CMD_HELLO_OPCODE 0x0
#define LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_HELLO_ENCRYPTION_FLAG_OFFSET 4
#define LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_HELLO_ENCRYPTION_FLAG_MASK (1U << LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_HELLO_ENCRYPTION_FLAG_OFFSET)

// close connection command
// opcode (4 bits): 0x1
// reserved (4 bits)
// lbridge_protocol_error (8 bits)
#define LBRIDGE_FRAME_HEADER_CMD_CLOSE_OPCODE 0x1

// ping command (keep-alive / refresh timeout)
// opcode (4 bits): 0x2
// no payload, no response
#define LBRIDGE_FRAME_HEADER_CMD_PING_OPCODE 0x2

inline void __lbridge_frame_set_start(struct lbridge_frame* frame, bool v)
{
	LBRIDGE_WRITE_BIT_U32(frame->header, LBRIDGE_FRAME_HEADER_START_OFFSET, v);
}

inline bool __lbridge_frame_is_start(const struct lbridge_frame* frame)
{
	return (frame->header & LBRIDGE_FRAME_HEADER_START_MASK) != 0;
}

inline void __lbridge_frame_set_end(struct lbridge_frame* frame, bool v)
{
	LBRIDGE_WRITE_BIT_U32(frame->header, LBRIDGE_FRAME_HEADER_END_OFFSET, v);
}

inline bool __lbridge_frame_is_end(const struct lbridge_frame* frame)
{
	return (frame->header & LBRIDGE_FRAME_HEADER_END_MASK) != 0;
}

inline void __lbridge_frame_set_cmd(struct lbridge_frame* frame, bool v)
{
	LBRIDGE_WRITE_BIT_U32(frame->header, LBRIDGE_FRAME_HEADER_CMD_OFFSET, v);
}

inline bool __lbridge_frame_is_cmd(const struct lbridge_frame* frame)
{
	return (frame->header & LBRIDGE_FRAME_HEADER_CMD_MASK) != 0;
}

inline bool __lbridge_frame_is_rpc_no_response(const struct lbridge_frame* frame)
{
	return (frame->header & LBRIDGE_FRAME_HEADER_RPC_NO_RESPONSE_MASK) != 0 && !__lbridge_frame_is_cmd(frame);
}

inline void __lbridge_frame_set_rpc_no_response(struct lbridge_frame* frame, bool v)
{
	LBRIDGE_WRITE_BIT_U32(frame->header, LBRIDGE_FRAME_HEADER_RPC_NO_RESPONSE_OFFSET, v);
}

inline uint16_t __lbridge_frame_get_rpc_id(const struct lbridge_frame* frame)
{
	return (uint16_t)((frame->header & LBRIDGE_FRAME_HEADER_RPC_ID_MASK) >> LBRIDGE_FRAME_HEADER_RPC_ID_OFFSET);
}

inline void __lbridge_frame_set_rpc_id(struct lbridge_frame* frame, uint16_t rpc_id)
{
	frame->header = (frame->header & ~LBRIDGE_FRAME_HEADER_RPC_ID_MASK) | ((uint32_t)(rpc_id) << LBRIDGE_FRAME_HEADER_RPC_ID_OFFSET);
}

inline uint16_t __lbridge_frame_get_cmd_data(const struct lbridge_frame* frame)
{
	return __lbridge_frame_get_rpc_id(frame);
}

inline void __lbridge_frame_set_cmd_data(struct lbridge_frame* frame, uint16_t cmd_data)
{
	__lbridge_frame_set_rpc_id(frame, cmd_data);
}

inline void __lbridge_frame_set_cmd_opcode(struct lbridge_frame* frame, uint8_t opcode)
{
	frame->header = (frame->header & ~LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_MASK) | ((uint32_t)(opcode) << LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET);
}

inline uint16_t __lbridge_frame_get_payload_length(const struct lbridge_frame* frame)
{
	return (uint16_t)((frame->header & LBRIDGE_FRAME_HEADER_PLEN_MASK) >> LBRIDGE_FRAME_HEADER_PLEN_OFFSET);
}

inline void __lbridge_frame_set_payload_length(struct lbridge_frame* frame, uint16_t payload_length)
{
	frame->header = (frame->header & ~LBRIDGE_FRAME_HEADER_PLEN_MASK) | ((uint32_t)(payload_length) << LBRIDGE_FRAME_HEADER_PLEN_OFFSET);
}

inline void __lbridge_object_set_error(lbridge_object_t obj, enum lbridge_error_code error_code)
{
	((struct lbridge_object*)obj)->last_error = error_code;
}

inline enum lbridge_error_code __lbridge_object_get_error(const lbridge_object_t obj)
{
	return ((struct lbridge_object*)obj)->last_error;
}

inline enum lbridge_type __lbridge_object_get_type(const lbridge_object_t obj)
{
	return ((struct lbridge_object*)obj)->type;
}

inline uint16_t __lbridge_object_get_max_frame_payload_size(const lbridge_object_t obj)
{
	return ((struct lbridge_object*)obj)->max_frame_payload_size;
}

inline uint32_t __lbridge_object_get_max_payload_size(const lbridge_object_t obj)
{
	return ((struct lbridge_object*)obj)->max_payload_size;
}

#if defined(LBRIDGE_ENABLE_SECURE)
inline bool __lbridge_connection_need_encryption(const struct lbridge_connection* connection)
{
	// if we have a nonce, we have encryption
	return (connection->counters.receive.value != 0 || connection->counters.send.value != 0 || connection->counters.receive.reserved_lsb_bytes != 0 || connection->counters.send.reserved_lsb_bytes != 0);
}
inline uint8_t* __lbridge_get_encryption_key(const lbridge_object_t obj)
{
	return (uint8_t*)((struct lbridge_object*)obj)->encryption_key_256bits;
}
#endif // LBRIDGE_ENABLE_SECURE

inline struct lbridge_context*  __lbridge_object_get_context(const lbridge_object_t obj)
{
	return ((struct lbridge_object*)obj)->context;
}


#include "lbridge_socket.h"

#ifdef __cplusplus
}
#endif

#endif // LBRIDGE_INTERNAL_H
