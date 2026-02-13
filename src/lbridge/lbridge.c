#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <memory.h>

#include "internals/lbridge_internal.h"

#ifdef __LBRIDGE_LOG_ANY_ENABLED
#include <stdio.h>
void lbridge_log_default(lbridge_context_t context, enum lbridge_log_level level, const char* message)
{
	(void)context;
	static const char* level_names[] = { "ERROR", "INFO", "TRACE" };
	const char* level_name = (level <= LBRIDGE_LOG_LEVEL_TRACE) ? level_names[level] : "?";
	if (level == LBRIDGE_LOG_LEVEL_ERROR)
		fprintf(stderr, "[LBridge/%s] %s\n", level_name, message);
	else
		printf("[LBridge/%s] %s\n", level_name, message);
}
#endif

bool __lbridge_send_data(lbridge_object_t p_object, const uint8_t* data, uint32_t size, struct lbridge_connection* p_connection)
{
	if (p_object == NULL)
	{
		return false;
	}
	if (data == NULL || size == 0 || p_connection == NULL)
	{
		__lbridge_object_set_error(p_object, LBRIDGE_ERROR_BAD_ARGUMENT);
		return false;
	}
	struct lbridge_object* obj = p_object;
	__lbridge_object_set_error(obj, LBRIDGE_ERROR_NONE);
	struct lbridge_object_send_data send_data;
	send_data.connection = p_connection;
	send_data.data = data;
	send_data.size = size;
	return obj->backend(LBRIDGE_OP_SEND_DATA, obj, &send_data);
}

bool __lbridge_receive_data(lbridge_object_t p_object, uint8_t* data, uint32_t requested_size, uint32_t* received_size, struct lbridge_connection* p_connection, enum lbridge_receive_flag flags)
{
	if (p_object == NULL)
	{
		return false;
	}
	if (data == NULL || requested_size == 0 || p_connection == NULL)
	{
		__lbridge_object_set_error(p_object, LBRIDGE_ERROR_BAD_ARGUMENT);
		return false;
	}

	__lbridge_object_set_error(p_object, LBRIDGE_ERROR_NONE);
	struct lbridge_object* obj = p_object;
	struct lbridge_object_receive_data receive_data;
	receive_data.connection = p_connection;
	receive_data.data = data;
	receive_data.requested_size = requested_size;
	receive_data.received_size = 0;
	receive_data.flags = flags;
	const bool result = obj->backend(LBRIDGE_OP_RECEIVE_DATA, obj, &receive_data);
	if (received_size != NULL)
	{
		*received_size = receive_data.received_size;
	}
	return result;
}

bool __lbridge_send_data_sequence_rpc(lbridge_object_t p_object, uint16_t rpc_id, const uint8_t* data, const uint32_t size, struct lbridge_connection* p_connection)
{
	bool result = false;
	enum lbridge_error_code last_error = LBRIDGE_ERROR_NONE;
	if (p_object == NULL)
	{
		return false;
	}
	const bool are_arguments_invalid = (data == NULL || p_connection == NULL);
	if (are_arguments_invalid)
	{
		__lbridge_object_set_error(p_object, LBRIDGE_ERROR_BAD_ARGUMENT);
		return false;
	}
	if(size > (UINT32_MAX - 8))
	{
		__lbridge_object_set_error(p_object, LBRIDGE_ERROR_TOO_MUCH_DATA);
		return false;
	}
	struct lbridge_object* obj = p_object;
	__lbridge_object_set_error(obj, LBRIDGE_ERROR_NONE);

	const uint32_t max_payload_size = __lbridge_object_get_max_payload_size(obj);
	const uint16_t object_max_frame_payload_size = __lbridge_object_get_max_frame_payload_size(obj);
	
#if defined(LBRIDGE_ENABLE_SECURE)
	const uint8_t* encryption_key = __lbridge_get_encryption_key(obj);
	const bool encryption_needed = (encryption_key != NULL);
	uint8_t* encrypted_data = NULL;
	mbedtls_chachapoly_context chachapoly_ctx;
	uint8_t 	tag[16];
	const uint32_t size_with_encryption_tag = size + (encryption_needed ? 8 : 0);
	if (size_with_encryption_tag > max_payload_size)
	{
		last_error = LBRIDGE_ERROR_TOO_MUCH_DATA;
		goto lbl_return;
	}
	if (encryption_needed)
	{
		struct lbridge_context* context = __lbridge_object_get_context(p_object);
		encrypted_data = context->params.fp_malloc(size_with_encryption_tag);
		if (encrypted_data == NULL)
		{
			last_error = LBRIDGE_ERROR_BAD_ALLOC;
			goto lbl_return;
		}
		mbedtls_chachapoly_init(&chachapoly_ctx);
		mbedtls_chachapoly_setkey(&chachapoly_ctx, encryption_key);
		mbedtls_chachapoly_starts(&chachapoly_ctx, p_connection->counters.send.full_nonce, MBEDTLS_CHACHAPOLY_ENCRYPT);
	}
#else
	const bool encryption_needed = false;
	const uint32_t size_with_encryption_tag = size;
	if (size_with_encryption_tag > max_payload_size)
	{
		last_error = LBRIDGE_ERROR_BAD_ALLOC;
		goto lbl_return;
	}
#endif // LBRIDGE_ENABLE_SECURE

	const bool is_single_frame = size_with_encryption_tag <= object_max_frame_payload_size;

	// Calculate end frame payload and number of continue frames
	// Handle the case where size is exactly divisible by frame size
	uint16_t end_frame_payload = (uint16_t)(size_with_encryption_tag % object_max_frame_payload_size);
	uint32_t nb_continue_frames = 0;
	if (!is_single_frame)
	{
		if (end_frame_payload == 0)
		{
			// Size is exactly divisible - end frame gets a full payload
			end_frame_payload = object_max_frame_payload_size;
			nb_continue_frames = ((size_with_encryption_tag - object_max_frame_payload_size) / object_max_frame_payload_size) - 1;
		}
		else
		{
			nb_continue_frames = (size_with_encryption_tag - object_max_frame_payload_size) / object_max_frame_payload_size;
		}
	}

	// We build all headers first because we may need them for AAD if encryption is enabled
	struct lbridge_frame start_frame_header;
	__lbridge_frame_set_start(&start_frame_header, true);
	__lbridge_frame_set_end(&start_frame_header, is_single_frame);
	__lbridge_frame_set_cmd(&start_frame_header, false);
	__lbridge_frame_set_rpc_id(&start_frame_header, rpc_id);
	__lbridge_frame_set_payload_length(&start_frame_header, (uint16_t)(is_single_frame ? size_with_encryption_tag : object_max_frame_payload_size));
	struct lbridge_frame continue_frame_header;
	continue_frame_header.header = start_frame_header.header;
	__lbridge_frame_set_start(&continue_frame_header, false);
	__lbridge_frame_set_end(&continue_frame_header, false);
	// a continue frame will ALWAYS have max payload size
	__lbridge_frame_set_payload_length(&continue_frame_header, object_max_frame_payload_size);
	struct lbridge_frame end_frame_header;
	end_frame_header.header = start_frame_header.header;
	__lbridge_frame_set_start(&end_frame_header, false);
	__lbridge_frame_set_end(&end_frame_header, true);
	__lbridge_frame_set_payload_length(&end_frame_header, end_frame_payload);

#if defined(LBRIDGE_ENABLE_SECURE)
	// we must add all headers to the AAD prior to encrypting data
	if (encryption_needed)
	{
		mbedtls_chachapoly_update_aad(&chachapoly_ctx, (const uint8_t*)&start_frame_header, sizeof(struct lbridge_frame));
		if (!is_single_frame)
		{
			for (uint32_t i = 0; i < nb_continue_frames; i++)
			{
				mbedtls_chachapoly_update_aad(&chachapoly_ctx, (const uint8_t*)&continue_frame_header, sizeof(struct lbridge_frame));
			}
			mbedtls_chachapoly_update_aad(&chachapoly_ctx, (const uint8_t*)&end_frame_header, sizeof(struct lbridge_frame));
		}
		// encrypt data
		mbedtls_chachapoly_update(&chachapoly_ctx, size, data, encrypted_data);
		mbedtls_chachapoly_finish(&chachapoly_ctx, tag);
		// add the 8 first bytes of the tag to the encrypted data
		memcpy(encrypted_data + size, tag, 8);
		data = encrypted_data;
	}
#endif // LBRIDGE_ENABLE_SECURE

	// Send start frame header (always, even for zero-size payload)
	if (!__lbridge_send_data(p_object, (const uint8_t*)&start_frame_header, sizeof(struct lbridge_frame), p_connection))
	{
		goto lbl_return;
	}

	uint32_t payload_bytes_remaining = size_with_encryption_tag;
	uint32_t offset = 0;
	while (payload_bytes_remaining > 0)
	{
		const uint16_t frame_payload_size = (uint16_t)min(payload_bytes_remaining, object_max_frame_payload_size);
		if (!__lbridge_send_data(p_object, data + offset, frame_payload_size, p_connection))
		{
			goto lbl_return;
		}
		payload_bytes_remaining -= frame_payload_size;
		offset += frame_payload_size;

		if (payload_bytes_remaining > 0)
		{
			if (payload_bytes_remaining <= object_max_frame_payload_size)
			{
				// end frame
				if (!__lbridge_send_data(p_object, (const uint8_t*)&end_frame_header, sizeof(struct lbridge_frame), p_connection))
				{
					goto lbl_return;
				}
			}
			else
			{
				// continue frame
				if (!__lbridge_send_data(p_object, (const uint8_t*)&continue_frame_header, sizeof(struct lbridge_frame), p_connection))
				{
					goto lbl_return;
				}
			}
		}
	}

	result = true;

lbl_return:
#if defined(LBRIDGE_ENABLE_SECURE)
	if (encryption_needed)
	{
		mbedtls_chachapoly_free(&chachapoly_ctx);
		struct lbridge_context* context = __lbridge_object_get_context(p_object);
		context->params.fp_free(encrypted_data);
		if (result)
		{
			p_connection->counters.send.value++;
		}
	}
#endif // LBRIDGE_ENABLE_SECURE
	__lbridge_object_set_error(p_object, last_error);
	return result;
}

bool __lbridge_receive_data_sequence_rpc(lbridge_object_t p_object, uint8_t* out_data, uint32_t max_out_size, uint32_t* total_received_size, struct lbridge_connection* p_connection)
{
	bool result = false;
	enum lbridge_error_code last_error = LBRIDGE_ERROR_NONE;

	if (p_object == NULL || out_data == NULL || p_connection == NULL) {
		__lbridge_object_set_error(p_object, LBRIDGE_ERROR_BAD_ARGUMENT);
		return false;
	}

#if defined(LBRIDGE_ENABLE_SECURE)
	mbedtls_chachapoly_context ctx;
	const uint8_t* encryption_key = __lbridge_get_encryption_key(p_object);
	const bool encryption_needed = (encryption_key != NULL);
	if (encryption_needed)
	{
		mbedtls_chachapoly_init(&ctx);
		mbedtls_chachapoly_setkey(&ctx, encryption_key);
		mbedtls_chachapoly_starts(&ctx, p_connection->counters.receive.full_nonce, MBEDTLS_CHACHAPOLY_DECRYPT);
	}
#endif

	bool is_end_frame = false;
	uint32_t current_offset = 0;

	while (!is_end_frame) 
	{
		struct lbridge_frame header;
		uint32_t header_recv = 0;

		// reads the frame header
		const bool header_read_success = __lbridge_receive_data(p_object, (uint8_t*)&header, sizeof(struct lbridge_frame), &header_recv, p_connection, LBRIDGE_RECEIVE_BLOCKING);
		if (!header_read_success || header_recv != sizeof(struct lbridge_frame)) 
		{
			goto lbl_return;
		}

		// if frame is an error/close frame, abort and set error
		if (__lbridge_frame_is_cmd(&header))
		{
			const uint16_t cmd_data = __lbridge_frame_get_cmd_data(&header);
			const uint8_t opcode = (uint8_t)((cmd_data & LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_MASK) >> LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET);
			if (opcode == LBRIDGE_FRAME_HEADER_CMD_CLOSE_OPCODE)
			{
				const uint8_t protocol_error_code = (uint8_t)(cmd_data >> 8);
				switch (protocol_error_code)
				{
					case LBRIDGE_PROTOCOL_ERROR_NONE:
						last_error = LBRIDGE_ERROR_NONE;
						break;
					case LBRIDGE_PROTOCOL_ERROR_INVALID_RPC_ID:
						last_error = LBRIDGE_ERROR_INVALID_RPC_ID;
						break;
					default:
						last_error = LRBDIGE_ERROR_PROTOCOL_VIOLATION;
						break;
				}
				goto lbl_return;
			}
			else
			{
				// unexpected command frame
				last_error = LRBDIGE_ERROR_PROTOCOL_VIOLATION;
				goto lbl_return;
			}
		}

		const uint16_t frame_payload_len = __lbridge_frame_get_payload_length(&header);
		is_end_frame = __lbridge_frame_is_end(&header);

		if (current_offset + frame_payload_len > max_out_size) 
		{
			last_error = LBRIDGE_ERROR_TOO_MUCH_DATA;
			goto lbl_return;
		}

		// Update AAD with the header for decryption if needed 
#if defined(LBRIDGE_ENABLE_SECURE)
		if (encryption_needed)
		{
			mbedtls_chachapoly_update_aad(&ctx, (const uint8_t*)&header, sizeof(struct lbridge_frame));
		}
#endif

		// copy payload to output buffer
		if (frame_payload_len > 0)
		{
			uint32_t payload_recv = 0;
			const bool payload_read_success = __lbridge_receive_data(p_object, out_data + current_offset, frame_payload_len, &payload_recv, p_connection, LBRIDGE_RECEIVE_BLOCKING);
			if( !payload_read_success || payload_recv != frame_payload_len)
			{
				goto lbl_return;
			}
			current_offset += frame_payload_len;
		}
	}

	// Currently, out_data contains the full received data (+ 8 bytes tag if encrypted)
#if defined(LBRIDGE_ENABLE_SECURE)
	if (encryption_needed) 
	{
		if (current_offset < 8) 
		{
			goto lbl_return;
		}

		uint32_t pure_data_size = current_offset - 8;
		uint8_t generated_tag[16];

		// Decode data and process the tag
		mbedtls_chachapoly_update(&ctx, pure_data_size, out_data, out_data);
		mbedtls_chachapoly_finish(&ctx, generated_tag);

		// Compare the first 8 bytes of the generated tag with the received tag
		if (memcmp(out_data + pure_data_size, generated_tag, 8) != 0) 
		{
			last_error = LBRIDGE_ERROR_AUTHENTICATION_FAILED;
			goto lbl_return;
		}

		*total_received_size = pure_data_size;
	}
	else 
	{
		*total_received_size = current_offset;
	}
#else
	*total_received_size = current_offset;
#endif

	result = true;

lbl_return:
#if defined(LBRIDGE_ENABLE_SECURE)
	if (encryption_needed)
	{
		mbedtls_chachapoly_free(&ctx);
		if (result)
		{
			p_connection->counters.receive.value++;
		}
	}
#endif
	// In case of failure, clear output buffer
	if (!result)
	{
		memset(out_data, 0, max_out_size);
	}
	// If received size is less than max_out_size, zero the remaining buffer (for security)
	else
	{
		memset(out_data + *total_received_size, 0, max_out_size - *total_received_size);
	}
	if(__lbridge_object_get_error(p_object) == LBRIDGE_ERROR_NONE && last_error != LBRIDGE_ERROR_NONE)
	{
		__lbridge_object_set_error(p_object, last_error);
	}
	return result;
}

bool __lbridge_close_connection(lbridge_object_t p_object, struct lbridge_connection* p_connection, enum lbridge_protocol_error error)
{
	if (p_object == NULL || p_connection == NULL)
	{
		return false;
	}

	struct lbridge_object* obj = p_object;
	bool close_sent = false;

	// Only send close frame if connection was established (not during failed handshake)
	if (p_connection->connected)
	{
		uint8_t raw_data[sizeof(struct lbridge_frame)] = { 0 };
		struct lbridge_frame* close_frame = (struct lbridge_frame*)raw_data;

		__lbridge_frame_set_start(close_frame, true);
		__lbridge_frame_set_end(close_frame, true);
		__lbridge_frame_set_cmd(close_frame, true);

		uint16_t cmd_data = 0;
		cmd_data |= ((uint16_t)LBRIDGE_FRAME_HEADER_CMD_CLOSE_OPCODE << LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET);
		cmd_data |= ((uint16_t)error << 8);  // error code in bits 8-15
		__lbridge_frame_set_cmd_data(close_frame, cmd_data);
		__lbridge_frame_set_payload_length(close_frame, 0);

		close_sent = __lbridge_send_data(p_object, raw_data, sizeof(struct lbridge_frame), p_connection);
	}

	const bool connection_closed = obj->backend(LBRIDGE_OP_CONNECTION_CLOSE, obj, p_connection);
	p_connection->connected = false;
	return close_sent && connection_closed;
}

lbridge_context_t lbridge_context_create(struct lbridge_context_params* p_params)
{
	// if secure enabled, nonce function must be provided
#if defined(LBRIDGE_ENABLE_SECURE)
	if(p_params == NULL || p_params->fp_generate_nonce == NULL)
	{
		return NULL;
	}
#endif // LBRIDGE_ENABLE_SECURE
	struct lbridge_context_params params = { 0 };
	if (p_params != NULL)
		params = *p_params;

	if(params.fp_malloc == NULL)
	{
		params.fp_malloc = malloc;
	}
	if(params.fp_free == NULL)
	{
		params.fp_free = free;
	}

	struct lbridge_context* context = (struct lbridge_context*)params.fp_malloc(sizeof(struct lbridge_context));
	if (context == NULL)
	{
		return NULL;
	}
	context->params = params;
	LBRIDGE_LOG_INFO(context, "context created");
	return context;
}

void lbridge_context_destroy(lbridge_context_t p_context)
{
	struct lbridge_context* context = (struct lbridge_context*)p_context;
	if (context != NULL)
	{
		context->params.fp_free(context);
	}
}

uint16_t lbridge_rpc_context_get_rpc_id(const lbridge_rpc_context_t ctx)
{
	if (ctx == NULL)
	{
		return 0;
	}
	return ctx->rpc_id;
}

void lbridge_set_timeout(lbridge_object_t p_object, int32_t timeout_ms)
{
	if (p_object == NULL)
	{
		return;
	}
	__lbridge_object_set_error(p_object, LBRIDGE_ERROR_NONE);
	((struct lbridge_object*)p_object)->timeout_ms = timeout_ms;
}

#if defined(LBRIDGE_ENABLE_SECURE)
void lbridge_activate_encryption(lbridge_object_t p_object, const uint8_t key_256bits[32])
{
	if (p_object == NULL)
	{
		return;
	}
	__lbridge_object_set_error(p_object, LBRIDGE_ERROR_NONE);
	((struct lbridge_object*)p_object)->encryption_key_256bits = key_256bits;
}
#endif // LBRIDGE_ENABLE_SECURE

enum lbridge_error_code lbridge_get_last_error(const lbridge_object_t p_object)
{
	if (p_object == NULL)
	{
		return LBRIDGE_ERROR_BAD_ARGUMENT; // Or some other error code indicating invalid client
	}
	return __lbridge_object_get_error(p_object);
}

void* lbridge_get_backend_data(lbridge_object_t p_object)
{
	if (p_object == NULL)
	{
		return NULL;
	}
	return ((struct lbridge_object*)p_object)->backend_data;
}

void lbridge_set_backend_data(lbridge_object_t p_object, void* data)
{
	if (p_object == NULL)
	{
		return;
	}
	((struct lbridge_object*)p_object)->backend_data = data;
}

void* lbridge_connection_get_handle(struct lbridge_connection* connection)
{
	if (connection == NULL)
	{
		return NULL;
	}
	return connection->as_ptr;
}

void lbridge_connection_set_handle(struct lbridge_connection* connection, void* handle)
{
	if (connection == NULL)
	{
		return;
	}
	connection->as_ptr = handle;
}

enum lbridge_type lbridge_client_get_type(const lbridge_client_t p_client)
{
	if (p_client == NULL)
	{
		return LBRIDGE_TYPE_UNKNOWN;
	}
	return __lbridge_object_get_type(p_client);
}

bool lbridge_rpc_context_send_response(const lbridge_rpc_context_t ctx, const uint8_t* data, uint32_t size)
{
	if (ctx == NULL)
	{
		return false;
	}
	return __lbridge_send_data_sequence_rpc(ctx->object, ctx->rpc_id, data, size, ctx->connection);
}

bool lbridge_rpc_context_send_error(const lbridge_rpc_context_t ctx, enum lbridge_protocol_error error)
{
	if (ctx == NULL)
	{
		return false;
	}
	return __lbridge_close_connection(ctx->object, ctx->connection, error);
}


#if defined(LBRIDGE_ENABLE_CLIENT)

bool __lbridge_client_handshake(lbridge_client_t p_client)
{
	// creates an hanshake frame and sends it
	// Handshake frame: start=1, end=1, cmd=1, opcode=HELLO
	// <!> payload length indicates the size of the payload only for the handshake frame <!>
	// payload: - none if no crypted transfert
	//			- 12 bytes of random nonce if crypted transfert
	uint8_t raw_data[sizeof(struct lbridge_frame) + 12] = {0};
	struct lbridge_frame* handshake_frame = (struct lbridge_frame*)raw_data;
	__lbridge_frame_set_start(handshake_frame, true);
	__lbridge_frame_set_end(handshake_frame, true);
	__lbridge_frame_set_cmd(handshake_frame, true);
#if defined(LBRIDGE_ENABLE_SECURE)
	const bool encryption_needed = !!(p_client->base.encryption_key_256bits != NULL);
#else
	const bool encryption_needed = false;
#endif // LBRIDGE_ENABLE_SECURE

	uint16_t command_data = 0;
	command_data |= ((uint16_t)LBRIDGE_FRAME_HEADER_CMD_HELLO_OPCODE << LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET);
	command_data |= ((uint16_t)(encryption_needed ? 1 : 0) << LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_HELLO_ENCRYPTION_FLAG_OFFSET); // no encryption
	__lbridge_frame_set_cmd_data(handshake_frame, command_data);
	__lbridge_frame_set_payload_length(handshake_frame, p_client->base.max_frame_payload_size); // in the handshake only, the payload length indicates the size of the max data size field (2 bytes)
	if(!__lbridge_send_data(p_client, (const uint8_t*)handshake_frame, sizeof(struct lbridge_frame), &p_client->connection))
	{
		return false;
	}
	// if encryption is needed, server expects a 12 bytes nonce in the payload
#if defined(LBRIDGE_ENABLE_SECURE)
	if (encryption_needed)
	{
		struct lbridge_context* context = __lbridge_object_get_context(p_client);
		// generate random nonce (12 bytes)
		if (!context->params.fp_generate_nonce(context, p_client->connection.counters.receive.full_nonce))
		{
			return false;
		}
		memcpy(p_client->connection.counters.send.full_nonce, p_client->connection.counters.receive.full_nonce, 12);
		if (!__lbridge_send_data(p_client, p_client->connection.counters.send.full_nonce, sizeof(p_client->connection.counters.send.full_nonce), &p_client->connection))
		{
			return false;
		}
	}
#endif // LBRIDGE_ENABLE_SECURE


	// wait for server response header
	memset(raw_data, 0, sizeof(raw_data));
	uint32_t received_size = 0;
	const uint32_t expected_size = sizeof(struct lbridge_frame) + (encryption_needed ? 12 : 0);
	if (!__lbridge_receive_data(p_client, (uint8_t*)handshake_frame, expected_size, &received_size, &p_client->connection, LBRIDGE_RECEIVE_BLOCKING))
	{
		return false;
	}

	if(expected_size < received_size)
	{
		// invalid size
		__lbridge_object_set_error(p_client, LBRIDGE_ERROR_HANDSHAKE_FAILED);
		return false;
	}

	// hanshake frame must be start=1, end=1, cmd=1
	if (!__lbridge_frame_is_start(handshake_frame) || !__lbridge_frame_is_end(handshake_frame) || !__lbridge_frame_is_cmd(handshake_frame))
	{
		__lbridge_object_set_error(p_client, LBRIDGE_ERROR_HANDSHAKE_FAILED);
		return false;
	}

	// check opcode
	command_data = __lbridge_frame_get_cmd_data(handshake_frame);
	const uint8_t opcode = (uint8_t)((command_data & LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_MASK) >> LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET);
	if (opcode != LBRIDGE_FRAME_HEADER_CMD_HELLO_OPCODE)
	{
		__lbridge_object_set_error(p_client, LBRIDGE_ERROR_HANDSHAKE_FAILED);
		return false;
	}

	const uint16_t negotiated_max_payload_len = __lbridge_frame_get_payload_length(handshake_frame);
	if (negotiated_max_payload_len > p_client->base.max_frame_payload_size)
	{
		// server requested more data size than we can handle
		__lbridge_object_set_error(p_client, LBRIDGE_ERROR_HANDSHAKE_FAILED);
		return false;
	}
	p_client->base.max_frame_payload_size = negotiated_max_payload_len;

#if defined(LBRIDGE_ENABLE_SECURE)
	// if encryption is needed, xor the server nonce with client nonce to create the final nonce
	if (encryption_needed)
	{
		for(int i = 0; i < 12; i++)
		{
			p_client->connection.counters.send.full_nonce[i] ^= handshake_frame->data[i];
			p_client->connection.counters.receive.full_nonce[i] = p_client->connection.counters.send.full_nonce[i];
		}
		// inverts the 64-th bit of nonce_counter_receive to differenciate both counters
		p_client->connection.counters.receive.value ^= (1ULL << 63);
	}
#endif // LBRIDGE_ENABLE_SECURE
	p_client->connection.connected = true;
	p_client->connection.waiting_handshake = false;

	return true;
}

lbridge_client_t lbridge_client_create(lbridge_context_t p_context, uint16_t max_frame_payload_size, uint32_t max_payload_size)
{
	if (max_frame_payload_size == 0 || max_payload_size == 0 || p_context == NULL)
	{
		return NULL;
	}
	struct lbridge_context* ctx = (struct lbridge_context*)p_context;
	struct lbridge_client* p_client = ctx->params.fp_malloc(sizeof(struct lbridge_client));
	if (p_client == NULL)
	{
		return NULL;
	}
	__lbridge_object_set_error(p_client, LBRIDGE_ERROR_NONE);
	p_client->base.context = ctx;
	p_client->base.type = LBRIDGE_TYPE_UNKNOWN;
	p_client->base.object_type = LBRIDGE_CLIENT;
	p_client->base.timeout_ms = -1;
	memset(&p_client->connection, 0, sizeof(p_client->connection));
	p_client->connection.waiting_handshake = true;
	p_client->base.backend = NULL;
#if defined(LBRIDGE_ENABLE_SECURE)
	p_client->base.encryption_key_256bits = NULL;
#endif // LBRIDGE_ENABLE_SECURE
	p_client->base.max_frame_payload_size = max_frame_payload_size;
	p_client->base.max_payload_size = max_payload_size;
	return p_client;
}

void lbridge_client_destroy(lbridge_client_t p_client)
{
	if (p_client == NULL)
		return;

	if (p_client->connection.connected)
	{
		__lbridge_close_connection(p_client, &p_client->connection, LBRIDGE_PROTOCOL_ERROR_NONE);
	}

	if (p_client->base.backend != NULL)
	{
		p_client->base.backend(LBRIDGE_OP_CLIENT_CLEANUP, p_client, NULL);
	}

	struct lbridge_context* context = __lbridge_object_get_context(p_client);
	context->params.fp_free(p_client);
}

bool lbridge_client_call_rpc(lbridge_client_t p_client, uint16_t rpc_id, uint8_t* inout_data, uint32_t* inout_size, uint32_t max_out_size)
{
	if (p_client == NULL)
	{
		return false;
	}
	const bool are_arguments_invalid = (inout_data == NULL || inout_size == NULL || (*inout_size > max_out_size && max_out_size != 0));
	if (are_arguments_invalid)
	{
		__lbridge_object_set_error(p_client, LBRIDGE_ERROR_BAD_ARGUMENT);
		return false;
	}
	if (!p_client->connection.connected)
	{
		__lbridge_object_set_error(p_client, LBRIDGE_ERROR_NOT_CONNECTED);
		return false;
	}
	__lbridge_object_set_error(p_client, LBRIDGE_ERROR_NONE);
	LBRIDGE_LOG_TRACE(__lbridge_object_get_context(p_client), "client: rpc call (id=%u, size=%u)", (unsigned)rpc_id, (unsigned)*inout_size);

	const bool response_expected = (max_out_size != 0);

	const bool request_sent = __lbridge_send_data_sequence_rpc(p_client, rpc_id, inout_data, *inout_size, &p_client->connection);
	if (!request_sent)
	{
		return false;
	}
	if (!response_expected)
	{
		memset(inout_data, 0, *inout_size);
		// no response expected, we are done
		return true;
	}
	// now wait for response
	const bool response_received = __lbridge_receive_data_sequence_rpc(p_client, inout_data, max_out_size, inout_size, &p_client->connection);
	return response_received;
}

bool lbridge_client_ping(lbridge_client_t p_client)
{
	if (p_client == NULL)
	{
		return false;
	}
	if (!p_client->connection.connected)
	{
		__lbridge_object_set_error(p_client, LBRIDGE_ERROR_NOT_CONNECTED);
		return false;
	}
	__lbridge_object_set_error(p_client, LBRIDGE_ERROR_NONE);
	LBRIDGE_LOG_TRACE(__lbridge_object_get_context(p_client), "client: ping");

	// Build ping frame: start=1, end=1, cmd=1, opcode=PING, payload_len=0
	struct lbridge_frame ping_frame;
	ping_frame.header = 0;
	__lbridge_frame_set_start(&ping_frame, true);
	__lbridge_frame_set_end(&ping_frame, true);
	__lbridge_frame_set_cmd(&ping_frame, true);

	uint16_t cmd_data = 0;
	cmd_data |= ((uint16_t)LBRIDGE_FRAME_HEADER_CMD_PING_OPCODE << LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET);
	__lbridge_frame_set_cmd_data(&ping_frame, cmd_data);
	__lbridge_frame_set_payload_length(&ping_frame, 0);

	return __lbridge_send_data(p_client, (const uint8_t*)&ping_frame, sizeof(struct lbridge_frame), &p_client->connection);
}

#if defined(LBRIDGE_ENABLE_TCP_CLIENT)

bool lbridge_client_connect_tcp(lbridge_client_t p_client, const char* host, uint16_t port)
{
	if (p_client == NULL)
	{
		return false;
	}
	__lbridge_object_set_error(p_client, LBRIDGE_ERROR_NONE);
	p_client->base.type				= LBRIDGE_TYPE_TCP;
	p_client->base.backend			= &lbridge_backend_tcp_impl;
	struct lbridge_tcp_connection_data connection_data;
	connection_data.host = host;
	connection_data.port = port;
	const bool connected = p_client->base.backend(LBRIDGE_OP_CLIENT_CONNECT, p_client, &connection_data);
	if (!connected)
	{
		return false;
	}
	if (!__lbridge_client_handshake(p_client))
	{
		return false;
	}
	LBRIDGE_LOG_INFO(__lbridge_object_get_context(p_client), "client connected (TCP %s:%u)", host, (unsigned)port);
	return true;
}
#endif

#if defined(LBRIDGE_ENABLE_UNIX_CLIENT)

bool lbridge_client_connect_unix(lbridge_client_t p_client, const char* socket_path)
{
	if (p_client == NULL || socket_path == NULL)
	{
		return false;
	}
	__lbridge_object_set_error(p_client, LBRIDGE_ERROR_NONE);
	p_client->base.type = LBRIDGE_TYPE_UNIX;
	p_client->base.backend = &lbridge_backend_unix_impl;
	struct lbridge_unix_connection_data connection_data;
	connection_data.socket_path = socket_path;
	const bool connected = p_client->base.backend(LBRIDGE_OP_CLIENT_CONNECT, p_client, &connection_data);
	if (!connected)
	{
		return false;
	}
	if (!__lbridge_client_handshake(p_client))
	{
		return false;
	}
	LBRIDGE_LOG_INFO(__lbridge_object_get_context(p_client), "client connected (UNIX %s)", socket_path);
	return true;
}
#endif

#if defined(LBRIDGE_ENABLE_BLUETOOTH_CLIENT)

bool lbridge_client_connect_bluetooth(lbridge_client_t p_client, const char* address, uint8_t channel)
{
	if (p_client == NULL || address == NULL)
	{
		return false;
	}
	if (channel < 1 || channel > 30)
	{
		__lbridge_object_set_error(p_client, LBRIDGE_ERROR_BAD_ARGUMENT);
		return false;
	}
	__lbridge_object_set_error(p_client, LBRIDGE_ERROR_NONE);
	p_client->base.type = LBRIDGE_TYPE_BLUETOOTH;
	p_client->base.backend = &lbridge_backend_bluetooth_impl;
	struct lbridge_bluetooth_connection_data connection_data;
	connection_data.address = address;
	connection_data.channel = channel;
	const bool connected = p_client->base.backend(LBRIDGE_OP_CLIENT_CONNECT, p_client, &connection_data);
	if (!connected)
	{
		return false;
	}
	return __lbridge_client_handshake(p_client);
}
#endif

bool lbridge_client_connect_custom(lbridge_client_t p_client, lbridge_custom_backend_fn backend, void* user_data, void* connect_arg)
{
	if (p_client == NULL || backend == NULL)
	{
		return false;
	}
	__lbridge_object_set_error(p_client, LBRIDGE_ERROR_NONE);
	p_client->base.type = LBRIDGE_TYPE_CUSTOM;
	p_client->base.backend = backend;
	p_client->base.backend_data = user_data;
	const bool connected = p_client->base.backend(LBRIDGE_OP_CLIENT_CONNECT, p_client, connect_arg);
	if (!connected)
	{
		return false;
	}
	return __lbridge_client_handshake(p_client);
}

#endif // LBRIDGE_ENABLE_CLIENT
#if defined(LBRIDGE_ENABLE_SERVER)

lbridge_server_t lbridge_server_create(lbridge_context_t p_context, uint16_t max_frame_payload_size, uint32_t max_payload_size, fp_rpc_call on_rpc_call)
{
	if (p_context == NULL || max_frame_payload_size == 0 || max_payload_size == 0 || on_rpc_call == NULL)
	{
		return NULL;
	}
	struct lbridge_context* context = (struct lbridge_context*)p_context;
	struct lbridge_server* p_server = context->params.fp_malloc(sizeof(struct lbridge_server));
	if (p_server == NULL)
	{
		return NULL;
	}
	__lbridge_object_set_error(p_server, LBRIDGE_ERROR_NONE);
	p_server->base.context = context;
	p_server->base.type = LBRIDGE_TYPE_UNKNOWN;
	p_server->base.object_type = LBRIDGE_SERVER;
	p_server->base.timeout_ms = 0; // Non-blocking by default for server operations
	p_server->rpc_call = on_rpc_call;
	p_server->base.backend = NULL;
	p_server->base.backend_data = NULL;
#if defined(LBRIDGE_ENABLE_SECURE)
	p_server->base.encryption_key_256bits = NULL;
#endif // LBRIDGE_ENABLE_SECURE
	p_server->base.max_frame_payload_size = max_frame_payload_size;
	p_server->base.max_payload_size = max_payload_size;
	p_server->connections.capacity = 0;
	p_server->connections.size = 0;
	p_server->connections.array = NULL;
	p_server->client_timeout_ms = 0; // disabled by default
	return p_server;
}

void __lbridge_server_free_connection(lbridge_server_t p_server, struct lbridge_connection_async* p_connection)
{
	if (p_server == NULL || p_connection == NULL)
	{
		return;
	}
	struct lbridge_context* context = __lbridge_object_get_context(p_server);
	context->params.fp_free(p_connection->receive_buffer);
#if defined(LBRIDGE_ENABLE_SECURE)
	mbedtls_chachapoly_free(&p_connection->chachapoly_ctx);
#endif // LBRIDGE_ENABLE_SECURE
}

void lbridge_server_destroy(lbridge_server_t p_server)
{
	if (p_server == NULL)
		return;

	// disconnect all clients
	if (p_server->connections.array != NULL)
	{
		for(uint32_t i_connection = 0; i_connection < p_server->connections.size; ++i_connection)
		{
			struct lbridge_connection_async* p_connection = &p_server->connections.array[i_connection];
			if (p_connection->base.connected)
			{
				__lbridge_close_connection(p_server, (struct lbridge_connection*)p_connection, LBRIDGE_PROTOCOL_ERROR_NONE);
			}
			__lbridge_server_free_connection(p_server, p_connection);
		}
	}

	// Close the listening socket
	if (p_server->base.backend != NULL && p_server->base.backend_data != NULL)
	{
		p_server->base.backend(LBRIDGE_OP_SERVER_CLEANUP, p_server, NULL);
	}

	struct lbridge_context* context = __lbridge_object_get_context(p_server);
	if (p_server->connections.array != NULL)
	{
		context->params.fp_free(p_server->connections.array);
	}
	context->params.fp_free(p_server);
}

void lbridge_server_set_client_timeout(lbridge_server_t p_server, uint32_t timeout_ms)
{
	if (p_server == NULL)
		return;
	p_server->client_timeout_ms = timeout_ms;
}


bool __lbridge_server_handshake(lbridge_server_t p_server, struct lbridge_connection_async* p_connection)
{
	// process handshake (size of handshake frame is 4 bytes + optional 12 bytes for nonce if encryption requested)
	uint8_t raw_data[sizeof(struct lbridge_frame) + 12] = { 0 };
	struct lbridge_frame* handshake_frame = (struct lbridge_frame*)raw_data;
	// wait for server response header
	memset(raw_data, 0, sizeof(raw_data));
	uint32_t received_size = 0;
	// 4 bytes header
	if (!__lbridge_receive_data(p_server, (uint8_t*)handshake_frame, sizeof(struct lbridge_frame), &received_size, (struct lbridge_connection*)p_connection, 0))
	{
		return false;
	}
	if (received_size == 0)
	{
		return true; // no data yet
	}
	// hanshake frame must be start=1, end=1, cmd=1
	if (!__lbridge_frame_is_start(handshake_frame) || !__lbridge_frame_is_end(handshake_frame) || !__lbridge_frame_is_cmd(handshake_frame))
	{
		__lbridge_close_connection(p_server, (struct lbridge_connection*)p_connection, LBRIDGE_PROTOCOL_ERROR_INVALID_FRAME_FLAG);
		return false;
	}
	// handshake frame opcode must be HELLO
	const uint16_t cmd_data = __lbridge_frame_get_cmd_data(handshake_frame);
	const uint8_t opcode = (uint8_t)((cmd_data & LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_MASK) >> LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET);
	if (opcode != LBRIDGE_FRAME_HEADER_CMD_HELLO_OPCODE)
	{
		__lbridge_close_connection(p_server, (struct lbridge_connection*)p_connection, LBRIDGE_PROTOCOL_ERROR_INVALID_OPCODE_HANDSHAKE);
		return false;
	}
	LBRIDGE_LOG_INFO(__lbridge_object_get_context(p_server), "server: handshake request received");

	// next 2 bytes are max payload size per frame supported by client
	// the negotiated value is the minimum between server and client capabilities
	const uint16_t client_max_frame_payload_size = __lbridge_frame_get_payload_length(handshake_frame);
	const uint16_t negotiated_max_payload_size = min(client_max_frame_payload_size, p_server->base.max_frame_payload_size);

	// if encryption requested, we check the 12 bytes of nonce
	const bool client_encryption_flag = (cmd_data & LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_HELLO_ENCRYPTION_FLAG_MASK) != 0;
	if (client_encryption_flag)
	{
#if defined(LBRIDGE_ENABLE_SECURE)
		// if server has no encryption key, we cannot proceed
		if (p_server->base.encryption_key_256bits == NULL)
		{
			__lbridge_close_connection(p_server, (struct lbridge_connection*)p_connection, LBRIDGE_PROTOCOL_ERROR_ENCRYPTION_NOT_ACTIVATED_ON_SERVER);
			return false;
		}
		// 12 bytes of nonce in payload
		if (!__lbridge_receive_data(p_server, (uint8_t*)handshake_frame + sizeof(struct lbridge_frame), 12, &received_size, (struct lbridge_connection*)p_connection, 0))
		{
			__lbridge_close_connection(p_server, (struct lbridge_connection*)p_connection, LBRIDGE_PROTOCOL_ERROR_HANDSHAKE_ERROR);
			return false;
		}
		if (received_size < 12)
		{
			return true; // no data yet
		}

		// generate server nonce (12 bytes)
		uint8_t server_nonce[12];
		struct lbridge_context* context = __lbridge_object_get_context(p_server);
		// generate random nonce (12 bytes)
		if (!context->params.fp_generate_nonce(context, server_nonce))
		{
			__lbridge_close_connection(p_server, (struct lbridge_connection*)p_connection, LBRIDGE_PROTOCOL_ERROR_INTERNAL);
			return false;
		}
		for (uint8_t i = 0; i < 12; ++i)
		{
			// we XOR client nonce and server nonce to create shared nonce
			p_connection->base.counters.send.full_nonce[i] = server_nonce[i] ^ raw_data[sizeof(struct lbridge_frame) + i];
			p_connection->base.counters.receive.full_nonce[i] = p_connection->base.counters.send.full_nonce[i];
		}
		// inverts the 64-th bit of nonce_counter_receive to differenciate both counters
		p_connection->base.counters.send.value ^= (1ULL << 63);
		// prepare the server nonce to be sent to client
		for (uint8_t i = 0; i < 12; ++i)
		{
			raw_data[sizeof(struct lbridge_frame) + i] = server_nonce[i];
		}

		mbedtls_chachapoly_init(&p_connection->chachapoly_ctx);
		mbedtls_chachapoly_setkey(&p_connection->chachapoly_ctx, p_server->base.encryption_key_256bits);
#else
		__lbridge_close(p_server, (struct lbridge_connection*)p_connection, LBRIDGE_PROTOCOL_ERROR_ENCRYPTION_NOT_SUPPORTED_ON_SERVER);
		return false;
#endif // LBRIDGE_ENABLE_SECURE
	}

	// sends handshake response
	__lbridge_frame_set_start(handshake_frame, true);
	__lbridge_frame_set_end(handshake_frame, true);
	__lbridge_frame_set_cmd(handshake_frame, true);
	uint16_t command_data_response = 0;
	command_data_response |= ((uint16_t)LBRIDGE_FRAME_HEADER_CMD_HELLO_OPCODE << LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET);
	command_data_response |= ((uint16_t)(client_encryption_flag ? 1 : 0) << LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_HELLO_ENCRYPTION_FLAG_OFFSET); // encryption flag
	__lbridge_frame_set_cmd_data(handshake_frame, command_data_response);
	__lbridge_frame_set_payload_length(handshake_frame, negotiated_max_payload_size); // in the handshake only, the payload length indicates the size of the max data size field (2 bytes)
	if (!__lbridge_send_data(p_server, (const uint8_t*)handshake_frame, sizeof(struct lbridge_frame) + (client_encryption_flag ? 12 : 0), (struct lbridge_connection*)p_connection))
	{
		__lbridge_close_connection(p_server, (struct lbridge_connection*)p_connection, LBRIDGE_PROTOCOL_ERROR_HANDSHAKE_ERROR);
		return false;
	}

	// process handshake frame
	p_connection->base.waiting_handshake = false;
	p_connection->base.connected = true;
	LBRIDGE_LOG_INFO(__lbridge_object_get_context(p_server), "server: handshake completed");
	return true;
}

bool __lbridge_server_allocate_connections(lbridge_server_t p_server, uint32_t max_nb_clients)
{
	struct lbridge_context* context = __lbridge_object_get_context(p_server);
	p_server->connections.array = context->params.fp_malloc(sizeof(struct lbridge_connection_async) * max_nb_clients);
	if (p_server->connections.array == NULL)
	{
		__lbridge_object_set_error(p_server, LBRIDGE_ERROR_BAD_ALLOC);
		return false;
	}
	p_server->connections.capacity = max_nb_clients;
	p_server->connections.size = 0;
	return true;
}

void __lbridge_server_free_connections(lbridge_server_t p_server)
{
	struct lbridge_context* context = __lbridge_object_get_context(p_server);
	context->params.fp_free(p_server->connections.array);
	p_server->connections.array = NULL;
	p_server->connections.capacity = 0;
}

#if defined(LBRIDGE_ENABLE_TCP_SERVER)

bool LBRIDGE_API lbridge_server_listen_tcp(lbridge_server_t p_server, const char* address, uint16_t port, uint32_t max_nb_clients)
{
	if (p_server == NULL || max_nb_clients == 0)
	{
		return false;
	}
	__lbridge_object_set_error(p_server, LBRIDGE_ERROR_NONE);

	if (!__lbridge_server_allocate_connections(p_server, max_nb_clients))
	{
		return false;
	}

	p_server->base.type = LBRIDGE_TYPE_TCP;
	p_server->base.backend = &lbridge_backend_tcp_impl;
	struct lbridge_tcp_connection_data connection_data;
	connection_data.host = address;
	connection_data.port = port;
	const bool connected = p_server->base.backend(LBRIDGE_OP_SERVER_OPEN, p_server, &connection_data);
	if (!connected)
	{
		__lbridge_server_free_connections(p_server);
		return false;
	}
	LBRIDGE_LOG_INFO(__lbridge_object_get_context(p_server), "server listening (TCP %s:%u)", address, (unsigned)port);
	return true;
}

#endif // LBRIDGE_ENABLE_TCP_SERVER

#if defined(LBRIDGE_ENABLE_UNIX_SERVER)

bool LBRIDGE_API lbridge_server_listen_unix(lbridge_server_t p_server, const char* socket_path, uint32_t max_nb_clients)
{
	if (p_server == NULL || socket_path == NULL || max_nb_clients == 0)
	{
		return false;
	}
	__lbridge_object_set_error(p_server, LBRIDGE_ERROR_NONE);

	if (!__lbridge_server_allocate_connections(p_server, max_nb_clients))
	{
		return false;
	}

	p_server->base.type = LBRIDGE_TYPE_UNIX;
	p_server->base.backend = &lbridge_backend_unix_impl;
	struct lbridge_unix_server_data server_data;
	server_data.socket_path = socket_path;
	const bool connected = p_server->base.backend(LBRIDGE_OP_SERVER_OPEN, p_server, &server_data);
	if (!connected)
	{
		__lbridge_server_free_connections(p_server);
		return false;
	}
	return true;
}

#endif // LBRIDGE_ENABLE_UNIX_SERVER

#if defined(LBRIDGE_ENABLE_BLUETOOTH_SERVER)

bool LBRIDGE_API lbridge_server_listen_bluetooth(lbridge_server_t p_server, uint8_t channel, uint32_t max_nb_clients)
{
	if (p_server == NULL || max_nb_clients == 0)
	{
		return false;
	}
	if (channel < 1 || channel > 30)
	{
		__lbridge_object_set_error(p_server, LBRIDGE_ERROR_BAD_ARGUMENT);
		return false;
	}
	__lbridge_object_set_error(p_server, LBRIDGE_ERROR_NONE);

	if (!__lbridge_server_allocate_connections(p_server, max_nb_clients))
	{
		return false;
	}

	p_server->base.type = LBRIDGE_TYPE_BLUETOOTH;
	p_server->base.backend = &lbridge_backend_bluetooth_impl;
	struct lbridge_bluetooth_server_data server_data;
	server_data.channel = channel;
	const bool connected = p_server->base.backend(LBRIDGE_OP_SERVER_OPEN, p_server, &server_data);
	if (!connected)
	{
		__lbridge_server_free_connections(p_server);
		return false;
	}
	return true;
}

#endif // LBRIDGE_ENABLE_BLUETOOTH_SERVER

bool LBRIDGE_API lbridge_server_listen_custom(lbridge_server_t p_server, lbridge_custom_backend_fn backend, void* user_data, void* listen_arg, uint32_t max_nb_clients)
{
	if (p_server == NULL || backend == NULL || max_nb_clients == 0)
	{
		return false;
	}
	__lbridge_object_set_error(p_server, LBRIDGE_ERROR_NONE);

	if (!__lbridge_server_allocate_connections(p_server, max_nb_clients))
	{
		return false;
	}

	p_server->base.type = LBRIDGE_TYPE_CUSTOM;
	p_server->base.backend = backend;
	p_server->base.backend_data = user_data;
	const bool opened = p_server->base.backend(LBRIDGE_OP_SERVER_OPEN, p_server, listen_arg);
	if (!opened)
	{
		__lbridge_server_free_connections(p_server);
		return false;
	}
	return true;
}

void __lbridge_server_remove_connection(lbridge_server_t p_server, uint32_t index, enum lbridge_protocol_error error)
{
	if (p_server == NULL || index >= p_server->connections.size)
	{
		return;
	}
	LBRIDGE_LOG_INFO(__lbridge_object_get_context(p_server), "server: client disconnected");
	struct lbridge_connection_async* connection = &p_server->connections.array[index];
	if (connection->base.connected)
	{
		__lbridge_close_connection(p_server, (struct lbridge_connection*)connection, error);
	}
	__lbridge_server_free_connection(p_server, connection);
	// shift remaining connections
	for (uint32_t i = index; i < p_server->connections.size - 1; i++)
	{
		p_server->connections.array[i] = p_server->connections.array[i + 1];
	}
	p_server->connections.size--;
}

bool LBRIDGE_API lbridge_server_update(lbridge_server_t p_server)
{
	if (p_server == NULL)
	{
		return false;
	}
	__lbridge_object_set_error(p_server, LBRIDGE_ERROR_NONE);

	// accepts new client
	struct lbridge_server_accept_data accept_data;
	do
	{
		// accepts new clients only if there is capacity
		if (p_server->connections.size == p_server->connections.capacity)
			break;
		struct lbridge_connection_async connection;
		memset(&connection, 0, sizeof(connection));
		connection.base.connected = false;
		connection.base.waiting_handshake = false;
		accept_data.new_connection = (struct lbridge_connection*)&connection;
		accept_data.new_client_accepted = false;
		if (!p_server->base.backend(LBRIDGE_OP_SERVER_ACCEPT, p_server, &accept_data))
			return false;
		if (accept_data.new_client_accepted)
		{
			LBRIDGE_LOG_INFO(__lbridge_object_get_context(p_server), "server: client accepted");
			connection.base.connected = true;
			connection.base.waiting_handshake = true;
			// Initialize last activity timestamp if time callback is available
			struct lbridge_context* ctx = __lbridge_object_get_context(p_server);
			if (ctx->params.fp_get_time_ms != NULL)
			{
				connection.last_activity_ms = ctx->params.fp_get_time_ms(ctx);
			}
			else
			{
				connection.last_activity_ms = 0;
			}
			p_server->connections.array[p_server->connections.size++] = connection;
		}

	} while (accept_data.new_client_accepted);

	// Get current time for timeout checking
	struct lbridge_context* ctx = __lbridge_object_get_context(p_server);
	const bool timeout_enabled = (p_server->client_timeout_ms > 0 && ctx->params.fp_get_time_ms != NULL);
	const uint64_t current_time_ms = timeout_enabled ? ctx->params.fp_get_time_ms(ctx) : 0;

	for(uint32_t i_connection = 0; i_connection < p_server->connections.size; )
	{
		struct lbridge_connection_async* connection = &p_server->connections.array[i_connection];

		// Check for client timeout
		if (timeout_enabled && connection->base.connected && !connection->base.waiting_handshake)
		{
			const uint64_t elapsed_ms = current_time_ms - connection->last_activity_ms;
			if (elapsed_ms >= p_server->client_timeout_ms)
			{
				LBRIDGE_LOG_INFO(__lbridge_object_get_context(p_server), "server: client timed out");
				__lbridge_server_remove_connection(p_server, i_connection, LBRIDGE_PROTOCOL_ERROR_INACTIVITY_TIMEOUT);
				continue; // connection removed, don't increment i_connection
			}
		}
		// Check if client is disconnected
		if (!connection->base.connected && !connection->base.waiting_handshake)
		{
			__lbridge_server_remove_connection(p_server, i_connection, LBRIDGE_PROTOCOL_ERROR_NONE);
			continue; // connection removed, don't increment i_connection
		}

		if (connection->base.waiting_handshake)
		{
			if (!__lbridge_server_handshake(p_server, connection))
			{
				__lbridge_server_remove_connection(p_server, i_connection, LBRIDGE_PROTOCOL_ERROR_HANDSHAKE_ERROR);
				goto lbl_next_connection;
			}
			// Update activity timestamp after successful handshake
			if (timeout_enabled && connection->base.connected)
			{
				connection->last_activity_ms = current_time_ms;
			}
		}
		else if(connection->base.connected)
		{
			while (connection->base.connected)
			{
				// check if there is data to process
				if(connection->current_frame_header == 0)
				{
					struct lbridge_frame header;
					uint32_t received_size = 0;
					if (!__lbridge_receive_data(p_server, (uint8_t*)&header, sizeof(struct lbridge_frame), &received_size, (struct lbridge_connection*)connection, 0))
					{
						__lbridge_server_remove_connection(p_server, i_connection, LBRIDGE_PROTOCOL_ERROR_INTERNAL);
						goto lbl_next_connection;
					}
					if (received_size == 0)
					{
						// no more data pending for this client, we can check the next one
						break;
					}

					// Update activity timestamp on data reception
					if (timeout_enabled)
					{
						connection->last_activity_ms = current_time_ms;
					}

					// if frame is a command frame, process it
					if (__lbridge_frame_is_cmd(&header))
					{
						const uint16_t cmd_data = __lbridge_frame_get_cmd_data(&header);
						const uint8_t opcode = (uint8_t)((cmd_data & LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_MASK) >> LBRIDGE_FRAME_HEADER_CMD_DATA_OPCODE_OFFSET);
						switch (opcode)
						{
						case LBRIDGE_FRAME_HEADER_CMD_CLOSE_OPCODE:
						{
							enum lbridge_protocol_error error = (enum lbridge_protocol_error)((cmd_data >> 8) & 0xFF);
							(void)error;  // error received from client (can be logged if needed)
							connection->base.connected = false;
							__lbridge_server_remove_connection(p_server, i_connection, LBRIDGE_PROTOCOL_ERROR_NONE);
							goto lbl_next_connection;
						}
						case LBRIDGE_FRAME_HEADER_CMD_PING_OPCODE:
							// Ping received - activity timestamp already updated above
							// No response needed, continue processing
							continue;
						default:
							break;
						}
					}

					connection->current_frame_header = header.header;
					if(connection->receive_buffer == NULL)
					{
						// allocate receive buffer
						struct lbridge_context* context = __lbridge_object_get_context(p_server);
						connection->receive_buffer = context->params.fp_malloc(p_server->base.max_payload_size);
						if (connection->receive_buffer == NULL)
						{
							__lbridge_server_remove_connection(p_server, i_connection, LBRIDGE_PROTOCOL_ERROR_INTERNAL);
							goto lbl_next_connection;
						}
						connection->receive_buffer_used_size = 0;
					}
#if defined(LBRIDGE_ENABLE_SECURE)
					// if encryption is enabled, prepare/append decryption context for the sequence
					if (p_server->base.encryption_key_256bits != NULL)
					{
						// if new sequence, start cha-cha-poly context
						if (connection->receive_buffer_used_size == 0)
						{
							mbedtls_chachapoly_starts(&connection->chachapoly_ctx, connection->base.counters.receive.full_nonce, MBEDTLS_CHACHAPOLY_DECRYPT);
						}

						// add header to AAD
						mbedtls_chachapoly_update_aad(&connection->chachapoly_ctx, (const uint8_t*)&connection->current_frame_header, sizeof(struct lbridge_frame));
					}
#endif // LBRIDGE_ENABLE_SECURE
				}

				if(connection->current_frame_header != 0)
				{
					// there is data to process
					const uint16_t payload_length = __lbridge_frame_get_payload_length((const struct lbridge_frame*)&connection->current_frame_header);
					const uint16_t rpc_id = __lbridge_frame_get_rpc_id((const struct lbridge_frame*)&connection->current_frame_header);
					const bool is_end_frame = __lbridge_frame_is_end((const struct lbridge_frame*)&connection->current_frame_header);
					if (payload_length > 0)
					{
						uint32_t received_size = 0;
						// receive payload
						if (!__lbridge_receive_data(p_server, connection->receive_buffer + connection->receive_buffer_used_size, payload_length, &received_size, (struct lbridge_connection*)connection, 0))
						{
							__lbridge_server_remove_connection(p_server, i_connection, LBRIDGE_PROTOCOL_ERROR_INTERNAL);
							goto lbl_next_connection;
						}
						if (received_size == 0)
						{
							// no more data pending for this client, we can check the next one
							break;
						}
						connection->receive_buffer_used_size += received_size;
					}
					connection->current_frame_header = 0; // reset for next frame
					// a full message has been received, we can process it
					if (is_end_frame)
					{
						// if encryption is enabled, finalize decryption
#if defined(LBRIDGE_ENABLE_SECURE)
						if (p_server->base.encryption_key_256bits != NULL)
						{
							if (connection->receive_buffer_used_size < 8)
							{
								__lbridge_server_remove_connection(p_server, i_connection, LBRIDGE_PROTOCOL_ERROR_INVALID_PAYLOAD_LENGTH);
								goto lbl_next_connection;
							}
							uint32_t pure_data_size = connection->receive_buffer_used_size - 8;
							uint8_t generated_tag[16];
							// Decode data and process the tag
							mbedtls_chachapoly_update(&connection->chachapoly_ctx, pure_data_size, connection->receive_buffer, connection->receive_buffer);
							mbedtls_chachapoly_finish(&connection->chachapoly_ctx, generated_tag);
							// Compare the first 8 bytes of the generated tag with the received tag
							if (memcmp(connection->receive_buffer + pure_data_size, generated_tag, 8) != 0)
							{
								__lbridge_server_remove_connection(p_server, i_connection, LBRIDGE_PROTOCOL_ERROR_AUTHENTICATION_FAILED);
								goto lbl_next_connection;
							}
							connection->receive_buffer_used_size = pure_data_size;
							// zero the remaining buffer for security
							memset(connection->receive_buffer + pure_data_size, 0, 8);
							// increment receive counter
							connection->base.counters.receive.value++;
						}
#endif // LBRIDGE_ENABLE_SECURE

						LBRIDGE_LOG_TRACE(__lbridge_object_get_context(p_server), "server: rpc received (id=%u, size=%u)", (unsigned)rpc_id, (unsigned)connection->receive_buffer_used_size);
						struct lbridge_rpc_context rpc_ctx;
						rpc_ctx.object = p_server;
						rpc_ctx.connection = (struct lbridge_connection*)connection;
						rpc_ctx.rpc_id = rpc_id;
						p_server->rpc_call(&rpc_ctx, connection->receive_buffer, connection->receive_buffer_used_size);
						connection->receive_buffer_used_size = 0;
					}
				}
			}


		}
		i_connection++;
		lbl_next_connection:;
	}

	return true;
}

#endif // LBRIDGE_ENABLE_SERVER

#ifdef __cplusplus
}
#endif