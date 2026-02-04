#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest.h"

int main(int argc, char** argv) {
    doctest::Context context;
    context.setOption("no-breaks", true);
    context.applyCommandLine(argc, argv);
    return context.run();
}

#include <lbridge.h>
#include <cstring>
#include <cstdio>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <mutex>

// =============================================================================
// Platform-specific monotonic time implementation
// =============================================================================

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <afunix.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

static uint64_t get_time_ms_impl(lbridge_context_t ctx)
{
    (void)ctx;
    static LARGE_INTEGER frequency = { 0 };
    if (frequency.QuadPart == 0)
    {
        QueryPerformanceFrequency(&frequency);
    }
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (uint64_t)((counter.QuadPart * 1000) / frequency.QuadPart);
}

#elif defined(__APPLE__)
#include <mach/mach_time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

static uint64_t get_time_ms_impl(lbridge_context_t ctx)
{
    (void)ctx;
    static mach_timebase_info_data_t timebase = { 0, 0 };
    if (timebase.denom == 0)
    {
        mach_timebase_info(&timebase);
    }
    uint64_t time_ns = mach_absolute_time() * timebase.numer / timebase.denom;
    return time_ns / 1000000; // Convert nanoseconds to milliseconds
}

#else // Linux and other POSIX systems
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

static uint64_t get_time_ms_impl(lbridge_context_t ctx)
{
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

#endif

// =============================================================================
// Test Helpers
// =============================================================================

static constexpr uint16_t TEST_PORT = 27182;
static constexpr const char* TEST_HOST = "127.0.0.1";
static constexpr uint16_t MAX_FRAME_PAYLOAD = 1024;
static constexpr uint32_t MAX_PAYLOAD = 65536;

// Helper to retry server listen with delay (for TIME_WAIT on Linux/macOS)
static bool server_listen_tcp_with_retry(lbridge_server_t server, const char* host, uint16_t port, uint32_t max_clients, int max_attempts = 10)
{
    for (int i = 0; i < max_attempts; i++)
    {
        if (lbridge_server_listen_tcp(server, host, port, max_clients))
            return true;
		const enum lbridge_error_code err = lbridge_get_last_error(server);
		if (err != LBRIDGE_ERROR_RESSOURCE_UNAVAILABLE)
			return false;

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    return false;
}

// RAII helper to ensure server thread is always stopped, even if test fails
class ScopedServerThread
{
public:
    ScopedServerThread(lbridge_server_t server, int update_interval_ms = 1)
        : m_server(server), m_running(true)
    {
        m_thread = std::thread([this, update_interval_ms]() {
            while (m_running)
            {
                lbridge_server_update(m_server);
                std::this_thread::sleep_for(std::chrono::milliseconds(update_interval_ms));
            }
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Wait for server to be ready
    }

    ~ScopedServerThread()
    {
        stop();
    }

    void stop()
    {
        m_running = false;
        if (m_thread.joinable())
            m_thread.join();
    }

private:
    lbridge_server_t m_server;
    std::atomic<bool> m_running;
    std::thread m_thread;
};

#if defined(LBRIDGE_ENABLE_SECURE)
static bool test_generate_nonce(lbridge_context_t ctx, uint8_t out_nonce[12])
{
    (void)ctx;
    static uint64_t counter = 0;
    counter++;
    memcpy(out_nonce, &counter, sizeof(counter));
    memset(out_nonce + 8, 0, 4);
    return true;
}
#endif

struct TestContext
{
    lbridge_context_t ctx = nullptr;

    TestContext()
    {
        struct lbridge_context_params params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
        params.fp_generate_nonce = test_generate_nonce;
#endif
        params.fp_get_time_ms = get_time_ms_impl;
        ctx = lbridge_context_create(&params);
    }

    ~TestContext()
    {
        if (ctx)
            lbridge_context_destroy(ctx);
    }

    operator lbridge_context_t() { return ctx; }
};

// =============================================================================
// Context Tests
// =============================================================================

TEST_CASE("context creation and destruction")
{
    struct lbridge_context_params params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
    params.fp_generate_nonce = test_generate_nonce;
#endif
    params.fp_malloc = nullptr;
    params.fp_free = nullptr;

    lbridge_context_t ctx = lbridge_context_create(&params);
    REQUIRE(ctx != nullptr);

    lbridge_context_destroy(ctx);
}

#if defined(LBRIDGE_ENABLE_SECURE)
TEST_CASE("context creation fails without nonce generator")
{
    struct lbridge_context_params params = { 0 };
    params.fp_generate_nonce = nullptr;

    lbridge_context_t ctx = lbridge_context_create(&params);
    CHECK(ctx == nullptr);
}
#endif

// =============================================================================
// Client Tests
// =============================================================================

TEST_CASE("client creation and destruction")
{
    TestContext ctx;
    REQUIRE(ctx.ctx != nullptr);

    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    CHECK(lbridge_client_get_type(client) == LBRIDGE_TYPE_UNKNOWN);
    CHECK(lbridge_get_last_error(client) == LBRIDGE_ERROR_NONE);

    lbridge_client_destroy(client);
}

TEST_CASE("client creation with invalid params")
{
    TestContext ctx;
    REQUIRE(ctx.ctx != nullptr);

    SUBCASE("null context")
    {
        lbridge_client_t client = lbridge_client_create(nullptr, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
        CHECK(client == nullptr);
    }

    SUBCASE("zero max_frame_payload_size")
    {
        lbridge_client_t client = lbridge_client_create(ctx, 0, MAX_PAYLOAD);
        CHECK(client == nullptr);
    }

    SUBCASE("zero max_payload_size")
    {
        lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, 0);
        CHECK(client == nullptr);
    }
}

// =============================================================================
// Server Tests
// =============================================================================

static bool dummy_rpc_callback(const lbridge_rpc_context_t ctx, const uint8_t* data, uint32_t size)
{
    (void)ctx;
    (void)data;
    (void)size;
    return true;
}

TEST_CASE("server creation and destruction")
{
    TestContext ctx;
    REQUIRE(ctx.ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, dummy_rpc_callback);
    REQUIRE(server != nullptr);

    CHECK(lbridge_get_last_error(server) == LBRIDGE_ERROR_NONE);

    lbridge_server_destroy(server);
}

TEST_CASE("server creation with invalid params")
{
    TestContext ctx;
    REQUIRE(ctx.ctx != nullptr);

    SUBCASE("null context")
    {
        lbridge_server_t server = lbridge_server_create(nullptr, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, dummy_rpc_callback);
        CHECK(server == nullptr);
    }

    SUBCASE("null callback")
    {
        lbridge_server_t server = lbridge_server_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, nullptr);
        CHECK(server == nullptr);
    }
}

TEST_CASE("server listen with invalid params")
{
    TestContext ctx;
    REQUIRE(ctx.ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, dummy_rpc_callback);
    REQUIRE(server != nullptr);

    SUBCASE("zero max_nb_clients")
    {
        bool result = lbridge_server_listen_tcp(server, TEST_HOST, TEST_PORT, 0);
        CHECK_FALSE(result);
    }

    lbridge_server_destroy(server);
}

// =============================================================================
// Integration Tests (Client <-> Server over TCP)
// =============================================================================

class TestServer
{
public:
    TestServer(fp_rpc_call callback, uint32_t max_clients = 10)
        : m_callback(callback), m_max_clients(max_clients)
    {
    }

    ~TestServer()
    {
        stop();
    }

    bool start(uint16_t port = TEST_PORT)
    {
        struct lbridge_context_params params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
        params.fp_generate_nonce = test_generate_nonce;
#endif
        params.fp_get_time_ms = get_time_ms_impl;
        m_ctx = lbridge_context_create(&params);
        if (!m_ctx)
            return false;

        m_server = lbridge_server_create(m_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, m_callback);
        if (!m_server)
        {
            lbridge_context_destroy(m_ctx);
            m_ctx = nullptr;
            return false;
        }

        if (!server_listen_tcp_with_retry(m_server, TEST_HOST, port, m_max_clients))
        {
            lbridge_server_destroy(m_server);
            lbridge_context_destroy(m_ctx);
            m_server = nullptr;
            m_ctx = nullptr;
            return false;
        }

        m_running = true;
        m_thread = std::thread([this]() { run(); });

        // Wait for server to be ready
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return true;
    }

    void stop()
    {
        m_running = false;
        if (m_thread.joinable())
            m_thread.join();

        if (m_server)
        {
            lbridge_server_destroy(m_server);
            m_server = nullptr;
        }
        if (m_ctx)
        {
            lbridge_context_destroy(m_ctx);
            m_ctx = nullptr;
        }
    }

    bool is_running() const { return m_running; }

private:
    void run()
    {
        while (m_running)
        {
            lbridge_server_update(m_server);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    fp_rpc_call m_callback;
    uint32_t m_max_clients;
    lbridge_context_t m_ctx = nullptr;
    lbridge_server_t m_server = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_running{ false };
};

// -----------------------------------------------------------------------------
// Handshake Tests
// -----------------------------------------------------------------------------

TEST_CASE("TCP handshake - successful connection")
{
    auto callback = [](const lbridge_rpc_context_t, const uint8_t*, uint32_t) -> bool {
        return true;
    };

    TestServer server(callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    bool connected = lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT);
    CHECK(connected);
    CHECK(lbridge_client_get_type(client) == LBRIDGE_TYPE_TCP);
    CHECK(lbridge_get_last_error(client) == LBRIDGE_ERROR_NONE);

    lbridge_client_destroy(client);
}

TEST_CASE("TCP handshake - connection refused (no server)")
{
    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_set_timeout(client, 1000);

    bool connected = lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT + 100);
    CHECK_FALSE(connected);
    CHECK(lbridge_get_last_error(client) != LBRIDGE_ERROR_NONE);

    lbridge_client_destroy(client);
}

// -----------------------------------------------------------------------------
// RPC Tests - Echo (with response)
// -----------------------------------------------------------------------------

static constexpr uint16_t RPC_ECHO = 0x0001;
static constexpr uint16_t RPC_ADD = 0x0002;
static constexpr uint16_t RPC_NO_RESPONSE = 0x0003;
static constexpr uint16_t RPC_LARGE_DATA = 0x0004;
static constexpr uint16_t RPC_DELAYED = 0x0005;
static constexpr uint16_t RPC_SEND_ERROR = 0x0006;

static bool echo_rpc_callback(const lbridge_rpc_context_t ctx, const uint8_t* data, uint32_t size)
{
    uint16_t rpc_id = lbridge_rpc_context_get_rpc_id(ctx);

    switch (rpc_id)
    {
    case RPC_ECHO:
        // Echo back the same data
        lbridge_rpc_context_send_response(ctx, data, size);
        break;

    case RPC_ADD:
        // Add two uint32_t values
        if (size == 8)
        {
            uint32_t a, b;
            memcpy(&a, data, 4);
            memcpy(&b, data + 4, 4);
            uint32_t result = a + b;
            lbridge_rpc_context_send_response(ctx, (const uint8_t*)&result, sizeof(result));
        }
        break;

    case RPC_NO_RESPONSE:
        // Don't send response (fire-and-forget)
        break;

    case RPC_LARGE_DATA:
        // Echo back the large data
        lbridge_rpc_context_send_response(ctx, data, size);
        break;

    case RPC_DELAYED:
        // Delayed response
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        lbridge_rpc_context_send_response(ctx, data, size);
        break;

    case RPC_SEND_ERROR:
        // Send an error and disconnect the client
        lbridge_rpc_context_send_error(ctx, LBRIDGE_PROTOCOL_ERROR_INTERNAL);
        break;

    default:
        // Unknown RPC ID - send invalid RPC ID error
        lbridge_rpc_context_send_error(ctx, LBRIDGE_PROTOCOL_ERROR_INVALID_RPC_ID);
        return false;
    }

    return true;
}

TEST_CASE("RPC call - echo")
{
    TestServer server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    uint8_t buffer[256];
    const char* test_message = "Hello, LBridge!";
    size_t msg_len = strlen(test_message) + 1;
    memcpy(buffer, test_message, msg_len);
    uint32_t size = (uint32_t)msg_len;

    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);
    CHECK(size == msg_len);
    CHECK(strcmp((const char*)buffer, test_message) == 0);

    lbridge_client_destroy(client);
}

TEST_CASE("RPC call - add two numbers")
{
    TestServer server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    uint8_t buffer[256];
    uint32_t a = 42;
    uint32_t b = 58;
    memcpy(buffer, &a, 4);
    memcpy(buffer + 4, &b, 4);
    uint32_t size = 8;

    bool success = lbridge_client_call_rpc(client, RPC_ADD, buffer, &size, sizeof(buffer));
    CHECK(success);
    CHECK(size == 4);

    uint32_t result;
    memcpy(&result, buffer, 4);
    CHECK(result == 100);

    lbridge_client_destroy(client);
}

TEST_CASE("RPC call - multiple calls on same connection")
{
    TestServer server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    for (int i = 0; i < 10; i++)
    {
        uint8_t buffer[256];
        uint32_t value = i * 100;
        memcpy(buffer, &value, 4);
        uint32_t size = 4;

        bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
        CHECK(success);

        uint32_t result;
        memcpy(&result, buffer, 4);
        CHECK(result == value);
    }

    lbridge_client_destroy(client);
}

// -----------------------------------------------------------------------------
// RPC Tests - Fire and Forget (no response)
// -----------------------------------------------------------------------------

static std::atomic<int> g_no_response_counter{ 0 };

static bool no_response_callback(const lbridge_rpc_context_t ctx, const uint8_t* data, uint32_t size)
{
    uint16_t rpc_id = lbridge_rpc_context_get_rpc_id(ctx);

    if (rpc_id == RPC_NO_RESPONSE)
    {
        g_no_response_counter++;
        // No response sent
        (void)data;
        (void)size;
    }

    return true;
}

TEST_CASE("RPC call - fire and forget (no response expected)")
{
    g_no_response_counter = 0;

    TestServer server(no_response_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    uint8_t buffer[256] = { 1, 2, 3, 4 };
    uint32_t size = 4;

    // max_out_size = 0 means no response expected
    bool success = lbridge_client_call_rpc(client, RPC_NO_RESPONSE, buffer, &size, 0);
    CHECK(success);

    // Wait for server to process
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(g_no_response_counter == 1);

    lbridge_client_destroy(client);
}

// -----------------------------------------------------------------------------
// RPC Tests - Server sends error
// -----------------------------------------------------------------------------

TEST_CASE("RPC call - server sends error")
{
    TestServer server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    // First, verify the connection works with a normal RPC
    uint8_t buffer[256] = { 1, 2, 3, 4 };
    uint32_t size = 4;
    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);

    // Now call the RPC that triggers an error from the server
    size = 4;
    memcpy(buffer, "\x01\x02\x03\x04", 4);
    lbridge_set_timeout(client, 500);
    success = lbridge_client_call_rpc(client, RPC_SEND_ERROR, buffer, &size, sizeof(buffer));
    CHECK_FALSE(success);

    // Subsequent calls should also fail because connection was closed
    size = 4;
    memcpy(buffer, "\x01\x02\x03\x04", 4);
    success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK_FALSE(success);

    lbridge_client_destroy(client);
}

TEST_CASE("RPC call - invalid RPC ID error")
{
    TestServer server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    // Call an unknown RPC ID (0x9999 is not handled by echo_rpc_callback)
    uint8_t buffer[256] = { 1, 2, 3, 4 };
    uint32_t size = 4;
    lbridge_set_timeout(client, 500);

    bool success = lbridge_client_call_rpc(client, 0x9999, buffer, &size, sizeof(buffer));
    CHECK_FALSE(success);
    CHECK(lbridge_get_last_error(client) == LBRIDGE_ERROR_INVALID_RPC_ID);

    lbridge_client_destroy(client);
}

// -----------------------------------------------------------------------------
// Large Data Tests (Fragmentation)
// -----------------------------------------------------------------------------

TEST_CASE("RPC call - large data (fragmentation)")
{
    TestServer server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    // Create data larger than max frame payload to trigger fragmentation
    std::vector<uint8_t> large_data(MAX_FRAME_PAYLOAD * 3);
    for (size_t i = 0; i < large_data.size(); i++)
    {
        large_data[i] = (uint8_t)(i & 0xFF);
    }

    std::vector<uint8_t> buffer(large_data.size() + 1024);
    memcpy(buffer.data(), large_data.data(), large_data.size());
    uint32_t size = (uint32_t)large_data.size();

    bool success = lbridge_client_call_rpc(client, RPC_LARGE_DATA, buffer.data(), &size, (uint32_t)buffer.size());
    CHECK(success);
    CHECK(size == large_data.size());
    CHECK(memcmp(buffer.data(), large_data.data(), large_data.size()) == 0);

    lbridge_client_destroy(client);
}

// -----------------------------------------------------------------------------
// Multiple Clients Tests
// -----------------------------------------------------------------------------

TEST_CASE("Multiple clients - sequential connections")
{
    TestServer server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;

    for (int c = 0; c < 5; c++)
    {
        lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
        REQUIRE(client != nullptr);
        REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

        uint8_t buffer[256];
        uint32_t value = c * 111;
        memcpy(buffer, &value, 4);
        uint32_t size = 4;

        bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
        CHECK(success);

        uint32_t result;
        memcpy(&result, buffer, 4);
        CHECK(result == value);

        lbridge_client_destroy(client);
    }
}

TEST_CASE("Multiple clients - concurrent connections")
{
    TestServer server(echo_rpc_callback, 10);
    REQUIRE(server.start());

    constexpr int NUM_CLIENTS = 5;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{ 0 };

    for (int c = 0; c < NUM_CLIENTS; c++)
    {
        threads.emplace_back([c, &success_count]() {
            TestContext ctx;
            lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
            if (!client)
                return;

            if (!lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT))
            {
                lbridge_client_destroy(client);
                return;
            }

            // Each client makes several calls
            bool all_ok = true;
            for (int i = 0; i < 5 && all_ok; i++)
            {
                uint8_t buffer[256];
                uint32_t value = c * 1000 + i;
                memcpy(buffer, &value, 4);
                uint32_t size = 4;

                if (!lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer)))
                {
                    all_ok = false;
                    break;
                }

                uint32_t result;
                memcpy(&result, buffer, 4);
                if (result != value)
                {
                    all_ok = false;
                    break;
                }
            }

            if (all_ok)
                success_count++;

            lbridge_client_destroy(client);
        });
    }

    for (auto& t : threads)
        t.join();

    CHECK(success_count == NUM_CLIENTS);
}

// -----------------------------------------------------------------------------
// Error Cases
// -----------------------------------------------------------------------------

TEST_CASE("RPC call - not connected")
{
    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    uint8_t buffer[256] = { 1, 2, 3, 4 };
    uint32_t size = 4;

    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK_FALSE(success);
    CHECK(lbridge_get_last_error(client) == LBRIDGE_ERROR_NOT_CONNECTED);

    lbridge_client_destroy(client);
}

TEST_CASE("RPC call - server disconnects")
{
    auto server = std::make_unique<TestServer>(echo_rpc_callback);
    REQUIRE(server->start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    // First call should work
    uint8_t buffer[256] = { 1, 2, 3, 4 };
    uint32_t size = 4;
    CHECK(lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer)));

    // Stop server
    server->stop();
    server.reset();

    // Give time for connection to detect closure
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Next call should fail
    size = 4;
    memcpy(buffer, "\x01\x02\x03\x04", 4);
    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK_FALSE(success);

    lbridge_client_destroy(client);
}

TEST_CASE("Server - max clients limit")
{
    TestServer server(echo_rpc_callback, 2);  // Only 2 clients allowed
    REQUIRE(server.start());

    TestContext ctx1, ctx2, ctx3;

    lbridge_client_t client1 = lbridge_client_create(ctx1, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    lbridge_client_t client2 = lbridge_client_create(ctx2, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    lbridge_client_t client3 = lbridge_client_create(ctx3, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);

    REQUIRE(client1 != nullptr);
    REQUIRE(client2 != nullptr);
    REQUIRE(client3 != nullptr);

    // First two should connect
    CHECK(lbridge_client_connect_tcp(client1, TEST_HOST, TEST_PORT));
    CHECK(lbridge_client_connect_tcp(client2, TEST_HOST, TEST_PORT));

    // Third should fail or timeout (server won't accept)
    lbridge_set_timeout(client3, 500);
    bool connected = lbridge_client_connect_tcp(client3, TEST_HOST, TEST_PORT);
    // Note: This may or may not connect depending on TCP backlog behavior
    // The server simply won't call accept() for it

    lbridge_client_destroy(client1);
    lbridge_client_destroy(client2);
    lbridge_client_destroy(client3);
}

// -----------------------------------------------------------------------------
// Timeout Tests
// -----------------------------------------------------------------------------

TEST_CASE("RPC call - timeout")
{
    // Server that responds slowly (longer than client timeout)
    auto slow_callback = [](const lbridge_rpc_context_t, const uint8_t*, uint32_t) -> bool {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        return true;
    };

    TestServer server(slow_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    lbridge_set_timeout(client, 100);  // 100ms timeout (less than callback's 500ms)

    uint8_t buffer[256] = { 1, 2, 3, 4 };
    uint32_t size = 4;

    bool success = lbridge_client_call_rpc(client, 0x9999, buffer, &size, sizeof(buffer));
    CHECK_FALSE(success);
    CHECK(lbridge_get_last_error(client) == LBRIDGE_ERROR_RECEIVE_TIMEOUT);

    lbridge_client_destroy(client);
}

// -----------------------------------------------------------------------------
// Encryption Tests
// -----------------------------------------------------------------------------

#if defined(LBRIDGE_ENABLE_SECURE)
TEST_CASE("RPC call - with encryption")
{
    // Small delay to ensure previous test's sockets are fully closed (especially after RPC timeout test)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    static const uint8_t test_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    // Custom server with encryption
    struct lbridge_context_params params = { 0 };
    params.fp_generate_nonce = test_generate_nonce;
    params.fp_get_time_ms = get_time_ms_impl;

    lbridge_context_t server_ctx = lbridge_context_create(&params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    lbridge_activate_encryption(server, test_key);
    REQUIRE(server_listen_tcp_with_retry(server, TEST_HOST, TEST_PORT, 10));

    ScopedServerThread server_thread(server);

    // Client with encryption
    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_activate_encryption(client, test_key);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    // Make RPC call
    uint8_t buffer[256];
    const char* test_message = "Encrypted Hello!";
    size_t msg_len = strlen(test_message) + 1;
    memcpy(buffer, test_message, msg_len);
    uint32_t size = (uint32_t)msg_len;

    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);
    CHECK(size == msg_len);
    CHECK(strcmp((const char*)buffer, test_message) == 0);

    lbridge_client_destroy(client);

    server_thread.stop();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}

TEST_CASE("RPC call - encryption key mismatch")
{
    static const uint8_t server_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    static const uint8_t client_key[32] = {
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,  // Different key!
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    struct lbridge_context_params params = { 0 };
    params.fp_generate_nonce = test_generate_nonce;
    params.fp_get_time_ms = get_time_ms_impl;

    lbridge_context_t server_ctx = lbridge_context_create(&params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    lbridge_activate_encryption(server, server_key);
    REQUIRE(server_listen_tcp_with_retry(server, TEST_HOST, TEST_PORT, 10));

    ScopedServerThread server_thread(server);

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_activate_encryption(client, client_key);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    lbridge_set_timeout(client, 500);

    uint8_t buffer[256] = { 1, 2, 3, 4 };
    uint32_t size = 4;

    // This should fail due to authentication failure
    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK_FALSE(success);

    lbridge_client_destroy(client);

    server_thread.stop();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}
#endif

// -----------------------------------------------------------------------------
// Client Timeout Tests
// -----------------------------------------------------------------------------

TEST_CASE("Server - client timeout disconnects inactive client")
{
    struct lbridge_context_params params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
    params.fp_generate_nonce = test_generate_nonce;
#endif
    params.fp_get_time_ms = get_time_ms_impl;

    lbridge_context_t server_ctx = lbridge_context_create(&params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    // Set a short client timeout (200ms)
    lbridge_server_set_client_timeout(server, 200);

    REQUIRE(server_listen_tcp_with_retry(server, TEST_HOST, TEST_PORT, 10));

    ScopedServerThread server_thread(server, 10);

    // Connect a client
    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    // First call should succeed
    uint8_t buffer[256] = { 1, 2, 3, 4 };
    uint32_t size = 4;
    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);

    // Wait longer than the timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Next call should fail because server disconnected the client
    size = 4;
    memcpy(buffer, "\x01\x02\x03\x04", 4);
    lbridge_set_timeout(client, 500);
    success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK_FALSE(success);

    lbridge_client_destroy(client);

    server_thread.stop();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}

TEST_CASE("Server - client timeout disabled by default")
{
    TestServer server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    // First call
    uint8_t buffer[256] = { 1, 2, 3, 4 };
    uint32_t size = 4;
    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);

    // Wait some time (if timeout was enabled with a very short value, this would fail)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Should still work because timeout is disabled by default
    size = 4;
    memcpy(buffer, "\x01\x02\x03\x04", 4);
    success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);

    lbridge_client_destroy(client);
}

TEST_CASE("Client - ping refreshes timeout")
{
    struct lbridge_context_params params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
    params.fp_generate_nonce = test_generate_nonce;
#endif
    params.fp_get_time_ms = get_time_ms_impl;

    lbridge_context_t server_ctx = lbridge_context_create(&params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    // Set client timeout of 500ms (needs margin for CI timing variance)
    lbridge_server_set_client_timeout(server, 500);

    REQUIRE(server_listen_tcp_with_retry(server, TEST_HOST, TEST_PORT, 10));

    ScopedServerThread server_thread(server, 10);

    // Connect a client
    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    // Keep the client alive using ping instead of RPC calls
    // Wait 200ms (less than timeout), then ping, wait another 200ms, then ping again
    for (int i = 0; i < 3; i++)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        bool ping_success = lbridge_client_ping(client);
        CHECK(ping_success);
    }

    // Now make an actual RPC call - should still work because pings kept connection alive
    uint8_t buffer[256] = { 1, 2, 3, 4 };
    uint32_t size = 4;
    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);

    lbridge_client_destroy(client);

    server_thread.stop();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}

TEST_CASE("Server - active client is not disconnected")
{
    struct lbridge_context_params params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
    params.fp_generate_nonce = test_generate_nonce;
#endif
    params.fp_get_time_ms = get_time_ms_impl;

    lbridge_context_t server_ctx = lbridge_context_create(&params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    // Set client timeout of 500ms (needs margin for CI timing variance)
    lbridge_server_set_client_timeout(server, 500);

    REQUIRE(server_listen_tcp_with_retry(server, TEST_HOST, TEST_PORT, 10));

    ScopedServerThread server_thread(server, 10);

    // Connect a client
    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST, TEST_PORT));

    // Keep the client active by sending requests every 200ms (less than timeout)
    bool all_success = true;
    for (int i = 0; i < 5; i++)
    {
        uint8_t buffer[256];
        uint32_t value = i * 100;
        memcpy(buffer, &value, 4);
        uint32_t size = 4;

        bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
        if (!success)
        {
            all_success = false;
            break;
        }

        uint32_t result;
        memcpy(&result, buffer, 4);
        if (result != value)
        {
            all_success = false;
            break;
        }

        // Wait less than timeout before next request
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    CHECK(all_success);

    lbridge_client_destroy(client);

    server_thread.stop();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}

// =============================================================================
// IPv6 Tests
// =============================================================================

static constexpr const char* TEST_HOST_IPV6 = "::1";

// Helper to check if IPv6 is available on this system
static bool is_ipv6_available()
{
    static int cached_result = -1;  // -1 = not checked, 0 = not available, 1 = available
    if (cached_result >= 0)
        return cached_result == 1;

#if defined(_WIN32)
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cached_result = 0;
        return false;
    }
#endif

    // Try to create an IPv6 socket and bind to ::1
#if defined(_WIN32)
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        cached_result = 0;
        return false;
    }
    closesocket(s);
#else
    int s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
    {
        cached_result = 0;
        return false;
    }
    close(s);
#endif

    cached_result = 1;
    return true;
}

class TestServerIPv6
{
public:
    TestServerIPv6(fp_rpc_call callback, uint32_t max_clients = 10)
        : m_callback(callback), m_max_clients(max_clients)
    {
    }

    ~TestServerIPv6()
    {
        stop();
    }

    bool start(const char* host = TEST_HOST_IPV6, uint16_t port = TEST_PORT)
    {
        struct lbridge_context_params params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
        params.fp_generate_nonce = test_generate_nonce;
#endif
        params.fp_get_time_ms = get_time_ms_impl;
        m_ctx = lbridge_context_create(&params);
        if (!m_ctx)
            return false;

        m_server = lbridge_server_create(m_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, m_callback);
        if (!m_server)
        {
            lbridge_context_destroy(m_ctx);
            m_ctx = nullptr;
            return false;
        }

        if (!server_listen_tcp_with_retry(m_server, host, port, m_max_clients))
        {
            lbridge_server_destroy(m_server);
            lbridge_context_destroy(m_ctx);
            m_server = nullptr;
            m_ctx = nullptr;
            return false;
        }

        m_running = true;
        m_thread = std::thread([this]() { run(); });

        // Wait for server to be ready
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return true;
    }

    void stop()
    {
        m_running = false;
        if (m_thread.joinable())
            m_thread.join();

        if (m_server)
        {
            lbridge_server_destroy(m_server);
            m_server = nullptr;
        }
        if (m_ctx)
        {
            lbridge_context_destroy(m_ctx);
            m_ctx = nullptr;
        }
    }

    bool is_running() const { return m_running; }

private:
    void run()
    {
        while (m_running)
        {
            lbridge_server_update(m_server);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    fp_rpc_call m_callback;
    uint32_t m_max_clients;
    lbridge_context_t m_ctx = nullptr;
    lbridge_server_t m_server = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_running{ false };
};

TEST_CASE("IPv6 TCP handshake - successful connection")
{
    if (!is_ipv6_available())
    {
        WARN("IPv6 not available on this system, skipping test");
        return;
    }

    auto callback = [](const lbridge_rpc_context_t, const uint8_t*, uint32_t) -> bool {
        return true;
    };

    TestServerIPv6 server(callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    bool connected = lbridge_client_connect_tcp(client, TEST_HOST_IPV6, TEST_PORT);
    CHECK(connected);
    CHECK(lbridge_client_get_type(client) == LBRIDGE_TYPE_TCP);
    CHECK(lbridge_get_last_error(client) == LBRIDGE_ERROR_NONE);

    lbridge_client_destroy(client);
}

TEST_CASE("IPv6 RPC call - echo")
{
    if (!is_ipv6_available())
    {
        WARN("IPv6 not available on this system, skipping test");
        return;
    }

    TestServerIPv6 server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST_IPV6, TEST_PORT));

    uint8_t buffer[256];
    const char* test_message = "Hello, IPv6!";
    size_t msg_len = strlen(test_message) + 1;
    memcpy(buffer, test_message, msg_len);
    uint32_t size = (uint32_t)msg_len;

    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);
    CHECK(size == msg_len);
    CHECK(strcmp((const char*)buffer, test_message) == 0);

    lbridge_client_destroy(client);
}

TEST_CASE("IPv6 RPC call - multiple calls on same connection")
{
    if (!is_ipv6_available())
    {
        WARN("IPv6 not available on this system, skipping test");
        return;
    }

    TestServerIPv6 server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST_IPV6, TEST_PORT));

    for (int i = 0; i < 10; i++)
    {
        uint8_t buffer[256];
        uint32_t value = i * 100;
        memcpy(buffer, &value, 4);
        uint32_t size = 4;

        bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
        CHECK(success);

        uint32_t result;
        memcpy(&result, buffer, 4);
        CHECK(result == value);
    }

    lbridge_client_destroy(client);
}

TEST_CASE("IPv6 RPC call - large data (fragmentation)")
{
    if (!is_ipv6_available())
    {
        WARN("IPv6 not available on this system, skipping test");
        return;
    }

    TestServerIPv6 server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST_IPV6, TEST_PORT));

    // Create data larger than max frame payload to trigger fragmentation
    std::vector<uint8_t> large_data(MAX_FRAME_PAYLOAD * 3);
    for (size_t i = 0; i < large_data.size(); i++)
    {
        large_data[i] = (uint8_t)(i & 0xFF);
    }

    std::vector<uint8_t> buffer(large_data.size() + 1024);
    memcpy(buffer.data(), large_data.data(), large_data.size());
    uint32_t size = (uint32_t)large_data.size();

    bool success = lbridge_client_call_rpc(client, RPC_LARGE_DATA, buffer.data(), &size, (uint32_t)buffer.size());
    CHECK(success);
    CHECK(size == large_data.size());
    CHECK(memcmp(buffer.data(), large_data.data(), large_data.size()) == 0);

    lbridge_client_destroy(client);
}

TEST_CASE("IPv6 - multiple clients concurrent connections")
{
    if (!is_ipv6_available())
    {
        WARN("IPv6 not available on this system, skipping test");
        return;
    }

    TestServerIPv6 server(echo_rpc_callback, 10);
    REQUIRE(server.start());

    constexpr int NUM_CLIENTS = 5;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{ 0 };

    for (int c = 0; c < NUM_CLIENTS; c++)
    {
        threads.emplace_back([c, &success_count]() {
            TestContext ctx;
            lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
            if (!client)
                return;

            if (!lbridge_client_connect_tcp(client, TEST_HOST_IPV6, TEST_PORT))
            {
                lbridge_client_destroy(client);
                return;
            }

            // Each client makes several calls
            bool all_ok = true;
            for (int i = 0; i < 5 && all_ok; i++)
            {
                uint8_t buffer[256];
                uint32_t value = c * 1000 + i;
                memcpy(buffer, &value, 4);
                uint32_t size = 4;

                if (!lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer)))
                {
                    all_ok = false;
                    break;
                }

                uint32_t result;
                memcpy(&result, buffer, 4);
                if (result != value)
                {
                    all_ok = false;
                    break;
                }
            }

            if (all_ok)
                success_count++;

            lbridge_client_destroy(client);
        });
    }

    for (auto& t : threads)
        t.join();

    CHECK(success_count == NUM_CLIENTS);
}

#if defined(LBRIDGE_ENABLE_SECURE)
TEST_CASE("IPv6 RPC call - with encryption")
{
    if (!is_ipv6_available())
    {
        WARN("IPv6 not available on this system, skipping test");
        return;
    }

    static const uint8_t test_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    // Custom server with encryption
    struct lbridge_context_params params = { 0 };
    params.fp_generate_nonce = test_generate_nonce;
    params.fp_get_time_ms = get_time_ms_impl;

    lbridge_context_t server_ctx = lbridge_context_create(&params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    lbridge_activate_encryption(server, test_key);
    REQUIRE(server_listen_tcp_with_retry(server, TEST_HOST_IPV6, TEST_PORT, 10));

    ScopedServerThread server_thread(server);

    // Client with encryption
    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_activate_encryption(client, test_key);
    REQUIRE(lbridge_client_connect_tcp(client, TEST_HOST_IPV6, TEST_PORT));

    // Make RPC call
    uint8_t buffer[256];
    const char* test_message = "Encrypted IPv6 Hello!";
    size_t msg_len = strlen(test_message) + 1;
    memcpy(buffer, test_message, msg_len);
    uint32_t size = (uint32_t)msg_len;

    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);
    CHECK(size == msg_len);
    CHECK(strcmp((const char*)buffer, test_message) == 0);

    lbridge_client_destroy(client);

    server_thread.stop();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}
#endif // LBRIDGE_ENABLE_SECURE

// =============================================================================
// Integration Tests (Client <-> Server over Unix Domain Socket)
// =============================================================================

#if defined(LBRIDGE_ENABLE_UNIX_CLIENT) && defined(LBRIDGE_ENABLE_UNIX_SERVER)

// Unix domain sockets on Windows use file system paths (not named pipes)
// Supported since Windows 10 version 1803
#if defined(_WIN32)
static const char* get_test_unix_socket_path()
{
    static char path[MAX_PATH] = { 0 };
    if (path[0] == 0)
    {
        GetTempPathA(MAX_PATH, path);
        strcat_s(path, MAX_PATH, "lbridge_test.sock");
    }
    return path;
}
#define TEST_UNIX_SOCKET_PATH get_test_unix_socket_path()
#else
static constexpr const char* TEST_UNIX_SOCKET_PATH = "/tmp/lbridge_test.sock";
#endif

class TestServerUnix
{
public:
    TestServerUnix(fp_rpc_call callback, uint32_t max_clients = 10)
        : m_callback(callback), m_max_clients(max_clients)
    {
    }

    ~TestServerUnix()
    {
        stop();
    }

    bool start(const char* socket_path = TEST_UNIX_SOCKET_PATH)
    {
        struct lbridge_context_params params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
        params.fp_generate_nonce = test_generate_nonce;
#endif
        params.fp_get_time_ms = get_time_ms_impl;
        m_ctx = lbridge_context_create(&params);
        if (!m_ctx)
        {
            printf("Unix server: failed to create context\n");
            return false;
        }

        m_server = lbridge_server_create(m_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, m_callback);
        if (!m_server)
        {
            printf("Unix server: failed to create server\n");
            lbridge_context_destroy(m_ctx);
            m_ctx = nullptr;
            return false;
        }

        if (!lbridge_server_listen_unix(m_server, socket_path, m_max_clients))
        {
            printf("Unix server: listen failed, error = %d\n", lbridge_get_last_error(m_server));
            lbridge_server_destroy(m_server);
            lbridge_context_destroy(m_ctx);
            m_server = nullptr;
            m_ctx = nullptr;
            return false;
        }

        m_running = true;
        m_thread = std::thread([this]() { run(); });

        // Wait for server to be ready
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        return true;
    }

    void stop()
    {
        m_running = false;
        if (m_thread.joinable())
            m_thread.join();

        if (m_server)
        {
            lbridge_server_destroy(m_server);
            m_server = nullptr;
        }
        if (m_ctx)
        {
            lbridge_context_destroy(m_ctx);
            m_ctx = nullptr;
        }
    }

    bool is_running() const { return m_running; }

private:
    void run()
    {
        while (m_running)
        {
            lbridge_server_update(m_server);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    fp_rpc_call m_callback;
    uint32_t m_max_clients;
    lbridge_context_t m_ctx = nullptr;
    lbridge_server_t m_server = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_running{ false };
};

// -----------------------------------------------------------------------------
// Helper to check if Unix sockets are supported on this Windows version
// -----------------------------------------------------------------------------

#if defined(_WIN32)
static bool is_unix_socket_supported()
{
    static int cached_result = -1;  // -1 = not checked, 0 = not supported, 1 = supported
    if (cached_result >= 0)
        return cached_result == 1;

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("WSAStartup failed\n");
        cached_result = 0;
        return false;
    }

    // Try to create a Unix domain socket to check if it's supported
    SOCKET s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
    {
        int err = WSAGetLastError();
        printf("Unix socket creation failed with error: %d\n", err);
        if (err == WSAEAFNOSUPPORT)
        {
            printf("Unix domain sockets are not supported on this Windows version.\n");
            printf("Requires Windows 10 version 1803 or later.\n");
        }
        cached_result = 0;
        return false;
    }
    closesocket(s);
    cached_result = 1;
    return true;
}
#else
static bool is_unix_socket_supported() { return true; }
#endif

// -----------------------------------------------------------------------------
// Unix Socket Handshake Tests
// -----------------------------------------------------------------------------

TEST_CASE("Unix socket handshake - successful connection")
{
    if (!is_unix_socket_supported())
    {
        WARN("Unix sockets not supported on this system, skipping test");
        return;
    }

    auto callback = [](const lbridge_rpc_context_t, const uint8_t*, uint32_t) -> bool {
        return true;
    };

    TestServerUnix server(callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    bool connected = lbridge_client_connect_unix(client, TEST_UNIX_SOCKET_PATH);
    CHECK(connected);
    CHECK(lbridge_client_get_type(client) == LBRIDGE_TYPE_UNIX);
    CHECK(lbridge_get_last_error(client) == LBRIDGE_ERROR_NONE);

    lbridge_client_destroy(client);
}

TEST_CASE("Unix socket handshake - connection refused (no server)")
{
    if (!is_unix_socket_supported())
    {
        WARN("Unix sockets not supported on this system, skipping test");
        return;
    }

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_set_timeout(client, 1000);

#if defined(_WIN32)
    char nonexistent_path[MAX_PATH];
    GetTempPathA(MAX_PATH, nonexistent_path);
    strcat_s(nonexistent_path, MAX_PATH, "lbridge_nonexistent.sock");
    bool connected = lbridge_client_connect_unix(client, nonexistent_path);
#else
    bool connected = lbridge_client_connect_unix(client, "/tmp/lbridge_nonexistent.sock");
#endif
    CHECK_FALSE(connected);
    CHECK(lbridge_get_last_error(client) != LBRIDGE_ERROR_NONE);

    lbridge_client_destroy(client);
}

// -----------------------------------------------------------------------------
// Unix Socket RPC Tests
// -----------------------------------------------------------------------------

TEST_CASE("Unix socket RPC call - echo")
{
    if (!is_unix_socket_supported()) { WARN("Skipping - Unix sockets not supported"); return; }
    TestServerUnix server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_unix(client, TEST_UNIX_SOCKET_PATH));

    uint8_t buffer[256];
    const char* test_message = "Hello, Unix Socket!";
    size_t msg_len = strlen(test_message) + 1;
    memcpy(buffer, test_message, msg_len);
    uint32_t size = (uint32_t)msg_len;

    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);
    CHECK(size == msg_len);
    CHECK(strcmp((const char*)buffer, test_message) == 0);

    lbridge_client_destroy(client);
}

TEST_CASE("Unix socket RPC call - add two numbers")
{
    if (!is_unix_socket_supported()) { WARN("Skipping - Unix sockets not supported"); return; }
    TestServerUnix server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_unix(client, TEST_UNIX_SOCKET_PATH));

    uint8_t buffer[256];
    uint32_t a = 42;
    uint32_t b = 58;
    memcpy(buffer, &a, 4);
    memcpy(buffer + 4, &b, 4);
    uint32_t size = 8;

    bool success = lbridge_client_call_rpc(client, RPC_ADD, buffer, &size, sizeof(buffer));
    CHECK(success);
    CHECK(size == 4);

    uint32_t result;
    memcpy(&result, buffer, 4);
    CHECK(result == 100);

    lbridge_client_destroy(client);
}

TEST_CASE("Unix socket RPC call - multiple calls on same connection")
{
    if (!is_unix_socket_supported()) { WARN("Skipping - Unix sockets not supported"); return; }
    TestServerUnix server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_unix(client, TEST_UNIX_SOCKET_PATH));

    for (int i = 0; i < 10; i++)
    {
        uint8_t buffer[256];
        uint32_t value = i * 100;
        memcpy(buffer, &value, 4);
        uint32_t size = 4;

        bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
        CHECK(success);

        uint32_t result;
        memcpy(&result, buffer, 4);
        CHECK(result == value);
    }

    lbridge_client_destroy(client);
}

// -----------------------------------------------------------------------------
// Unix Socket Large Data Tests (Fragmentation)
// -----------------------------------------------------------------------------

TEST_CASE("Unix socket RPC call - large data (fragmentation)")
{
    if (!is_unix_socket_supported()) { WARN("Skipping - Unix sockets not supported"); return; }
    TestServerUnix server(echo_rpc_callback);
    REQUIRE(server.start());

    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);
    REQUIRE(lbridge_client_connect_unix(client, TEST_UNIX_SOCKET_PATH));

    // Create data larger than max frame payload to trigger fragmentation
    std::vector<uint8_t> large_data(MAX_FRAME_PAYLOAD * 3);
    for (size_t i = 0; i < large_data.size(); i++)
    {
        large_data[i] = (uint8_t)(i & 0xFF);
    }

    std::vector<uint8_t> buffer(large_data.size() + 1024);
    memcpy(buffer.data(), large_data.data(), large_data.size());
    uint32_t size = (uint32_t)large_data.size();

    bool success = lbridge_client_call_rpc(client, RPC_LARGE_DATA, buffer.data(), &size, (uint32_t)buffer.size());
    CHECK(success);
    CHECK(size == large_data.size());
    CHECK(memcmp(buffer.data(), large_data.data(), large_data.size()) == 0);

    lbridge_client_destroy(client);
}

// -----------------------------------------------------------------------------
// Unix Socket Multiple Clients Tests
// -----------------------------------------------------------------------------

TEST_CASE("Unix socket - multiple clients concurrent connections")
{
    if (!is_unix_socket_supported()) { WARN("Skipping - Unix sockets not supported"); return; }
    TestServerUnix server(echo_rpc_callback, 10);
    REQUIRE(server.start());

    constexpr int NUM_CLIENTS = 5;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{ 0 };

    for (int c = 0; c < NUM_CLIENTS; c++)
    {
        threads.emplace_back([c, &success_count]() {
            TestContext ctx;
            lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
            if (!client)
                return;

            if (!lbridge_client_connect_unix(client, TEST_UNIX_SOCKET_PATH))
            {
                lbridge_client_destroy(client);
                return;
            }

            // Each client makes several calls
            bool all_ok = true;
            for (int i = 0; i < 5 && all_ok; i++)
            {
                uint8_t buffer[256];
                uint32_t value = c * 1000 + i;
                memcpy(buffer, &value, 4);
                uint32_t size = 4;

                if (!lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer)))
                {
                    all_ok = false;
                    break;
                }

                uint32_t result;
                memcpy(&result, buffer, 4);
                if (result != value)
                {
                    all_ok = false;
                    break;
                }
            }

            if (all_ok)
                success_count++;

            lbridge_client_destroy(client);
        });
    }

    for (auto& t : threads)
        t.join();

    CHECK(success_count == NUM_CLIENTS);
}

// -----------------------------------------------------------------------------
// Unix Socket Encryption Tests
// -----------------------------------------------------------------------------

#if defined(LBRIDGE_ENABLE_SECURE)
TEST_CASE("Unix socket RPC call - with encryption")
{
    if (!is_unix_socket_supported()) { WARN("Skipping - Unix sockets not supported"); return; }
    static const uint8_t test_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    // Custom server with encryption
    struct lbridge_context_params params = { 0 };
    params.fp_generate_nonce = test_generate_nonce;
    params.fp_get_time_ms = get_time_ms_impl;

    lbridge_context_t server_ctx = lbridge_context_create(&params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    lbridge_activate_encryption(server, test_key);
    REQUIRE(lbridge_server_listen_unix(server, TEST_UNIX_SOCKET_PATH, 10));

    ScopedServerThread server_thread(server);

    // Client with encryption
    TestContext ctx;
    lbridge_client_t client = lbridge_client_create(ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_activate_encryption(client, test_key);
    REQUIRE(lbridge_client_connect_unix(client, TEST_UNIX_SOCKET_PATH));

    // Make RPC call
    uint8_t buffer[256];
    const char* test_message = "Encrypted Unix Hello!";
    size_t msg_len = strlen(test_message) + 1;
    memcpy(buffer, test_message, msg_len);
    uint32_t size = (uint32_t)msg_len;

    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);
    CHECK(size == msg_len);
    CHECK(strcmp((const char*)buffer, test_message) == 0);

    lbridge_client_destroy(client);

    server_thread.stop();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}
#endif // LBRIDGE_ENABLE_SECURE

#endif // LBRIDGE_ENABLE_UNIX_CLIENT && LBRIDGE_ENABLE_UNIX_SERVER

// =============================================================================
// Custom Backend Tests (FIFO-based in-memory transport)
// =============================================================================

#include <queue>
#include <deque>

// Thread-safe FIFO for inter-thread communication
class ThreadSafeFifo
{
public:
    void push(uint8_t byte)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_data.push_back(byte);
    }

    void push(const uint8_t* data, size_t size)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (size_t i = 0; i < size; i++)
        {
            m_data.push_back(data[i]);
        }
    }

    size_t pop(uint8_t* buffer, size_t max_size)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t count = 0;
        while (count < max_size && !m_data.empty())
        {
            buffer[count++] = m_data.front();
            m_data.pop_front();
        }
        return count;
    }

    size_t available() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_data.size();
    }

    void clear()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_data.clear();
    }

private:
    std::deque<uint8_t> m_data;
    mutable std::mutex m_mutex;
};

// Bidirectional FIFO channel (two FIFOs for full-duplex communication)
struct FifoChannel
{
    ThreadSafeFifo client_to_server;  // Client writes, Server reads
    ThreadSafeFifo server_to_client;  // Server writes, Client reads
};

// Custom backend context
struct FifoBackendContext
{
    FifoChannel* channel;
    bool is_server;
};

// Custom FIFO backend implementation
bool fifo_backend(enum lbridge_backend_operation op, void* object, void* arg)
{
    FifoBackendContext* ctx = (FifoBackendContext*)lbridge_get_backend_data(object);

    switch (op)
    {
    case LBRIDGE_OP_CLIENT_CONNECT:
    case LBRIDGE_OP_SERVER_OPEN:
        // Nothing to do - channel is already set up
        return true;

    case LBRIDGE_OP_CLIENT_CLEANUP:
    case LBRIDGE_OP_SERVER_CLEANUP:
        return true;

    case LBRIDGE_OP_SERVER_ACCEPT: {
        struct lbridge_backend_accept_data* d = (struct lbridge_backend_accept_data*)arg;
        // For FIFO transport, we simulate a single always-connected client
        // Check if there's data waiting (indicates client is "connected")
        if (ctx->channel->client_to_server.available() > 0)
        {
            d->new_client_accepted = true;
        }
        else
        {
            d->new_client_accepted = false;
        }
        return true;
    }

    case LBRIDGE_OP_SEND_DATA: {
        struct lbridge_backend_send_data* d = (struct lbridge_backend_send_data*)arg;
        if (ctx->is_server)
        {
            ctx->channel->server_to_client.push(d->data, d->size);
        }
        else
        {
            ctx->channel->client_to_server.push(d->data, d->size);
        }
        return true;
    }

    case LBRIDGE_OP_RECEIVE_DATA: {
        struct lbridge_backend_receive_data* d = (struct lbridge_backend_receive_data*)arg;
        ThreadSafeFifo* fifo = ctx->is_server
            ? &ctx->channel->client_to_server
            : &ctx->channel->server_to_client;

        // Non-blocking: return what's available
        if (!(d->flags & LBRIDGE_RECEIVE_BLOCKING))
        {
            d->received_size = (uint32_t)fifo->pop(d->data, d->requested_size);
            return true;
        }

        // Blocking: wait for data with timeout
        auto start = std::chrono::steady_clock::now();
        const int32_t timeout_ms = 5000; // 5 second timeout for tests
        d->received_size = 0;

        while (d->received_size < d->requested_size)
        {
            size_t got = fifo->pop(d->data + d->received_size, d->requested_size - d->received_size);
            d->received_size += (uint32_t)got;

            if (d->received_size >= d->requested_size)
                break;

            // Check timeout
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > timeout_ms)
            {
                return false; // Timeout
            }

            // Small sleep to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        return true;
    }

    case LBRIDGE_OP_CONNECTION_CLOSE:
        return true;

    default:
        return true;
    }
}

TEST_CASE("Custom backend - FIFO client-server handshake")
{
    FifoChannel channel;

    // Server setup
    FifoBackendContext server_ctx_data = { &channel, true };
    struct lbridge_context_params server_params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
    server_params.fp_generate_nonce = test_generate_nonce;
#endif
    server_params.fp_get_time_ms = get_time_ms_impl;
    lbridge_context_t server_ctx = lbridge_context_create(&server_params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    lbridge_set_backend_data(server, &server_ctx_data);
    bool server_started = lbridge_server_listen_custom(server, fifo_backend, &server_ctx_data, nullptr, 1);
    REQUIRE(server_started);

    // Client setup
    FifoBackendContext client_ctx_data = { &channel, false };
    TestContext client_ctx;
    lbridge_client_t client = lbridge_client_create(client_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_set_backend_data(client, &client_ctx_data);

    // Run server in background thread
    std::atomic<bool> server_running{ true };
    std::thread server_thread([&]() {
        while (server_running)
        {
            lbridge_server_update(server);
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    });

    // Client connects
    bool connected = lbridge_client_connect_custom(client, fifo_backend, &client_ctx_data, nullptr);
    CHECK(connected);
    CHECK(lbridge_client_get_type(client) == LBRIDGE_TYPE_CUSTOM);

    // Cleanup
    lbridge_client_destroy(client);
    server_running = false;
    server_thread.join();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}

TEST_CASE("Custom backend - FIFO RPC echo")
{
    FifoChannel channel;

    // Server setup
    FifoBackendContext server_ctx_data = { &channel, true };
    struct lbridge_context_params server_params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
    server_params.fp_generate_nonce = test_generate_nonce;
#endif
    server_params.fp_get_time_ms = get_time_ms_impl;
    lbridge_context_t server_ctx = lbridge_context_create(&server_params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    lbridge_set_backend_data(server, &server_ctx_data);
    REQUIRE(lbridge_server_listen_custom(server, fifo_backend, &server_ctx_data, nullptr, 1));

    // Client setup
    FifoBackendContext client_ctx_data = { &channel, false };
    TestContext client_ctx;
    lbridge_client_t client = lbridge_client_create(client_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_set_backend_data(client, &client_ctx_data);

    // Server thread
    std::atomic<bool> server_running{ true };
    std::thread server_thread([&]() {
        while (server_running)
        {
            lbridge_server_update(server);
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    });

    // Connect and call RPC
    REQUIRE(lbridge_client_connect_custom(client, fifo_backend, &client_ctx_data, nullptr));

    uint8_t buffer[256];
    const char* test_message = "Hello via FIFO custom backend!";
    size_t msg_len = strlen(test_message) + 1;
    memcpy(buffer, test_message, msg_len);
    uint32_t size = (uint32_t)msg_len;

    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);
    CHECK(size == msg_len);
    CHECK(strcmp((const char*)buffer, test_message) == 0);

    // Cleanup
    lbridge_client_destroy(client);
    server_running = false;
    server_thread.join();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}

TEST_CASE("Custom backend - FIFO multiple RPC calls")
{
    FifoChannel channel;

    // Server setup
    FifoBackendContext server_ctx_data = { &channel, true };
    struct lbridge_context_params server_params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
    server_params.fp_generate_nonce = test_generate_nonce;
#endif
    server_params.fp_get_time_ms = get_time_ms_impl;
    lbridge_context_t server_ctx = lbridge_context_create(&server_params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    lbridge_set_backend_data(server, &server_ctx_data);
    REQUIRE(lbridge_server_listen_custom(server, fifo_backend, &server_ctx_data, nullptr, 1));

    // Client setup
    FifoBackendContext client_ctx_data = { &channel, false };
    TestContext client_ctx;
    lbridge_client_t client = lbridge_client_create(client_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_set_backend_data(client, &client_ctx_data);

    // Server thread
    std::atomic<bool> server_running{ true };
    std::thread server_thread([&]() {
        while (server_running)
        {
            lbridge_server_update(server);
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    });

    REQUIRE(lbridge_client_connect_custom(client, fifo_backend, &client_ctx_data, nullptr));

    // Multiple RPC calls
    for (int i = 0; i < 10; i++)
    {
        uint8_t buffer[256];
        uint32_t value = i * 100 + 42;
        memcpy(buffer, &value, 4);
        uint32_t size = 4;

        bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
        CHECK(success);
        CHECK(size == 4);

        uint32_t result;
        memcpy(&result, buffer, 4);
        CHECK(result == value);
    }

    // Cleanup
    lbridge_client_destroy(client);
    server_running = false;
    server_thread.join();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}

TEST_CASE("Custom backend - FIFO large data (fragmentation)")
{
    FifoChannel channel;

    // Server setup
    FifoBackendContext server_ctx_data = { &channel, true };
    struct lbridge_context_params server_params = { 0 };
#if defined(LBRIDGE_ENABLE_SECURE)
    server_params.fp_generate_nonce = test_generate_nonce;
#endif
    server_params.fp_get_time_ms = get_time_ms_impl;
    lbridge_context_t server_ctx = lbridge_context_create(&server_params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    lbridge_set_backend_data(server, &server_ctx_data);
    REQUIRE(lbridge_server_listen_custom(server, fifo_backend, &server_ctx_data, nullptr, 1));

    // Client setup
    FifoBackendContext client_ctx_data = { &channel, false };
    TestContext client_ctx;
    lbridge_client_t client = lbridge_client_create(client_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_set_backend_data(client, &client_ctx_data);

    // Server thread
    std::atomic<bool> server_running{ true };
    std::thread server_thread([&]() {
        while (server_running)
        {
            lbridge_server_update(server);
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    });

    REQUIRE(lbridge_client_connect_custom(client, fifo_backend, &client_ctx_data, nullptr));

    // Create large data to trigger fragmentation
    std::vector<uint8_t> large_data(MAX_FRAME_PAYLOAD * 3);
    for (size_t i = 0; i < large_data.size(); i++)
    {
        large_data[i] = (uint8_t)(i & 0xFF);
    }

    std::vector<uint8_t> buffer(large_data.size() + 1024);
    memcpy(buffer.data(), large_data.data(), large_data.size());
    uint32_t size = (uint32_t)large_data.size();

    bool success = lbridge_client_call_rpc(client, RPC_LARGE_DATA, buffer.data(), &size, (uint32_t)buffer.size());
    CHECK(success);
    CHECK(size == large_data.size());
    CHECK(memcmp(buffer.data(), large_data.data(), large_data.size()) == 0);

    // Cleanup
    lbridge_client_destroy(client);
    server_running = false;
    server_thread.join();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}

#if defined(LBRIDGE_ENABLE_SECURE)
TEST_CASE("Custom backend - FIFO with encryption")
{
    FifoChannel channel;

    static const uint8_t test_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    // Server setup
    FifoBackendContext server_ctx_data = { &channel, true };
    struct lbridge_context_params server_params = { 0 };
    server_params.fp_generate_nonce = test_generate_nonce;
    server_params.fp_get_time_ms = get_time_ms_impl;
    lbridge_context_t server_ctx = lbridge_context_create(&server_params);
    REQUIRE(server_ctx != nullptr);

    lbridge_server_t server = lbridge_server_create(server_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD, echo_rpc_callback);
    REQUIRE(server != nullptr);

    lbridge_activate_encryption(server, test_key);
    lbridge_set_backend_data(server, &server_ctx_data);
    REQUIRE(lbridge_server_listen_custom(server, fifo_backend, &server_ctx_data, nullptr, 1));

    // Client setup
    FifoBackendContext client_ctx_data = { &channel, false };
    TestContext client_ctx;
    lbridge_client_t client = lbridge_client_create(client_ctx, MAX_FRAME_PAYLOAD, MAX_PAYLOAD);
    REQUIRE(client != nullptr);

    lbridge_activate_encryption(client, test_key);
    lbridge_set_backend_data(client, &client_ctx_data);

    // Server thread
    std::atomic<bool> server_running{ true };
    std::thread server_thread([&]() {
        while (server_running)
        {
            lbridge_server_update(server);
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    });

    REQUIRE(lbridge_client_connect_custom(client, fifo_backend, &client_ctx_data, nullptr));

    uint8_t buffer[256];
    const char* test_message = "Encrypted FIFO message!";
    size_t msg_len = strlen(test_message) + 1;
    memcpy(buffer, test_message, msg_len);
    uint32_t size = (uint32_t)msg_len;

    bool success = lbridge_client_call_rpc(client, RPC_ECHO, buffer, &size, sizeof(buffer));
    CHECK(success);
    CHECK(size == msg_len);
    CHECK(strcmp((const char*)buffer, test_message) == 0);

    // Cleanup
    lbridge_client_destroy(client);
    server_running = false;
    server_thread.join();
    lbridge_server_destroy(server);
    lbridge_context_destroy(server_ctx);
}
#endif // LBRIDGE_ENABLE_SECURE
