// Required for MinGW and older MSVC (snprintf/vsnprintf compatibility)
#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER <= 1900)
#define MBEDTLS_PLATFORM_C
#endif

#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C