#include <stdbool.h>
#include <stdint.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BITSTREAM_BUF_SIZE ((32) * (AES_BLOCK_SIZE))
#define SALT_LEN (32)
//#define SCOST_MIN (1)
//#define SCOST_MAX (UINT32_MAX)
//#define TCOST_MIN 1ull
#define BLOCKS_MIN (1ull)
#define BLOCK_SIZE (32)

struct bitstream {
	bool initialized;
	uint8_t *zeros;
	SHA256_CTX c;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_CIPHER_CTX* ctx;
#else
	EVP_CIPHER_CTX ctx;
#endif
};

struct balloon_options {
	int64_t s_cost;
	int32_t t_cost;
};

void balloon(unsigned char *input, unsigned char *output, int32_t len, int64_t s_cost, int32_t t_cost);
void balloon_reset();

void balloon_hash(unsigned char *input, unsigned char *output, int64_t s_cost, int32_t t_cost);
void balloon_128(unsigned char *input, unsigned char *output); // input 80, cost 128 4

#ifdef __cplusplus
}
#endif
