#include "sgx_ttls.h"

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
// #include <openssl/sha
#include <string>
#include <sgx_trts.h>

#include "Utils.h"

char* base64_encode(const unsigned char *input, int length);
unsigned char* base64_decode(const char* input, int length);
int base64_decode_len(const char* input, int length, unsigned char** out);
void generate_rsa_key(void);
std::string sign_message(const char* message, EVP_PKEY* longTermKey);
bool generate_ec_key_pair(EC_KEY **ecKey);
unsigned char* get_public_key(EVP_PKEY *pkey);
EC_POINT* extract_ec_point(char* in);
EVP_PKEY* convert_to_PKEY(EC_POINT* point);
unsigned char* derive_shared_key(EC_KEY* privKey, const EC_POINT* peerKey, size_t* secretLen);
int aes_encryption(unsigned char* plainText, size_t plainTextLen, unsigned char* key, unsigned char* cipherText);
bool rsa_encryption(std::string data, RSA* pkey);