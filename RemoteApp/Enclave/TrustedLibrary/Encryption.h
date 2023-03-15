#include "sgx_ttls.h"

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
// #include <openssl/sha
#include <string>

char* convert_to_base64(const unsigned char *input, int length);
unsigned char* decode_from_base64(const char* input, int length);
void generate_rsa_key(void);
std::string sign_message(std::string message); 
bool generate_ec_key_pair(EC_KEY **ecKey);
unsigned char* get_public_key(EVP_PKEY *pkey);
EC_POINT* extract_ec_point(char* in);
EVP_PKEY* convert_to_PKEY(EC_POINT* point);
unsigned char* derive_shared_key(EC_KEY* privKey, const EC_POINT* peerKey, size_t* secretLen);