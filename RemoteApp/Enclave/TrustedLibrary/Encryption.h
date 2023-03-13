#include "sgx_ttls.h"


#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
// #include <openssl/sha
#include <string>

char* convert_to_base64(const unsigned char *input, int length);
void generate_rsa_key(void);
std::string sign_message(std::string message); 
bool generate_ec_key_pair(EVP_PKEY **pkey);
unsigned char* get_public_key(EVP_PKEY *pkey);
