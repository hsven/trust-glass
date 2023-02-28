#include "sgx_ttls.h"


#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
// #include <openssl/sha

void generate_rsa_key(void);
void sign_message(const char* message); 