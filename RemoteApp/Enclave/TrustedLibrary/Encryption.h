#include "sgx_ttls.h"


#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
// #include <openssl/sha
#include <string>

void generate_rsa_key(void);
std::string sign_message(std::string message); 