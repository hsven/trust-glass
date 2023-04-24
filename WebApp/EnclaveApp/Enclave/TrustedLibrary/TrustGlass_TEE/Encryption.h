#include "sgx_ttls.h"

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <string>
#include <sgx_trts.h>

#include <algorithm>

/**
 * Encodes a binary string of specified length into a Base64 string
 * 
 * Param: 
 * - 'input' = binary string to be encoded
 * - 'length' = length of the binary string
 * 
 * Return: resulting Base64 encoded string, or NULL if the operation fails
*/
char* base64_encode(const unsigned char *input, int length);

/**
 * Decodes a Base64 string of specified length into a binary string
 * 
 * Param: 
 * - 'input' = Base64 string to be decoded
 * - 'length' = length of the Base64 string
 * 
 * Return: resulting decoded binary string, or NULL if the operation fails
*/
unsigned char* base64_decode(const char* input, int length);

/**
 * Decodes a Base64 string of specified length into a binary string
 * 
 * Param: 
 * - 'input' = Base64 string to be decoded
 * - 'length' = length of the Base64 string
 * -  'out' = resulting decoded binary string
 * 
 * Return: length of the 'out' string, or NULL if the operation fails
*/
int base64_decode_len(const char* input, int length, unsigned char** out);

/**
 * Hashes and signs the string 'message' with a specified key.
 * It applied SHA-256 for generating the digest, and ECDSA for signing it
 * 
 * Param: 
 * - 'message' = target string of this operation
 * - 'longTermKey' = long term private EC key
 * 
 * Return: Base64 encoded string of the signed digest, or an empty string if the operation fails
*/
std::string sign_message(const char* message, EVP_PKEY* longTermKey);

/**
 * Generates a new EC Key pair
 * 
 * Param:
 * - 'ecKey' = EC_KEY struct to store the resulting key
 * 
 * Return: 'true' if the operation was successful, 'false' otherwise
*/
bool generate_ec_key_pair(EC_KEY **ecKey);

/**
 * Extracts the public key of a key pair structure
 * 
 * Param:
 * - 'pKey' = key pair to extract the public key from
 * 
 * Return: public key if the operation was successful, 'NULL' otherwise
*/
unsigned char* get_public_key(EVP_PKEY *pkey);

/**
 * Creates a new EC_POINT object from an hex encoded EC point string
 * 
 * Param:
 * - 'in' = hex encoded EC point
 * 
 * Return: pointer to the new EC_POINT struct if the operation was successful, 'NULL' otherwise
*/
EC_POINT* extract_ec_point(char* in);

/**
 * Converts an EC_POINT structure into its EVP_PKEY equivalent,
 * using the NID_X9_62_prime256v1 EC curve
 * 
 * Param:
 * - 'point' = pointer to the target EC_POINT structure
 * 
 * Return: pointer to the new EVP_PKEY struct if the operation was successful, 'NULL' otherwise
*/
EVP_PKEY* convert_to_PKEY(EC_POINT* point);

/**
 * Applies ECDH to a pair of keys to derive a symmetric key
 * 
 * Param:
 * - 'privKey' = pointer to the private EC_KEY struct
 * - 'peerKey' = poiter to the public, peer EC_POINT struct
 * - 'secretLen' = output argument specifing the length of the return value
 * 
 * Return: key derived from the operation if it was successful, 'NULL' otherwise
*/
unsigned char* derive_shared_key(EC_KEY* privKey, const EC_POINT* peerKey, size_t* secretLen);

/**
 * Applies AES encryption to the specified plain text
 * 
 * Param:
 * - 'plainText' = plain text to encrypt
 * - 'plainTextLen' = length of the input plain text
 * - 'key' = symmetric key to perform the operation with
 * - 'cipherText' = output argument specifing the resulting cipher text
 * 
 * Return: length of the resulting cipher text if the operation was successful, -1 otherwise
*/
int aes_encryption(unsigned char* plainText, size_t plainTextLen, unsigned char* key, unsigned char* cipherText);

/**
 * Applies RSA encryption to the specified plain text
 * NOTE: Deprecated, does not return the cipher text 
 * 
 * Param:
 * - 'data' = plain text to encrypt
 * - 'pkey' = key to perform the operation with
*/
bool rsa_encryption(std::string data, RSA* pkey);

/**
 * Creates an alphanumeric string of specified length, with random characters
 * Taken from https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
 * 
 * Param:
 * - 'len' = desired length of the string
 * 
 * Return: string with randomly selected characters
*/
std::string generate_random_string(const int len);