#include "../Enclave.h"
// #include "Encryption.h"
// #include <string>


char* convert_to_base64(const unsigned char *input, int length) {
  const auto pl = 4*((length+2)/3);
  auto output = reinterpret_cast<char *>(calloc(pl+1, 1)); //+1 for the terminating null that EVP_EncodeBlock adds on
  const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), input, length);
  if (pl != ol) { return NULL; }
  return output;
}




//Taken from intel sgxssl test app
void generate_rsa_key() {
    //Initialize the generator
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
    {
        printf("EVP_PKEY_CTX_new_id: %ld\n", ERR_get_error());
        return;
    }
    int ret = EVP_PKEY_keygen_init(ctx);
    if (!ret)
    {
        printf("EVP_PKEY_keygen_init: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0)
    {
        printf("EVP_PKEY_CTX_set_rsa_keygen_bits: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    EVP_PKEY* evp_pkey = NULL;  //The public key struct
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (EVP_PKEY_keygen(ctx, &evp_pkey) <= 0)
#else //new API EVP_PKEY_generate() since 3.0
    if (EVP_PKEY_generate(ctx, &evp_pkey) <= 0)
#endif
    {
        printf("EVP_PKEY_keygen: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    // public key - string
    int len = i2d_PublicKey(evp_pkey, NULL);
    // evp_pkey.
    unsigned char *buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        //For some reason the usage of \n without an argument before is bad
        printf("Failed in calling malloc()%c\n", ';');
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    unsigned char *tbuf = buf;
    i2d_PublicKey(evp_pkey, &tbuf);

    // print public key
    printf ("{\"public\":\"");
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x", (unsigned char) buf[i]);
    }
    printf("\"}");
    printf("%c\n", ';');

    free(buf);

    // private key - string
    len = i2d_PrivateKey(evp_pkey, NULL);
    buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        // printf("Failed in calling malloc()\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    tbuf = buf;
    i2d_PrivateKey(evp_pkey, &tbuf);

    // print private key
    printf ("{\"private\":\"");
    for (i = 0; i < len; i++) {
        printf("%02x", (unsigned char) buf[i]);
    }
    printf("\"}");
    printf("%c\n", ';');

    free(buf);

    EVP_PKEY_free(evp_pkey);
}

// , unsigned char **digest, unsigned int *digest_len
std::string sign_message(std::string message) {
    // size_t len = sizeof(message) - 1;
    // unsigned int mdlen = EVP_MD_size(EVP_sha256());
    EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        printf("EVP_MD_CTX_new: %ld\n", ERR_get_error());
        EVP_MD_CTX_free(mdctx);
        return "";
    }
	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    {
        printf("EVP_DigestInit_ex: %ld\n", ERR_get_error());
        EVP_MD_CTX_free(mdctx);
        return "";
    }
	if(1 != EVP_DigestUpdate(mdctx, message.c_str(), message.length()))
    {
        printf("EVP_DigestUpdate: %ld\n", ERR_get_error());
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    // unsigned char *digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
    unsigned char digest_value[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 1;

	// if(digest == NULL)
    // {
    //     printf("OPENSSL_malloc: %ld\n", ERR_get_error());
    //     EVP_MD_CTX_free(mdctx);
    //     return;
    // }
	if(1 != EVP_DigestFinal_ex(mdctx, digest_value, &digest_len))
    {
        printf("EVP_DigestFinal_ex: %ld\n", ERR_get_error());
        EVP_MD_CTX_free(mdctx);
        return "";
    }

	EVP_MD_CTX_free(mdctx);
    // printf("%d", digest_len);
    return convert_to_base64(digest_value, digest_len);
}

// As seen in https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
bool generate_ec_key_pair(EVP_PKEY **pkey) {
    EVP_PKEY_CTX *pctx, *kctx;
	// EVP_PKEY_CTX *ctx;
	unsigned char *secret;
    EVP_PKEY *keyPair = NULL;
	EVP_PKEY *peerkey, *params = NULL;
	/* NB: assumes pkey, peerkey have been already set up */

	/* Create the context for parameter generation */
	if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
        printf("EVP_PKEY_CTX_new_id: %ld\n", ERR_get_error());
        return false;
    }

	/* Initialise the parameter generation */
	if(1 != EVP_PKEY_paramgen_init(pctx)) {
        printf("EVP_PKEY_paramgen_init: %ld\n", ERR_get_error());
        return false;
    }

	/* We're going to use the ANSI X9.62 Prime 256v1 curve */
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) {
        printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid: %ld\n", ERR_get_error());
        return false;
    }

	/* Create the parameter object params */
	if (!EVP_PKEY_paramgen(pctx, &params)) {
        printf("EVP_PKEY_paramgen: %ld\n", ERR_get_error());
        return false;
    }

	/* Create the context for the key generation */
	if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) {
        printf("EVP_PKEY_CTX_new: %ld\n", ERR_get_error());
        return false;
    }

	/* Generate the key */
	if(1 != EVP_PKEY_keygen_init(kctx)) {
        printf("EVP_PKEY_keygen_init: %ld\n", ERR_get_error());
        return false;
    }
	if (1 != EVP_PKEY_keygen(kctx, &keyPair)) {
        printf("EVP_PKEY_CTX_keygen: %ld\n", ERR_get_error());
        return false;
    }

    // EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    *pkey = keyPair;

    return true;
}

unsigned char* get_public_key(EVP_PKEY *pkey) {
    int len = i2d_PublicKey(pkey, NULL);
    // evp_pkey.
    unsigned char *buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        //For some reason the usage of \n without an argument before is bad
        printf("Failed in calling malloc()%c\n", ';');
        return nullptr;
    }
    unsigned char *tbuf = buf;
    i2d_PublicKey(pkey, &tbuf);

    return tbuf;
}