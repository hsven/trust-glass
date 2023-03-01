#include "../Enclave.h"
// #include "Encryption.h"
// #include <string>



char *base64(const unsigned char *input, int length) {
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
    return base64(digest_value, digest_len);
    // printf("%s", b64String);
    // std::string ret;
    // ret.reserve(*digest_len * 2);
    // for(const unsigned char *ptr = digest; ptr < digest+*digest_len; ++ptr) {
    //     char buf[3];
    //     sprintf(buf, "%02x", (*ptr)&0xff);
    //     ret += buf;
    // }
    // printf("%s", b64String);
    // for (size_t i = 0; i < *digest_len; i++)
    // {
    //     // auto c = digest[i];
    //     printf("%.2x", (const char*) digest[i]);
    // }
    
    // printf("%.2x", (const char*) digest);
}