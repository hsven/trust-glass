#include "Encryption.h"

char* base64_encode(const unsigned char *input, int length) {
    const auto pl = 4*((length+2)/3);
    auto output = reinterpret_cast<char *>(calloc(pl+1, 1)); //+1 for the terminating null that EVP_EncodeBlock adds on
    const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), input, length);
    if (pl != ol) { return NULL; }
    return output;
}

unsigned char* base64_decode(const char* input, int length) {
    const auto pl = 3*length/4;
    auto output = reinterpret_cast<unsigned char *>(calloc(pl+1, 1));
    const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
    if (pl != ol) {
        return NULL;
    }
    return output;
}

int base64_decode_len(const char* input, int length, unsigned char** out) {
    const auto pl = 3*length/4;
    *out = reinterpret_cast<unsigned char *>(calloc(pl+1, 1));
    const auto ol = EVP_DecodeBlock(*out, reinterpret_cast<const unsigned char *>(input), length);
    if (pl != ol) {
        return NULL;
    }
    return ol;
}

std::string sign_message(const char* message, EVP_PKEY* pKey) {
    EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        EVP_MD_CTX_free(mdctx);
        return "";
    }
	if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pKey))
    {
        EVP_MD_CTX_free(mdctx);
        return "";
    }
	if(1 != EVP_DigestSignUpdate(mdctx, message, strlen(message)))
    {
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    unsigned char* digest_value;
    size_t digest_len = 0;

    //Obtain length to allocate
    if(1 != EVP_DigestSignFinal(mdctx, NULL, &digest_len)) {
        EVP_MD_CTX_free(mdctx);
        return "";
    }
     /* Allocate memory for the signature based on size in slen */
    if(!(digest_value = (unsigned char*) OPENSSL_malloc(sizeof(unsigned char) * (digest_len)))) {
        EVP_MD_CTX_free(mdctx);
        OPENSSL_free(digest_value);
        return "";
    }
    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(mdctx, digest_value, &digest_len)) {
        EVP_MD_CTX_free(mdctx);
        OPENSSL_free(digest_value);
        return "";
    }

	EVP_MD_CTX_free(mdctx);
    return base64_encode(digest_value, (int) digest_len);
}

// As seen in https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
bool generate_ec_key_pair(EC_KEY **ecKey) {
    if(NULL == (*ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) {
        return false;
    }

    if(1 != EC_KEY_generate_key(*ecKey)) {
        EC_KEY_free(*ecKey);
        return false;
    }

    return true;
}

unsigned char* get_public_key(EVP_PKEY *pkey) {
    int len = i2d_PublicKey(pkey, NULL);
    unsigned char *buf = (unsigned char *) malloc (len + 1);

    if (0 < len) {
        return NULL;
    } 
    else if (!buf) {
        return NULL;
    }

    unsigned char *tbuf = buf;
    if (0 < i2d_PublicKey(pkey, &tbuf)) {
        free(buf);
        return NULL;
    }

    return tbuf;
}

EC_POINT* extract_ec_point(char* in) {
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* retPoint = NULL;
    return EC_POINT_hex2point(ecgroup, in, retPoint, ctx);
}

EVP_PKEY* convert_to_PKEY(EC_POINT* point) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);;
    EC_KEY* key = EC_KEY_new();
    EVP_PKEY* finalKey = EVP_PKEY_new();

    if (1 != EC_KEY_set_group(key, group)) {
        EC_KEY_free(key);
        EVP_PKEY_free(finalKey);
        return NULL;
    }
    if (1 != EC_KEY_set_public_key(key, point)) {
        EC_KEY_free(key);
        EVP_PKEY_free(finalKey);
        return NULL;
    }
    if (1 != EVP_PKEY_set1_EC_KEY(finalKey, key)) {
        EC_KEY_free(key);
        EVP_PKEY_free(finalKey);
        return NULL;
    }

    EC_KEY_free(key);
    return finalKey;
}

unsigned char* derive_shared_key(EC_KEY* privKey, const EC_POINT* peerKey, size_t* secretLen){
	int field_size;
	unsigned char *secret;

	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(privKey));
	*secretLen = (field_size + 7) / 8;

	if (NULL == (secret = (unsigned char*) OPENSSL_malloc(*secretLen))) {
		return NULL;
	}

	*secretLen = ECDH_compute_key(secret, *secretLen,
					peerKey, privKey, NULL);

	if (*secretLen <= 0) {
		OPENSSL_free(secret);
		return NULL;
	}
	return secret;
}

//Taken from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int aes_encryption(unsigned char* plainText, size_t plainTextLen, unsigned char* key, unsigned char* cipherText) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // A 128 bit IV
    // TODO: Remove this, it should not be hardcoded
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }
    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

bool rsa_encryption(std::string data, RSA* longTermKey) {
    EVP_PKEY* pKey = EVP_PKEY_new();

    if (!EVP_PKEY_assign_RSA(pKey, longTermKey))
    {
        EVP_PKEY_free(pKey);
        return "";
    }

    std::string output = "";
    // Create/initialize context
    EVP_PKEY_CTX* ctx;
    ctx = EVP_PKEY_CTX_new(pKey, NULL);
    EVP_PKEY_encrypt_init(ctx);

    // Specify padding: default is PKCS#1 v1.5
    // EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING); // for OAEP with SHA1 for both digests

    // Encryption
    size_t ciphertextLen;
    EVP_PKEY_encrypt(ctx, NULL, &ciphertextLen, (const unsigned char*)data.c_str(), data.size());
    unsigned char* ciphertext = (unsigned char*)OPENSSL_malloc(ciphertextLen);
    EVP_PKEY_encrypt(ctx, ciphertext, &ciphertextLen, (const unsigned char*)data.c_str(), data.size());
    output.assign((char*)ciphertext, ciphertextLen);

    // Release memory
    EVP_PKEY_free(pKey);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(ciphertext);

    return true; // add exception/error handling
}

std::string generate_random_string(const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);


    for (int i = 0; i < len; ++i) {
        char n[12];
        sgx_read_rand(reinterpret_cast<unsigned char*>(&n),
                        sizeof(n));

        tmp_s += alphanum[(*(char*)n) % (sizeof(alphanum) - 1)];
    }
    
    return tmp_s;
}