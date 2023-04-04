#include "TrustGlass.h"

int messageCounter = 0;
EVP_PKEY* longTermKeyPair_pkey =  EVP_PKEY_new();

EVP_PKEY* longTermPeerKey_pkey =  EVP_PKEY_new();

EC_KEY *keyPair = NULL;
EC_POINT *peerPoint = NULL;
unsigned char* secretKey = NULL;


void ecall_receive_input(const char* in) {
    //Decrypt message

    //Generate Response Message
    // ResponseMessage* response = create_response("MSG", resManager.prepare_response(in), true);
    ResponseMessage* response = create_response("MSG", in, true);

    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));
}

ResponseMessage* create_response(std::string headerMsg, std::string mainMsg, bool withSecure) {
    //Generate Response Message
    ResponseMessage* response = new ResponseMessage();
    MessageContent* content = new MessageContent();
    content->header = headerMsg;
    content->message = mainMsg;
    content->freshnessToken = messageCounter;
    std::string contentString = content->generate_final();

    //Prepare Response    
    response->content = base64_encode((unsigned char*) contentString.data(), contentString.length());

    //If message requires security properties
    if (withSecure) {
        //Encrypt response
        //TODO: Message size should not be hardcoded
        unsigned char encryptedMessage[contentString.length() + 256];
        int msgLen = aes_encryption((unsigned char*) contentString.data(), contentString.length(), secretKey, encryptedMessage);
        response->content = base64_encode(encryptedMessage, msgLen);

        //Sign message
        response->digitalSignature = sign_message(contentString.c_str(), longTermKeyPair_pkey);
    }

    //Prints for DEBUG purposes
    printf("%s\n", "From the original creator!");
    printf("Message: %s\n", response->content.c_str());
    printf("Signature: %s\n", response->digitalSignature.c_str());
    printf("Freshess: %d\n", messageCounter);

    messageCounter++;
    return response;
}

void ecall_receive_key_pair(const char* in) {
    printf("Peer Key: %s\n", in);

    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, in, strlen(in));

    if (PEM_read_bio_PrivateKey(bo, &longTermKeyPair_pkey, NULL, NULL) == NULL) {
        printf("PEM_read_bio_PrivateKey: %ld\n",  ERR_get_error());
        BIO_free(bo);
        EVP_PKEY_free(longTermKeyPair_pkey);
        return;
    }

    BIO_free(bo);
}

void ecall_receive_peer_key(const char* in) {
    printf("Peer Key: %s\n", in);

    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, in, strlen(in));

    if (PEM_read_bio_PUBKEY(bo, &longTermPeerKey_pkey, NULL, NULL) == NULL) {
        printf("PEM_read_bio_PUBKEY: %ld\n",  ERR_get_error());
        BIO_free(bo);
        EVP_PKEY_free(longTermPeerKey_pkey);
        return;
    }

    BIO_free(bo);
}

void ecall_initial_enclave_setup(void) {
    //Prepare keys
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if(!generate_ec_key_pair(&keyPair)) {
        printf("%s\n", "Error generating keypair");
        return;
    }
    

    EC_POINT const* pub = EC_KEY_get0_public_key(keyPair);
    if(!pub)
    {
        EC_KEY_free(keyPair);
        return;
    }
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    char* result = NULL;
    result = EC_POINT_point2hex(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, ctx);
    printf("POINT: %s\n", result);
    const char* b64PubKey = base64_encode((const unsigned char*) result, strlen(result));
    printf("KEY: %s\n", b64PubKey);

    BN_CTX_free(ctx);
    OPENSSL_free(result);

    //Generate Response Message
    ResponseMessage* response = create_response("HANDSHAKE", b64PubKey, false);
    char* finalMsg = response->generate_final();
    ocall_send_response(finalMsg, strlen(finalMsg));
}

void derive_secret_key(const char* encodedPeerKey) {
    //For some reason the string enters with an extra, unwanted, character
    printf("KEY: %s\n", encodedPeerKey);
    unsigned char* decodedPeerKey = NULL;

    int len = base64_decode_len(encodedPeerKey, strlen(encodedPeerKey), &decodedPeerKey);
    std::string hexStr = std::string(OPENSSL_buf2hexstr(decodedPeerKey, len));
    hexStr.erase(std::remove(hexStr.begin(), hexStr.end(), ':'), hexStr.end());
    printf("%s\n", hexStr.data());

    peerPoint = extract_ec_point(hexStr.data());
    if (!peerPoint) {
        printf("%s\n", "Failed to create the EC_POINT for the peer key");
    }
    size_t secretLen;
    secretKey = derive_shared_key(keyPair, peerPoint, &secretLen);
    secretKey[secretLen] = '\0';

    printf("SECRET KEY: %s\nKey Length: %ld\nRegistered Length: %ld\n\n", base64_encode(secretKey, secretLen), secretLen, strlen((const char*) secretKey));
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