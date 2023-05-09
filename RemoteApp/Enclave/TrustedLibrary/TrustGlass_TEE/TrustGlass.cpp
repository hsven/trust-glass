#include "TrustGlass.h"

TrustGlass::TrustGlass() {
    //Prepare keys
    ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    generate_ec_key_pair(&keyPair);
}

void TrustGlass::set_key_pair(const char* in) {
    longTermKeyPair = EVP_PKEY_new();

    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, in, strlen(in));

    if (PEM_read_bio_PrivateKey(bo, &longTermKeyPair, NULL, NULL) == NULL) {
        BIO_free(bo);
        EVP_PKEY_free(longTermKeyPair);
        return;
    }

    BIO_free(bo);
}

void TrustGlass::set_peer_key(const char* in) {
    longTermPeerKey = EVP_PKEY_new();

    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, in, strlen(in));

    if (PEM_read_bio_PUBKEY(bo, &longTermPeerKey, NULL, NULL) == NULL) {
        BIO_free(bo);
        EVP_PKEY_free(longTermPeerKey);
        return;
    }

    BIO_free(bo);
}

std::string TrustGlass::retrieve_public_EC_session_key() {
    if (keyPair == NULL) return "";

    EC_POINT const* pub = EC_KEY_get0_public_key(keyPair);
    if(!pub)
    {
        EC_KEY_free(keyPair);
        return "";
    }

    BN_CTX *ctx;
    ctx = BN_CTX_new();
    char* result = NULL;
    result = EC_POINT_point2hex(ecGroup, pub, POINT_CONVERSION_UNCOMPRESSED, ctx);
    if (strcmp(result, "") == 0) {
        EC_KEY_free(keyPair);
        return "";
    }

    BN_CTX_free(ctx);
    OPENSSL_free(result);

    return base64_encode((const unsigned char*) result, strlen(result));
}

bool TrustGlass::derive_secret_key(const char* encodedPeerKey) {
    //For some reason the string enters with an extra, unwanted, character
    //TODO: Check if this is still true

    unsigned char* decodedPeerKey = NULL;

    int len = base64_decode_len(encodedPeerKey, strlen(encodedPeerKey), &decodedPeerKey);
    std::string hexStr = std::string(OPENSSL_buf2hexstr(decodedPeerKey, len));
    hexStr.erase(std::remove(hexStr.begin(), hexStr.end(), ':'), hexStr.end());

    peerPoint = extract_ec_point(hexStr.data());
    if (!peerPoint) return false;
    
    size_t secretLen;
    secretKey = derive_shared_key(keyPair, peerPoint, &secretLen);
    if (secretKey == NULL || secretLen <= 0) return false;
    secretKey[secretLen] = '\0';

    return true;
}

std::string TrustGlass::encrypt_string(std::string contentString) {
    //TODO: Message size should not be hardcoded
    unsigned char encryptedMessage[contentString.length() + 256];
    int msgLen = aes_encryption((unsigned char*) contentString.data(), contentString.length(), secretKey, encryptedMessage);
    return std::string(base64_encode(encryptedMessage, msgLen));
}

std::string TrustGlass::sign_string(std::string contentString) {
    return sign_message(contentString.c_str(), longTermKeyPair);
}

ResponseMessage* TrustGlass::create_response(std::string headerMsg, std::string mainMsg, bool withSecure) {
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
        response->content = encrypt_string(contentString).data();
        response->digitalSignature = sign_string(contentString.c_str());
    }

    // //Prints for DEBUG purposes
    // printf("Message: %s\n", response->content.c_str());
    // printf("Signature: %s\n", response->digitalSignature.c_str());
    // printf("Freshess: %d\n", messageCounter);

    messageCounter++;
    return response;
}