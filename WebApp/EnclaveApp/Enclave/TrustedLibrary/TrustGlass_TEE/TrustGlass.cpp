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

void TrustGlass::set_otp_key(std::string in) {
    // strcpy(otpSharedKey, in);
    otpSharedKey = (char*) malloc( sizeof(char) * ( in.length() + 1 ) );
    strncpy(otpSharedKey, in.c_str(), in.length());
    // otpSharedKey = in.data();
    // otpSharedKey = in;
}

std::string TrustGlass::create_otp_value() {
    latestOTP = generate_random_string(6);
    // latestOTP = "AAAAAA";

    unsigned char encryptedMessage[latestOTP.length() + 256];
    // base64_decode(otpSharedKey.data())
    int msgLen = aes_encryption((unsigned char*) latestOTP.data(), latestOTP.length(), base64_decode(otpSharedKey, strlen(otpSharedKey)), encryptedMessage);
    // encrypt_string(std::string());
    return base64_encode(encryptedMessage, msgLen);

    // encrypt_string(std::string(encryptedOtp));
}

// See https://stackoverflow.com/questions/73392097/totp-implementation-using-c-and-openssl
bool TrustGlass::verify_otp_entry(const char* in) {
    return std::string(in) == latestOTP;

    // if (strlen(in) != 6) {
    //     return false;
    // }
    // unsigned long long intCounter = floor(time(NULL)/30);

    // unsigned long long endianness = 0xdeadbeef;
    // if ((*(const uint8_t *)&endianness) == 0xef) {
    // intCounter = ((intCounter & 0x00000000ffffffff) << 32) | ((intCounter & 0xffffffff00000000) >> 32);
    // intCounter = ((intCounter & 0x0000ffff0000ffff) << 16) | ((intCounter & 0xffff0000ffff0000) >> 16);
    // intCounter = ((intCounter & 0x00ff00ff00ff00ff) <<  8) | ((intCounter & 0xff00ff00ff00ff00) >>  8);
    // };

    // char md[20];
    // unsigned int mdLen;
    // HMAC(EVP_sha1(), totpKey.data(), totpKey.size(), (const unsigned char*)&intCounter, sizeof(intCounter), (unsigned char*)&md, &mdLen);
    // // OPENSSL_cleanse(key, keylen);
    // int offset = md[19] & 0x0f;
    // int bin_code = (md[offset] & 0x7f) << 24
    //     | (md[offset+1] & 0xff) << 16
    //     | (md[offset+2] & 0xff) << 8
    //     | (md[offset+3] & 0xff);
    // bin_code = bin_code % 1000000;
    // char correctCode[7];
    // snprintf((char*)&correctCode, 7,"%06d", bin_code);
    // int compR = strcmp(in, correctCode);
    // // int compR = compHash(&correctCode, in, 6); // Compares the two char arrays in a way that avoids timing attacks. Returns 0 on success.
    // // delete[] key;
    // // delete[] code;
    // if (compR == 0) {
    //     return true;
    // }
    // // std::this_thread::sleep_for(std::chrono::seconds(5));
    // return false;
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
    // OPENSSL_free(result);

    return base64_encode((const unsigned char*) result, strlen(result));
}

bool TrustGlass::derive_secret_key(const char* encodedPeerKey) {
    //For some reason the string enters with an extra, unwanted, character
    //TODO: Check if this is still true

    unsigned char* decodedPeerKey = NULL;

    int len = base64_decode_len(encodedPeerKey, strlen(encodedPeerKey), &decodedPeerKey);
    char* hexCharArr = OPENSSL_buf2hexstr(decodedPeerKey, len);
    std::string hexStr = std::string(hexCharArr);
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