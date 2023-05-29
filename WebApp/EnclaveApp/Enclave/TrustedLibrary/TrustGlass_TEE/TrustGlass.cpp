#include "TrustGlass.h"

TrustGlass::TrustGlass() {
    //Prepare keys
    ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    generate_ec_key_pair(&keyPair);


    PKEY_keyPair = EVP_PKEY_new();

    if (!EVP_PKEY_assign_EC_KEY(PKEY_keyPair, keyPair))
    {
        EVP_PKEY_free(PKEY_keyPair);
        abort();
    }
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

void TrustGlass::set_long_term_shared_key(std::string in) {
    longTermSharedKey = (char*) malloc( sizeof(char) * ( in.length() + 1 ) );
    strncpy(longTermSharedKey, in.c_str(), in.length());
}

char* TrustGlass::do_session_start() {
    const char* sessionData = this->create_session();

    // send_response("HANDSHAKE", response, "null", false);
    ResponseMessage* response = this->create_response("HANDSHAKE", sessionData, "null", false);
    return response->generate_final();
}

char* TrustGlass::do_pin_login() {
    std::map<char, char>* keyboard = this->create_random_keyboard("0123456789");
    std::string keyboardOut = this->map_to_string(keyboard);

    this->currentState = TrustGlassStates::IN_AUTH;
    ResponseMessage* response = this->create_response("HANDSHAKE", "Please insert your PIN following the defined number mapping", keyboardOut, true);
    return response->generate_final();
}

char* TrustGlass::do_error(std::string errorMsg) {
    return this->create_response("ERROR", errorMsg, "null", false)->generate_final();
}

char* TrustGlass::do_message(std::string msgContent, std::string map) {
    if (this->currentState != TrustGlassStates::CONNECTED) return "";
    
    if (map.empty())
        map = "null";

    return this->create_response("MSG", msgContent, map, true)->generate_final();
}

std::string TrustGlass::create_otp_value() {
    latestOTP = generate_random_string(6);

    return latestOTP;
}

bool TrustGlass::verify_otp_entry(const char* in) {
    return std::string(in) == latestOTP;
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

    return base64_encode((const unsigned char*) result, strlen(result));
}

std::string TrustGlass::encrypt_string(std::string contentString) {
    //TODO: Message size should not be hardcoded
    unsigned char total[32 + contentString.length() + 256];
    unsigned char encryptedMessage[contentString.length() + 256];
    unsigned char iv[16];
    unsigned char mac[16];
    int msgLen = aes_encryption((unsigned char*) contentString.data(), contentString.length(), sessionKey, encryptedMessage, iv, mac);

    //Prepend IV
    memcpy(total, iv, 16);
    //Encrypted Message
    memcpy(total+16, encryptedMessage, msgLen);
    //Append MAC
    memcpy(total+16+msgLen, mac, 16);
    return std::string(base64_encode(total, msgLen+32));
}

std::string TrustGlass::sign_string(std::string contentString) {
    return sign_message(contentString.c_str(), longTermKeyPair);
}

std::map<char, char>* TrustGlass::create_random_keyboard(std::string keyboardToRandomize) {
    //Reset previous maps 
    free(latestInvertedKeyboard);
    free(latestKeyboard);

    latestInvertedKeyboard = new std::map<char, char>(); 
    latestKeyboard = generate_randomized_keyboard(keyboardToRandomize, latestInvertedKeyboard);
    return latestKeyboard;
}

std::string TrustGlass::map_to_string(std::map<char, char>* map) {
    std::string out = "{";
    for (auto &&i : *map)
    {
        out += "\""; 
        out += i.first;
        out += "\":\"";
        out += i.second;
        out += "\",";
    }
    out.replace(out.length() - 1, 1, "}");

    return out;
}

std::string TrustGlass::decipher_randomized_string(std::string input) {
    std::string decipheredString = "";
    for (char character : input)
    {
        decipheredString += (*latestInvertedKeyboard)[character];
    }
    
    return decipheredString;
}

const char* TrustGlass::create_session() {
    //Step 1. Retrieve User-related Keys
    //TODO: Remove the hard-coding of this step

    //Step 2. Generate Nonce
    unsigned char* nonce = (unsigned char*) malloc(sizeof(unsigned char) * 16);
    int ret = generate_nonce(nonce, 16);
    if (ret != 1) {
        abort();
    }
    
    //Step 3. Obtain session key via KDF
    sessionKey = (unsigned char*) malloc(sizeof(unsigned char) * 32);
    unsigned char decodedLTK[256];
    unsigned char* test = NULL;

    base64_decode_len(longTermSharedKey, strlen(longTermSharedKey), &test);
    memcpy(decodedLTK, test, 256);
    ret = derive_new_key(decodedLTK, 256, nonce, 16, sessionKey);
    if (ret != 0) {
        abort();
    }

    //Return nonce and ID
    //TODO: Include ID
    char* nonceB64 = base64_encode(nonce, 16);

    return nonceB64;
}

ResponseMessage* TrustGlass::create_response(std::string headerMsg, std::string mainMsg, std::string map, bool isEncrypted) {
    //Generate Response Message
    ResponseMessage* response = new ResponseMessage();
    MessageContent* content = new MessageContent();
    content->header = headerMsg;
    content->message = mainMsg;
    content->mapStr = map;
    content->freshnessToken = messageCounter;
    std::string contentString = content->generate_final();

    //Prepare Response    
    response->content = base64_encode((unsigned char*) contentString.data(), contentString.length());

    //If message requires security properties
    if (isEncrypted) {
        response->content = encrypt_string(contentString).data();
    }
    response->encrypted = isEncrypted;

    // //Prints for DEBUG purposes
    // printf("Message: %s\n", response->content.c_str());
    // printf("Signature: %s\n", response->digitalSignature.c_str());
    // printf("Freshess: %d\n", messageCounter);

    messageCounter++;
    return response;
}