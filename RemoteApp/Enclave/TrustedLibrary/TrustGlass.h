#include "Encryption.h"

struct MessageContent {
    std::string header;
    std::string message;
    //Freshness token is incorporated inside the message, 
    // otherwise there's no obvious way to prevent tampering on it
    int freshnessToken;
    std::string jsonMessage = "";

    std::string generate_final() {
        return "{\"hdr\":\"" + header + 
            "\",\"msg\":\"" + message + 
            "\",\"fresh\":" + std::to_string(freshnessToken) +
            "}";
    }
};

struct ResponseMessage {
    std::string content;
    std::string digitalSignature;

    std::string finalMessage = "";

    char* generate_final() {
        finalMessage = "{\"msg\":\"" + content + 
            "\",\"sig\":\"" + digitalSignature +
            "\"}";

        return finalMessage.data();
    }

    size_t total_length() {
        return finalMessage.size();
    }
};


class TrustGlass {
    EVP_PKEY* longTermKeyPair_pkey = NULL;
    EVP_PKEY* longTermPeerKey_pkey = NULL;

    EC_GROUP *ecgroup = NULL;
    EC_KEY *keyPair = NULL;
    EC_POINT *peerPoint = NULL;
    unsigned char* secretKey = NULL;

    public:
    std::string currentMessage = "";

    TrustGlass();

    /**
     * Prepares and retrieves the public key of this session's EC Key Pair.
     * The public key is retrieved as a Base64 encoded EC Point.
     * 
     * Return: Base64 encoded EC point string if the operation was successful, empty string otherwise 
    */
    std::string retrieve_public_EC_session_key();

    /**
     * Decodes a Base64 EC Point, stores it, and derives a secret key via ECDH,
     * applying this new EC Point and TrustGlass' own EC Point.
     * 
     * Param: 
     * - 'encodedPeerKey' = Base64 encoded EC Point
     * 
     * Return: 'true' if the operation was successful, 'false' otherwise 
    */
    bool derive_secret_key(const char* encodedPeerKey);

    /**
     * Sets the long term EC key pair of the host enclave
     * 
     * Param: 
     * - 'in' = Base64 encoded EC private key string
    */
    void set_key_pair(const char* in);

    /**
     * Sets the long term EC public key from the peer service
     * 
     * Param: 
     * - 'in' = Base64 encoded EC public key string
    */
    void set_peer_key(const char* in);

    /**
     * Encrypts a string with the AES encryption scheme,
     * using the currently loaded keys to do so 
     * 
     * Param: 
     * - 'contentString' = target of the operation
     * 
     * Return: cipher text if the operation was successful, empty string otherwise 
    */
    std::string encrypt_string(std::string contentString);

    /**
     * Signs a string with curretly loaded long-term EC private key of the enclave
     * 
     * Param: 
     * - 'contentString' = target of the operation
     * 
     * Return: Base64 encoded signature if the operation was successful, empty string otherwise 
    */
    std::string sign_string(std::string contentString);
};

/**
 * Creates a ResponseMessage object
 * 
 * Param:
 * - 'headerMsg' = header to include in the object
 * - 'mainMsg' = message to include in the object
 * - 'withSecure' = applies the necessary encryption and signing of the message
 * 
 * Return: resulting ResponseMessage object
*/
ResponseMessage* create_response(std::string headerMsg, std::string mainMsg, bool withSecure);