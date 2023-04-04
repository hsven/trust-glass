#include "Encryption.h"


struct MessageContent {
    std::string header;
    std::string message;
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
    //Freshness token is incorporated inside the message, 
    // otherwise there's no obvious way to prevent tampering on it
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


void ecall_receive_input(const char* in);
void ecall_receive_key_pair(const char* in);
void ecall_receive_peer_key(const char* in);
void ecall_initial_enclave_setup(void);

void derive_secret_key(const char* encodedPeerKey);

/**
 * Creates an alphanumeric string of specified length.
 * Taken from https://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
*/
std::string generate_random_string(const int len);

ResponseMessage* create_response(std::string headerMsg, std::string mainMsg, bool withSecure);