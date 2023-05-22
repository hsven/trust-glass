#include "Encryption.h"
#include "ResponseMessage.h"
#include <cmath>
#include <time.h>

enum class TrustGlassStates {
    DISCONNECTED,
    IN_OTP,
    IN_AUTH,
    CONNECTED
};

class TrustGlass {
    EVP_PKEY* longTermKeyPair = NULL;
    EVP_PKEY* longTermPeerKey = NULL;
    char* otpSharedKey = NULL;
    std::string latestOTP = "";
    std::map<char, char>* latestKeyboard;
    std::map<char, char>* latestInvertedKeyboard;
    EC_GROUP *ecGroup = NULL;
    EC_KEY *keyPair = NULL;
    EVP_PKEY* PKEY_keyPair = NULL;
    EC_POINT *peerPoint = NULL;

    unsigned char* sessionIV = NULL;
    
    public:
    TrustGlassStates currentState = TrustGlassStates::DISCONNECTED;
    char* longTermSharedKey = NULL;
    unsigned char* sessionKey = NULL;
    int messageCounter = 0;
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
     * Sets the long term shared secret key of the enclave and its peer
     * 
     * Param: 
     * - 'in' = Key string
    */
    void set_long_term_shared_key(std::string in);

    /**
     * Standard function for session creation. 
     * It calls TrustGlass::create_session and then prepares the message to be sent to the glasses 
     * 
     * Return: Message with Nonce and Server ID for the glasses to read
    */
    char* do_session_start();

    /**
     * Standard function for PIN login. 
     * It creates a random mapping of numbers, sets TrustGlass to the correct state, and prepares the message to be sent to the glasses
     * 
     * Return: Message with PIN instructions for the glasses to read
    */
    char* do_pin_login();

    /**
     * Standard function for generic messages. 
     * It prepares a message to be sent to the glasses, with the specified content and optional map.
     * 
     * Param: 
     * - 'msgContent' = Message to be encrypted
     * - 'map' = Optional keyboard mapping. Leave it empty or as "null" if not necessary
     * 
     * Return: Message for the glasses to read
    */
    char* do_message(std::string msgContent, std::string map);
    
    /**
     * Standard function for error messages. 
     * It prepares a message to be sent to the glasses, with the specified error message.
     * Note: The message is not encrypted, since this can be used before a session is established
     * 
     * Param: 
     * - 'errorMsg' = Message to be encrypted
     * 
     * Return: Error message for the glasses to read
    */
    char* do_error(std::string errorMsg);

    /**
     * Generates an alphanumerical (a-zA-Z0-9) string of 6 character for challenge-response purposes
     * Also stores the generated result to check against in TrustGlass::verify_otp_entry
     * 
     * Return: string of random alphanumerical characters
    */
    std::string create_otp_value();

    /**
     * Verifies if the input matches the stored OTP value, generated in TrustGlass::create_otp_value
     * 
     * Param: 
     * - 'in' = string to be compared
     * 
     * Return: Whether the string matches or not
    */
    bool verify_otp_entry(const char* in);

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

    /**
     * Creates a randomized keyboard mapping, as well as the inverted mapping to check user input in TrustGlass::decipher_randomized_string.
     * The characters to randomize are user-specified
     * 
     * Param: 
     * - 'keyboardToRandomize' = target of the operation
     * 
     * Return: pointer to the randomized keyboard map
    */
    std::map<char, char>* create_random_keyboard(std::string keyboardToRandomize);

    /**
     * Converts a map of characters to characters into a compatible JSON string
     * 
     * Param: 
     * - 'map' = target of the operation
     * 
     * Return: The resulting JSON string
    */
    std::string map_to_string(std::map<char, char>* map);

    /**
     * Recovers the original characters of the input string, by utilizing the inverted mapping generated in TrustGlass::create_random_keyboard
     * 
     * Param: 
     * - 'input' = target of the operation
     * 
     * Return: The deciphered string
    */
    std::string decipher_randomized_string(std::string input);

    /**
     * Sets up TrustGlass for a new session with a specific set of user+smart glasses
     * It generates a nonce and derives the session key with it.
     * Unless granularity is required, use TrustGlass::do_session_start instead
     * 
     * Return: The nonce required to derive the session key
    */
    const char* create_session();

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
    ResponseMessage* create_response(std::string headerMsg, std::string mainMsg, std::string map, bool signWithSessionKeys);
};
