#include <string>

class MessageContent {
    public:
        std::string header;
        std::string message;
        std::string mapStr = "";
        //Freshness token is incorporated inside the message, 
        // otherwise there's no obvious way to prevent tampering on it
        int freshnessToken;
        std::string jsonMessage = "";

        std::string generate_final() {
            return "{\"hdr\":\"" + header + 
                "\",\"msg\":\"" + message + 
                "\",\"map\":" + mapStr +
                ",\"fresh\":" + std::to_string(freshnessToken) +
                "}";
        }
};

class ResponseMessage {
    public:
        std::string content;

        std::string finalMessage = "";
        bool encrypted = false;
    
        char* generate_final() {
            finalMessage = "{\"msg\":\"" + content + 
                "\",\"enc\":" + (encrypted ? "true" : "false") +
                "}";

            return finalMessage.data();
        }

        size_t total_length() {
            return finalMessage.size();
        }
};