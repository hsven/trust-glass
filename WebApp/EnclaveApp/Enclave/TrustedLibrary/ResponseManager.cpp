#include <map>
#include <string>
#include "TrustGlass_TEE/TrustGlass.h"

enum MenuOptions {
    NO_MENU_OPTION,
    CHECK_BALANCE,
    TAKE_MONEY,
    LOGOUT,
    DEBUG_ECHO,
};

enum SubMenuOptions {
    NO_SUBMENU_OPTION,
    CONFIRM,
    DENY,
};


class ResponseManager {
    MenuOptions currentOption = MenuOptions::NO_MENU_OPTION;
    int currentBalance = 99999;
    TrustGlass* trustGlass;
    public:
    //This map allows the TEE to keep track of the options the user
    //has at their disposal during interactions
    std::map<std::string, MenuOptions> userMenu = {};

    void set_TrustGlass(TrustGlass* trstGls) {
        trustGlass = trstGls;
    }

    std::string generate_home_message() {
        trustGlass->currentState = TrustGlassStates::CONNECTED;

        this->userMenu.clear();
        std::string opt1 = generate_random_string(4);

        std::string opt2 = "abcd";
        do {
            opt2 = generate_random_string(4);
        } while (opt1.compare(opt2) == 0);
        std::string opt3 = "abcd";
        do {
            opt3 = generate_random_string(4);
        } while (opt1.compare(opt3) == 0 && opt2.compare(opt3) == 0);
        std::string opt4 = "abcd";
        do {
            opt4 = generate_random_string(4);
        } while (opt1.compare(opt3) == 0 && opt2.compare(opt3) == 0  && opt3.compare(opt4) == 0);

        this->userMenu = {
            {opt1, MenuOptions::CHECK_BALANCE},
            {opt2, MenuOptions::TAKE_MONEY},
            {opt3, MenuOptions::LOGOUT},
            {opt4, MenuOptions::DEBUG_ECHO}
        };

        std::string resStr = "Type:\n- \'" + opt1 + "\' to check your balance.\n";
        resStr += "- \'" + opt2 + "\' to retrieve money from your account.\n";
        resStr += "- \'" + opt3 + "\' to logout.\n";
        resStr += "- \'" + opt4 + "\' to enter echo mode.";
        return resStr;
    }

    /* 
    * prepare_response: 
    *   Creates an adequate response according to the input command.
    */
    std::string prepare_response(std::string input, std::string* mapOutput) {
        switch (currentOption)
        {  
            case MenuOptions::TAKE_MONEY:
            {
                std::string decipheredStr = trustGlass->decipher_randomized_string(input);
                try
                {
                    int take = std::stoi(decipheredStr);
                    currentBalance -= take;
                    currentOption = MenuOptions::NO_MENU_OPTION;
                    std::string homeMsg = generate_home_message();
                    return "Took " + decipheredStr + "€ from the account.\nThe current balance is: " + std::to_string(currentBalance) + "\n\n" + homeMsg;
                }
                catch(const std::exception& e)
                {
                    return "Invalid number, please enter an integer.";
                }
                return "ERROR Something went wrong, please try again.";
            }
            case MenuOptions::LOGOUT:
                return "Currently logged out. Please login again for new operations";
            //Let's assume example 5 is an echo mode
            case MenuOptions::DEBUG_ECHO:
                return "response_" + input;    
            default:
                break;
        }

        if(!userMenu.empty()) {
            switch (userMenu[input])
            {
            case MenuOptions::CHECK_BALANCE:
            {
                std::string homeMsg = generate_home_message();
                return "Your account's current balance is: " + std::to_string(currentBalance) + "\n\n" + homeMsg;
            }
            case MenuOptions::TAKE_MONEY:
            {
                currentOption = MenuOptions::TAKE_MONEY;
                *mapOutput = trustGlass->map_to_string(trustGlass->create_random_keyboard("0123456789"));
                return "Please select the amount to take.\nFollow the following mapping:\n";      
            }
            case MenuOptions::LOGOUT:
                currentOption = MenuOptions::LOGOUT;
                return "Logged out";         
            case MenuOptions::DEBUG_ECHO:
                currentOption = MenuOptions::DEBUG_ECHO;
                return "Selected echo mode.";    
            default:
                return "Invalid selection and/or input, please try again.";       
            }
        } else {
            return "Invalid selection and/or input, please try again.";       
        }

        return "ERROR when preparing response";
    }
};