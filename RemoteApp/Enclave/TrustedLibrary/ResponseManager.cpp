#include <map>
#include <string>

enum MenuOptions {
    NO_MENU_OPTION,
    EXAMPLE_1,
    EXAMPLE_2,
    EXAMPLE_3,
    EXAMPLE_4,
    EXAMPLE_5,
};

enum SubMenuOptions {
    NO_SUBMENU_OPTION,
    CONFIRM,
    DENY,
};

class ResponseManager {
    MenuOptions currentOption = MenuOptions::NO_MENU_OPTION;

    public:
    int messageCounter = 0;
    //This map allows the TEE to keep track of the options the user
    //has at their disposal during interactions
    std::map<std::string, MenuOptions> userMenu = {};


    /* 
    * prepare_response: 
    *   Creates an adequate response according to the input command.
    */
    std::string prepare_response(std::string input) {
        switch (currentOption)
        {  
            //Let's assume example 5 is an echo mode
            case MenuOptions::EXAMPLE_5:
                return "response_" + input;    
            default:
                break;
        }

        if(!userMenu.empty()) {
            switch (userMenu[input])
            {
            case MenuOptions::EXAMPLE_1:
                return "Selected EXAMPLE_1";
            case MenuOptions::EXAMPLE_2:
                return "Selected EXAMPLE_2";      
            case MenuOptions::EXAMPLE_3:
                return "Selected EXAMPLE_3";       
            case MenuOptions::EXAMPLE_4:
                return "Selected EXAMPLE_4";      
            //Let's assume example 5 is an echo mode
            case MenuOptions::EXAMPLE_5:
                currentOption = MenuOptions::EXAMPLE_5;
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


