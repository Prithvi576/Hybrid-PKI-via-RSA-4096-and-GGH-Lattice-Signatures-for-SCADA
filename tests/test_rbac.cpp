#include <iostream>

#include "../scada/rbac/role_manager.h"

int main() {

    Role operatorRole =
        RoleManager::stringToRole("OPERATOR");

    Role engineerRole =
        RoleManager::stringToRole("ENGINEER");

    Role adminRole =
        RoleManager::stringToRole("ADMIN");


    std::cout << "Operator - OPEN_VALVE: "
              << RoleManager::isCommandAllowed(
                     operatorRole,
                     "OPEN_VALVE")
              << std::endl;


    std::cout << "Operator - SHUTDOWN_PLANT: "
              << RoleManager::isCommandAllowed(
                     operatorRole,
                     "SHUTDOWN_PLANT")
              << std::endl;


    std::cout << "Engineer - SHUTDOWN_PLANT: "
              << RoleManager::isCommandAllowed(
                     engineerRole,
                     "SHUTDOWN_PLANT")
              << std::endl;


    std::cout << "Admin - CHANGE_CONFIGURATION: "
              << RoleManager::isCommandAllowed(
                     adminRole,
                     "CHANGE_CONFIGURATION")
              << std::endl;


    return 0;
}