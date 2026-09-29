#include "role_manager.h"

Role RoleManager::stringToRole(const std::string& role) {

    if (role == "OPERATOR")
        return Role::OPERATOR;

    if (role == "ENGINEER")
        return Role::ENGINEER;

    if (role == "ADMIN")
        return Role::ADMIN;

    return Role::UNKNOWN;
}

bool RoleManager::isCommandAllowed(
    Role role,
    const std::string& command
) {

    // Unknown roles cannot execute commands
    if (role == Role::UNKNOWN)
        return false;

    // Admin has full access
    if (role == Role::ADMIN)
        return true;

    // Normal SCADA commands
    if (command == "OPEN_VALVE" ||
        command == "CLOSE_VALVE" ||
        command == "READ_PRESSURE" ||
        command == "READ_TEMPERATURE") {

        return true;
    }

    // Critical/configuration commands
    if (command == "SHUTDOWN_PLANT" ||
        command == "CHANGE_CONFIGURATION") {

        return role == Role::ENGINEER;
    }

    // Unknown commands are rejected
    return false;
}