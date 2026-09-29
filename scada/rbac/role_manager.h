#ifndef ROLE_MANAGER_H
#define ROLE_MANAGER_H

#include <string>

enum class Role {
    OPERATOR,
    ENGINEER,
    ADMIN,
    UNKNOWN
};

class RoleManager {
public:
    static Role stringToRole(const std::string& role);

    static bool isCommandAllowed(
        Role role,
        const std::string& command
    );
};

#endif