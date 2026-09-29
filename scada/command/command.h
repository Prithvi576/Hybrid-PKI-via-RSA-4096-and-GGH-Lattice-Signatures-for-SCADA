#ifndef COMMAND_H
#define COMMAND_H

#include <string>
#include <cstdint>

struct Command {
    std::string command;
    std::string userId;
    std::string role;
    std::string certificateId;

    std::uint64_t timestamp;
    std::uint64_t sequence;

    std::string rsaSignature;
    std::string gghSignature;
};

#endif