#ifndef STRING_TOOLS_H
#define STRING_TOOLS_H

#include <string>
#include <sstream>

// Converts a byte array (std::string where each char represents a byte) to a hexadecimal string.
// The function iterates over each byte in the input string, converts it to a two-character hex representation,
// and appends it to the output string.
std::string inline Byte2HexAsc(const std::string& bytes) {
    std::ostringstream o_stream;  // Stream used to format output string
    for (uint8_t item : bytes) {
        o_stream.width(2);  // Set width to 2 to ensure two characters for each byte (adding leading zero if necessary)
        o_stream.fill('0');  // Fill with '0' if the hex number is less than 0x10
        o_stream << std::hex << (uint32_t)item;  // Convert byte to hexadecimal
    }
    o_stream.flush();  // Flush stream to ensure all data is processed
    return o_stream.str();  // Return the formatted string
}

// Converts a hexadecimal string to a byte string (std::string where each char represents a byte).
// This function parses two characters (one hex byte) at a time and converts them from the hex representation
// to a char, appending each to the output string.
std::string inline HexAsc2ByteString(const std::string& hex) {
    std::string rtn;  // Output string to hold the converted bytes
    for (size_t i = 0; i < hex.length(); i += 2) {
        // Convert two hex characters to a byte
        rtn += (char)std::strtol(hex.substr(i, 2).c_str(), nullptr, 16);
    }
    return rtn;  // Return the byte string
}

#endif // STRING_TOOLS_H
