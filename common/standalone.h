#pragma once

#include <cstdint>

inline uint16_t Reverse16(uint16_t number) {
    return (number << 8) | (number >> 8);
}

inline uint32_t Reverse32(uint32_t number) {
    return ((number & 0xFF) << 24) | ((number & 0xFF00) << 8) | ((number & 0xFF0000) >> 8) | (number >> 24);
}