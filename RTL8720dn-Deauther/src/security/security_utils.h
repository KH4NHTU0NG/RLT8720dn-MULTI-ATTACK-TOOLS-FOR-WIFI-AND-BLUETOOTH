#ifndef SECURITY_UTILS_H
#define SECURITY_UTILS_H

#include <Arduino.h>
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define MAX_SCAN_RESULTS    64
#define MAX_BLE_RESULTS     20
#define MAX_BLE_WRITE_BYTES 512
#define MAX_HTTP_REQ_SIZE   4096
#define MAX_SSID_BYTES      32

// Escape HTML/JS special characters to prevent Stored/Reflected XSS in Web UI.
static inline String htmlEscape(const String& input) {
    String out;
    out.reserve(input.length() + 16);
    for (unsigned int i = 0; i < input.length(); i++) {
        char c = input[i];
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;        break;
        }
    }
    return out;
}

// Convert a single ASCII hex digit to 0..15, or -1 if invalid.
static inline int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decode application/x-www-form-urlencoded values while blocking null-byte injection.
static inline String urlDecode(const String& src) {
    String out;
    out.reserve(src.length());
    unsigned int len = src.length();
    for (unsigned int i = 0; i < len; i++) {
        char c = src[i];
        if (c == '+') {
            out += ' ';
        } else if (c == '%' && (i + 2) < len) {
            int hi = hexNibble(src[i + 1]);
            int lo = hexNibble(src[i + 2]);
            if (hi >= 0 && lo >= 0) {
                char decoded = (char)((hi << 4) | lo);
                if (decoded != '\0') {
                    out += decoded;
                }
                i += 2;
                continue;
            }
            out += c;
        } else {
            out += c;
        }
    }
    return out;
}

#endif // SECURITY_UTILS_H
