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

#endif // SECURITY_UTILS_H
