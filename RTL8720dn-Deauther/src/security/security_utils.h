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

// Safely validate and decode a hex string into a caller-provided fixed buffer.
static inline bool decodeHexPayload(const String& hex_data, uint8_t* out_buf, size_t max_out_len, size_t* out_len) {
    if (!out_buf || !out_len || max_out_len == 0) return false;
    *out_len = 0;

    unsigned int slen = hex_data.length();
    if (slen == 0 || (slen % 2) != 0) return false;

    size_t byte_len = slen / 2;
    if (byte_len > max_out_len) return false;

    for (size_t i = 0; i < byte_len; i++) {
        int hi = hexNibble(hex_data[i * 2]);
        int lo = hexNibble(hex_data[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out_buf[i] = (uint8_t)((hi << 4) | lo);
    }

    *out_len = byte_len;
    return true;
}

// Safely parse Complete/Shortened Local Name from BLE advertising payload with strict bounds checks.
static inline String parseBleDeviceName(const uint8_t* p_adv, size_t len) {
    if (!p_adv || len == 0) return String("[Unknown]");

    size_t offset = 0;
    while (offset < len) {
        uint8_t ad_len = p_adv[offset];
        if (ad_len == 0) break;
        if (offset + 1 >= len) break;
        if (offset + 1 + (size_t)ad_len > len) break;

        uint8_t ad_type = p_adv[offset + 1];
        if ((ad_type == 0x09 || ad_type == 0x08) && ad_len >= 2) {
            char name_buf[32];
            size_t name_len = (size_t)(ad_len - 1);
            if (name_len > sizeof(name_buf) - 1) {
                name_len = sizeof(name_buf) - 1;
            }
            memcpy(name_buf, &p_adv[offset + 2], name_len);
            name_buf[name_len] = '\0';
            return String(name_buf);
        }
        offset += (size_t)ad_len + 1;
    }
    return String("[Unknown]");
}

#endif // SECURITY_UTILS_H
