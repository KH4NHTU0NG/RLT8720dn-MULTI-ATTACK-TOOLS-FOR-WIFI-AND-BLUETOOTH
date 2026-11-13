#include <Arduino.h>
#include "security_utils.h"

#include <cstdio>
#include <cstring>

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define ASSERT_TRUE(cond)                                                          \
    do {                                                                           \
        g_tests_run++;                                                             \
        if (!(cond)) {                                                             \
            g_tests_failed++;                                                      \
            std::fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                          \
    } while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_STREQ(actual_str, expected_cstr)                                      \
    do {                                                                             \
        g_tests_run++;                                                               \
        String _act = (actual_str);                                                  \
        const char* _exp = (expected_cstr);                                          \
        if (_act != _exp) {                                                          \
            g_tests_failed++;                                                        \
            std::fprintf(stderr,                                                     \
                         "FAIL [%s:%d]: expected \"%s\", got \"%s\"\n",              \
                         __FILE__, __LINE__, _exp ? _exp : "(null)", _act.c_str()); \
        }                                                                            \
    } while (0)

#define ASSERT_EQ_INT(actual_val, expected_val)                                    \
    do {                                                                           \
        g_tests_run++;                                                             \
        long long _a = static_cast<long long>(actual_val);                         \
        long long _e = static_cast<long long>(expected_val);                       \
        if (_a != _e) {                                                            \
            g_tests_failed++;                                                      \
            std::fprintf(stderr, "FAIL [%s:%d]: expected %lld, got %lld\n",        \
                         __FILE__, __LINE__, _e, _a);                              \
        }                                                                          \
    } while (0)

static void test_html_escape() {
    ASSERT_STREQ(htmlEscape(""), "");
    ASSERT_STREQ(htmlEscape("FreeWiFi_5G"), "FreeWiFi_5G");
    ASSERT_STREQ(htmlEscape("<script>alert(1)</script>"),
                 "&lt;script&gt;alert(1)&lt;/script&gt;");
    ASSERT_STREQ(htmlEscape("A\"'&<>B"),
                 "A&quot;&#39;&amp;&lt;&gt;B");
    ASSERT_STREQ(htmlEscape("'\" onfocus=\"alert(document.cookie)\""),
                 "&#39;&quot; onfocus=&quot;alert(document.cookie)&quot;");
}

static void test_url_decode() {
    ASSERT_STREQ(urlDecode(""), "");
    ASSERT_STREQ(urlDecode("AA%3ABB%3ACC%3A11%3A22%3A33"), "AA:BB:CC:11:22:33");
    ASSERT_STREQ(urlDecode("My+Home+WiFi"), "My Home WiFi");
    ASSERT_STREQ(urlDecode("SSID1%0ASSID2%0d%0a"), "SSID1\nSSID2\r\n");
    // Null byte (%00) must be dropped to block C-string truncation injection
    ASSERT_STREQ(urlDecode("prefix%00injected"), "prefixinjected");
    // Malformed or truncated percent sequences remain literal without OOB reads
    ASSERT_STREQ(urlDecode("abc%"), "abc%");
    ASSERT_STREQ(urlDecode("abc%A"), "abc%A");
    ASSERT_STREQ(urlDecode("abc%ZZ123"), "abc%ZZ123");
}

static void test_ble_device_name_parser() {
    ASSERT_STREQ(parseBleDeviceName(nullptr, 0), "[Unknown]");
    uint8_t dummy = 0;
    ASSERT_STREQ(parseBleDeviceName(&dummy, 0), "[Unknown]");

    // Valid AD flags + Complete Local Name (0x09)
    {
        const uint8_t raw[] = {0x02, 0x01, 0x06, 0x06, 0x09, 'B', 'W', '1', '6', 'A'};
        uint8_t* heap_adv = new uint8_t[sizeof(raw)];
        std::memcpy(heap_adv, raw, sizeof(raw));
        ASSERT_STREQ(parseBleDeviceName(heap_adv, sizeof(raw)), "BW16A");
        delete[] heap_adv;
    }

    // Valid Shortened Local Name (0x08)
    {
        const uint8_t raw[] = {0x05, 0x08, 'T', 'e', 's', 't'};
        ASSERT_STREQ(parseBleDeviceName(raw, sizeof(raw)), "Test");
    }

    // ad_len == 0 must break immediately without infinite loop
    {
        const uint8_t raw[] = {0x00, 0x09, 'X'};
        ASSERT_STREQ(parseBleDeviceName(raw, sizeof(raw)), "[Unknown]");
    }

    // ad_len == 1 with 0x09 (previously caused unsigned underflow / OOB read)
    {
        uint8_t* heap_adv = new uint8_t[2]{0x01, 0x09};
        ASSERT_STREQ(parseBleDeviceName(heap_adv, 2), "[Unknown]");
        delete[] heap_adv;
    }

    // Truncated TLV where offset + 1 + ad_len exceeds buffer length
    {
        uint8_t* heap_adv = new uint8_t[4]{0x10, 0x09, 'A', 'B'};
        ASSERT_STREQ(parseBleDeviceName(heap_adv, 4), "[Unknown]");
        delete[] heap_adv;
    }

    // Trailing single byte TLV header (offset + 1 >= len)
    {
        uint8_t* heap_adv = new uint8_t[1]{0x05};
        ASSERT_STREQ(parseBleDeviceName(heap_adv, 1), "[Unknown]");
        delete[] heap_adv;
    }

    // Long name (39 bytes) must be truncated cleanly to 31 bytes without stack overflow
    {
        uint8_t adv[41];
        adv[0] = 40;
        adv[1] = 0x09;
        std::memset(&adv[2], 'Z', 39);
        String parsed = parseBleDeviceName(adv, sizeof(adv));
        ASSERT_EQ_INT(parsed.length(), 31);
        ASSERT_STREQ(parsed, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
    }
}

int main() {
    std::printf("Running RTL8720dn security unit tests...\n");
    test_html_escape();
    test_url_decode();
    test_ble_device_name_parser();
    if (g_tests_failed > 0) {
        std::fprintf(stderr, "FAILED: %d / %d assertions\n", g_tests_failed, g_tests_run);
        return 1;
    }
    std::printf("PASSED: %d assertions\n", g_tests_run);
    return 0;
}
