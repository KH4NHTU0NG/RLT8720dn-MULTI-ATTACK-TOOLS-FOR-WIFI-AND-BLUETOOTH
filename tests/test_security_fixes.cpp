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

int main() {
    std::printf("Running RTL8720dn security unit tests...\n");
    if (g_tests_failed > 0) {
        std::fprintf(stderr, "FAILED: %d / %d assertions\n", g_tests_failed, g_tests_run);
        return 1;
    }
    std::printf("PASSED: %d assertions\n", g_tests_run);
    return 0;
}
