# Security Audit & Pentest Debug Report

Target Repository: `KH4NHTU0NG/RLT8720dn-MULTI-ATTACK-TOOLS-FOR-WIFI-AND-BLUETOOTH`

## 1. Executive Summary

A comprehensive static security assessment (SAST) and memory-safety review was conducted across `RTL8720dn-Deauther.ino`, `src/oled/oled_display.cpp`, `src/interference/interference.cpp`, `src/packet-injection/packet-injection.cpp`, and `src/spammer/spammer.cpp`.

The audit identified **1 Critical**, **4 High**, **4 Medium**, and **3 Low** severity vulnerabilities affecting device memory safety (stack/heap overflows, out-of-bounds reads, Use-After-Free race conditions), Web UI security (Stored/Reflected XSS, missing CSRF/Auth, HTTP DoS), and firmware stability.

---

## 2. Findings Matrix

| ID | Severity | CWE | Location | Issue Description |
| :--- | :--- | :--- | :--- | :--- |
| SEC-01 | Critical | CWE-121 / CWE-770 | `RTL8720dn-Deauther.ino:880-887` | Stack buffer overflow via unbounded Variable-Length Array (`uint8_t val[len]`) in `/blewrite` controlled by HTTP POST `data` parameter, without hex validation. |
| SEC-02 | High | CWE-79 | `RTL8720dn-Deauther.ino:287,309,336,338` | Stored/Reflected Cross-Site Scripting (XSS) when rendering untrusted 802.11 SSIDs and BLE device names directly into HTML and inline JS `onclick` attributes. |
| SEC-03 | High | CWE-125 / CWE-190 | `RTL8720dn-Deauther.ino:100-116` | Out-of-bounds read and `uint8_t` offset wrap-around in `bleScanCallback` when parsing malformed BLE advertisement length fields. |
| SEC-04 | High | CWE-193 / CWE-400 | `RTL8720dn-Deauther.ino:128-144` | Off-by-one write (`record->SSID.val[record->SSID.len] = 0`) and unbounded `scan_results` vector growth risking heap exhaustion. |
| SEC-05 | High | CWE-400 / CWE-770 | `RTL8720dn-Deauther.ino:699-702` | Unbounded HTTP request read into `String` causing heap fragmentation / OOM DoS and truncated POST bodies over slow TCP segments. |
| SEC-06 | Medium | CWE-113 / RFC 9112 | `RTL8720dn-Deauther.ino:211-222,857-864` | Non-compliant `\n` HTTP line endings, missing `\r\n\r\n` header terminator in `makeRedirect`, and missing URL-decoding in `parsePost`. |
| SEC-07 | Medium | CWE-362 / CWE-416 | `interference.cpp:138-182,294-306` | Asynchronous `_beacon_sniffer_cb` callback races with `free(t->payload)` on stop/timeout, causing Use-After-Free risk. |
| SEC-08 | Medium | CWE-121 / CWE-476 | `packet-injection.cpp:10-78,151-210` | Missing null-pointer checks (`rltk_wlan_info`, `src_mac`, `dst_mac`, `ssid`) and unbounded SSID length copy in `wifi_tx_beacon_frame` and `wifi_tx_beacon_csa_frame`. |
| SEC-09 | Medium | CWE-798 / CWE-306 | `RTL8720dn-Deauther.ino:50-51,707-917` | Hardcoded weak default SoftAP passphrase (`0123456789`), no Web UI authentication or CSRF protection, and idle `wext_set_channel` hammering on every `loop()` tick. |
| SEC-10 | Low | CWE-120 | `oled_display.cpp:295,305,366,442` | Unbounded `sprintf` calls into small fixed stack buffers (`buf[12]`, `buf[16]`, `buf[24]`). |
| SEC-11 | Low | CWE-400 / CWE-120 | `spammer.cpp:14-20,93-133` | Unbounded `_networks` vector growth in `addSSID` and unchecked frame buffer offset in `_craftAndSend`. |
| SEC-12 | Low | CWE-20 | `RTL8720dn-Deauther.ino:290,312,848-894` | Unclamped CSS RSSI bar width (`rssi + 120` can be negative or > 100%) and missing `BLE.end()` cleanup after `/blescan` and `/blewrite`. |

---

## 3. Remediation Plan

1. Extract reusable input sanitizers, bounds-checked parsers, and validation helpers into `RTL8720dn-Deauther/src/security/security_utils.h`.
2. Patch all identified vulnerabilities atomically across `.ino` and `src/` modules.
3. Implement a host-side C++17 unit test suite (`tests/test_security_fixes.cpp`) compiled with `-fsanitize=address,undefined` to verify all security controls and edge cases.
