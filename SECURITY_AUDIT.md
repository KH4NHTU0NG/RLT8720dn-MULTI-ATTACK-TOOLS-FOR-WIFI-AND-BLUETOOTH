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

## 3. Remediation Status

| ID | Status | Implemented Control |
| :--- | :--- | :--- |
| SEC-01 | Fixed | Replaced VLA `uint8_t val[len]` in `/blewrite` with fixed buffer `val[MAX_BLE_WRITE_BYTES]` (512 bytes) decoded via `decodeHexPayload`, plus `pClient` and `pConn` null checks and `(uint16_t)` length match. |
| SEC-02 | Fixed | Added `htmlEscape()` helper and applied HTML character escaping (`& < > " '`) across Wi-Fi SSID rows (`renderScanRow`), BLE device names/MACs, and added `type="button"` on non-submit action buttons. |
| SEC-03 | Fixed | Replaced raw BLE AD length indexing in `bleScanCallback` with bounds-checked `parseBleDeviceName()`, guarded null `p_data` pointers, and replaced `sprintf` with `snprintf` for `mac_str`. |
| SEC-04 | Fixed | Replaced in-place SDK struct mutation (`record->SSID.val[len] = 0`) with `sanitizeSsid()` copy and capped `scan_results` at `MAX_SCAN_RESULTS` (64). |
| SEC-05 | Fixed | Pre-allocated HTTP request buffer (`request.reserve(1024)`), enforced `MAX_HTTP_REQ_SIZE` (4096) with HTTP `413 Payload Too Large` rejection, and added bounded 250 ms TCP read loop with `Content-Length` tracking. |
| SEC-06 | Fixed | Standardized RFC 9112 CRLF headers (`buildHttpResponseHeaders`), RFC 9110 `303 See Other` redirects with `\r\n\r\n` (`buildHttpRedirectHeaders`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `urlDecode()` with `%00` null-byte stripping in `parsePost`. |
| SEC-07 | Fixed | Added `static volatile bool sniffer_active` and extracted `_reset_all_targets()` in `src/interference/interference.cpp` so `wifi_set_promisc(0, NULL, 0)` always disarms RX callbacks before freeing `payload` or activating synthetic fallback. |
| SEC-08 | Fixed | Added null-pointer and length bounds (`1..1536`) in `wifi_tx_raw_frame`, `i < 32` SSID bounds in `wifi_tx_beacon_frame` and `wifi_tx_beacon_csa_frame`, and null guards in `wifi_tx_auth_frame`, `wifi_tx_assoc_frame`, and `wifi_tx_null_frame`. |
| SEC-09 | Partially Fixed | Eliminated idle `wext_set_channel` WLAN driver hammering via state tracking (`channel_needs_restore`, `last_idle_channel`, `delay(2)`), converted SoftAP `ssid`/`pass` to `const char*` with CWE-798 warning. Credential rotation and Web UI auth/CSRF remain deployment hardening items. |
| SEC-10 | Fixed | Replaced all `sprintf` calls in `src/oled/oled_display.cpp` (`_draw_footer`, `_draw_big_num`, `oled_show_idle`, `oled_show_deauth`, `oled_show_interference`, `oled_show_spammer`) with `snprintf(..., sizeof(buf), ...)`. |
| SEC-11 | Fixed | Capped `_networks` to `MAX_SPAM_NETWORKS` (64) in `SSIDSpammer::addSSID`, guarded `bssid == nullptr` and clamped SSID IE length to `MAX_SSID_LEN` in `_craftAndSend`. |
| SEC-12 | Fixed | Added `clampRssiPercent()` `[0, 100]` CSS clamp in `renderScanRow` and full `BLE.configScan()->stopScan()`, `BLE.setScanCallback(nullptr)`, and `BLE.end()` teardown after `/blescan` and `/blewrite`. |

---

## 4. Host Verification (ASan & UBSan)

Because `arduino-cli` and an RTL8720DN hardware target were not connected during this host audit, security utility logic and buffer-boundary controls were compiled and verified locally on macOS using a lightweight `Arduino.h` `String` mock (`tests/mock/Arduino.h`) with AddressSanitizer and UndefinedBehaviorSanitizer enabled:

```sh
clang++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -Itests/mock -IRTL8720dn-Deauther/src/security \
  tests/test_security_fixes.cpp -o tests/bin/test_security_fixes && \
  ./tests/bin/test_security_fixes
```

Verified result: `PASSED: 59 assertions` with zero compiler warnings and zero ASan/UBSan violations across `htmlEscape`, `urlDecode` (`%00` blocking & OOB percent parsing), `parseBleDeviceName` (heap-allocated malformed/underflow/truncated TLV payloads), `decodeHexPayload` (odd/non-hex/oversized inputs), `sanitizeSsid` (heap-allocated non-NUL-terminated 32-byte SSIDs), `clampRssiPercent`, and RFC 9110/9112 HTTP headers.
