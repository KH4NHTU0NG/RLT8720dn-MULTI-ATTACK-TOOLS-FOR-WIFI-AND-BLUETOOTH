#ifndef MOCK_ARDUINO_H
#define MOCK_ARDUINO_H

#include <cctype>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

class String {
public:
    String() = default;
    String(const char* s) : _s(s ? s : "") {}
    String(const std::string& s) : _s(s) {}
    String(int val) : _s(std::to_string(val)) {}
    String(unsigned int val) : _s(std::to_string(val)) {}
    String(long val) : _s(std::to_string(val)) {}
    String(unsigned long val) : _s(std::to_string(val)) {}

    void reserve(unsigned int size) { _s.reserve(size); }
    unsigned int length() const { return static_cast<unsigned int>(_s.size()); }
    const char* c_str() const { return _s.c_str(); }
    const std::string& std_str() const { return _s; }

    char operator[](unsigned int index) const {
        return (index < _s.size()) ? _s[index] : '\0';
    }

    String& operator+=(const String& rhs) {
        _s += rhs._s;
        return *this;
    }

    String& operator+=(const char* rhs) {
        if (rhs) _s += rhs;
        return *this;
    }

    String& operator+=(char c) {
        _s += c;
        return *this;
    }

    bool operator==(const String& rhs) const { return _s == rhs._s; }
    bool operator==(const char* rhs) const { return _s == (rhs ? rhs : ""); }
    bool operator!=(const String& rhs) const { return !(*this == rhs); }
    bool operator!=(const char* rhs) const { return !(*this == rhs); }

    int indexOf(const char* needle, unsigned int fromIndex = 0) const {
        if (!needle || fromIndex > _s.size()) return -1;
        size_t pos = _s.find(needle, fromIndex);
        return (pos == std::string::npos) ? -1 : static_cast<int>(pos);
    }

    String substring(unsigned int left) const {
        if (left >= _s.size()) return String("");
        return String(_s.substr(left));
    }

    String substring(unsigned int left, unsigned int right) const {
        if (left > right) std::swap(left, right);
        if (left >= _s.size()) return String("");
        return String(_s.substr(left, right - left));
    }

    void trim() {
        size_t start = 0;
        while (start < _s.size() && std::isspace(static_cast<unsigned char>(_s[start]))) {
            start++;
        }
        size_t end = _s.size();
        while (end > start && std::isspace(static_cast<unsigned char>(_s[end - 1]))) {
            end--;
        }
        _s = _s.substr(start, end - start);
    }

    long toInt() const {
        return std::strtol(_s.c_str(), nullptr, 10);
    }

    friend String operator+(const String& lhs, const String& rhs) {
        return String(lhs._s + rhs._s);
    }

    friend String operator+(const char* lhs, const String& rhs) {
        return String(std::string(lhs ? lhs : "") + rhs._s);
    }

    friend String operator+(const String& lhs, const char* rhs) {
        return String(lhs._s + std::string(rhs ? rhs : ""));
    }

private:
    std::string _s;
};

static inline unsigned long millis() { return 0; }

#endif // MOCK_ARDUINO_H
