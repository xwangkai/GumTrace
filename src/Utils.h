//
// Created by lidongyooo on 2026/2/6.
//

#ifndef GUMTRACE_UTILS_H
#define GUMTRACE_UTILS_H
// #include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <array>
#include <sstream>
#include <atomic>
#include <mutex>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "platform.h"
#include <pthread.h>
#include <sys/stat.h>

#define LOG_TAG "gumtrace"

#if PLATFORM_IOS

#include "../libs/FridaGum-IOS-17.15.2.h"
#include <Foundation/Foundation.h>
#define LOGE(fmt, ...) NSLog(@"[ERROR] %s: " @fmt, LOG_TAG, ##__VA_ARGS__)

#else

#include "../libs/FridaGum-Android-17.15.2.h"
#include <jni.h>
#include <android/log.h>
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__)

#endif

#define PAGE_SIZE 4096

#define PAGE_ALIGN_DOWN(addr) \
((uintptr_t)(addr) & ~(SYSTEM_PAGE_SIZE - 1))

#define PAGE_ALIGN_UP(addr) \
(((uintptr_t)(addr) + SYSTEM_PAGE_SIZE - 1) & ~(SYSTEM_PAGE_SIZE - 1))

extern const std::vector<std::string> svc_names;
extern const std::vector<std::string> jni_func_names;

class Utils {
public:
    static std::vector<std::string> str_split(const std::string& s, char symbol);
    static bool is_lse(cs_insn *insn);
    static bool is_exclusive_load(cs_insn *insn);
    static int get_data_width(cs_insn *insn, cs_arm64 *arm64);
    static bool get_register_value(arm64_reg reg, _GumArm64CpuContext *ctx, __uint128_t &value);
    static void format_uint128_hex(__uint128_t value, int& counter, char* buff);
    static void auto_snprintf(int& counter, char* buff, const char* __restrict __format, ...);

    static inline void append_string(char* buff, int& counter, const char* str, int capacity = 1024 * 1024 * 50) {
        if (!str) return;
        while (*str && counter < capacity - 1) {
            buff[counter++] = *str++;
        }
        if (counter >= 0 && counter < capacity) {
            buff[counter] = '\0';
        }
    }
    
    static inline void append_char(char* buff, int& counter, char c, int capacity = 1024 * 1024 * 50) {
        if (counter < capacity - 1) {
            buff[counter++] = c;
            buff[counter] = '\0';
        }
    }

    static void append_uint64_hex(char* buff, int& counter, uint64_t val);
    static void append_uint64_hex_fixed(char* buff, int& counter, uint64_t val);

    static inline uintptr_t apply_shift(__uint128_t value, arm64_shifter type, unsigned int amount) {
        uintptr_t val = (uintptr_t)value;
        switch (type) {
            case ARM64_SFT_LSL:
                return val << amount;
            case ARM64_SFT_LSR:
                return val >> amount;
            case ARM64_SFT_ASR:
                return (uintptr_t)((intptr_t)val >> amount);
            case ARM64_SFT_ROR:
                return (val >> amount) | (val << (64 - amount));
            case ARM64_SFT_MSL:
                return (val << amount) | ((1ULL << amount) - 1);
            default:
                return val;
        }
    }
};


#endif //GUMTRACE_UTILS_H
