//
// Created by lidongyooo on 2026/2/6.
//

#ifndef GUMTRACE_GUMTRACE_H
#define GUMTRACE_GUMTRACE_H

#include "Utils.h"
#include "CallbackContext.h"

struct REG_LIST {
    int num = 0;
    arm64_reg regs[31] = {};
};


typedef enum {
    GUM_OPTIONS_MODE_Stand = 0,
    GUM_OPTIONS_MODE_DEBUG,
    GUM_OPTIONS_MODE_STABLE
} GUM_OPTIONS_MODE;

struct GUM_OPTIONS {
    uint64_t mode;
};

#define BUFFER_SIZE (1024 * 1024 * 50)

struct FUNC_CONTEXT {
    uint64_t address;
    const char* name;
    char info[BUFFER_SIZE];
    int info_n;
    bool call;
    bool is_jni;
    GumCpuContext cpu_context;
};

struct RangeInfo {
    uintptr_t base;
    uintptr_t size;
    uintptr_t end;
    std::string file_path;
};

class GumTrace {
public:
    static GumTrace *get_instance();
    std::map<std::string, std::map<std::string, std::size_t>> modules;
    char trace_file_path[256];
    std::ofstream trace_file;
    int trace_thread_id;
    int trace_flush = 0;
    std::unordered_map<size_t, std::string> func_maps;
    std::unordered_map<size_t, std::string> resolved_cache;  // 运行时解析缓存 add

    FUNC_CONTEXT last_func_context = {};

    GumStalker* _stalker;
    GumStalkerTransformer* _transformer;

    CallbackContext* callback_context_instance;

    static void transform_callback(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data);
    const std::string* in_range_module(size_t address);
    const RangeInfo* find_range_by_address(uintptr_t addr);
    const std::map<std::string, std::size_t>& get_module_by_name(const std::string &module_name);
    void follow();
    void unfollow();

    static void callout_callback(GumCpuContext *cpu_context, gpointer user_data);

    char buffer[BUFFER_SIZE] = {};
    int buffer_offset = 0;
    REG_LIST write_reg_list;

    struct CachedModule {
        const std::string* name;
        size_t base;
        size_t end;
    } last_module_cache;

    GUM_OPTIONS options;
    std::vector<RangeInfo> safa_ranges;

    std::unordered_map<size_t, std::string> svc_func_maps;
    std::unordered_map<size_t, std::string> func_fds;

    uintptr_t atomic_addr = 0;
    int atomic_width = 0;
    uintptr_t atomic_counter = 10;

#if PLATFORM_ANDROID
    JNIEnv *get_run_time_env();


    JavaVM *java_vm = nullptr;
    JNIEnv *jni_env = nullptr;
    bool jni_env_init = false;
    std::unordered_map<size_t, std::string> jni_func_maps;
    std::unordered_map<size_t, std::string> jni_classes;
    std::unordered_map<size_t, std::string> jni_methods;
    std::unordered_map<size_t, std::string> jni_methods_classes;
#    endif



private:
    GumTrace();

    ~GumTrace();

    GumTrace(const GumTrace &) = delete;

    GumTrace &operator=(const GumTrace &) = delete;
};


#endif //GUMTRACE_GUMTRACE_H
