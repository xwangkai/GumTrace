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

struct TRACE_PAUSE_CALL_CONFIG {
    bool enabled = false;
    uintptr_t callsite_offset = 0;
    uintptr_t callee_offset = 0;
};

struct TRACE_PAUSE_CALL_STATE {
    bool active = false;
    uintptr_t return_address = 0;
    uintptr_t return_sp = 0;
};

struct TRACE_BREADCRUMB {
    uintptr_t pc = 0;
    uintptr_t module_base = 0;
    uint64_t insn_id = 0;
    char mnemonic[32] = {};
};

class GumTrace {
public:
    static GumTrace *get_instance();
    std::map<std::string, std::map<std::string, std::size_t>> modules;
    char trace_file_path[256];
    std::ofstream trace_file;
    std::mutex trace_file_mutex;
    std::mutex callback_state_mutex;
    std::atomic<bool> flush_thread_running{false};
    pthread_t flush_thread{};
    int trace_thread_id;
    int trace_flush = 0;
    std::unordered_map<size_t, std::string> func_maps;
    std::unordered_map<size_t, std::string> resolved_cache;  // 运行时解析缓存 add

    FUNC_CONTEXT last_func_context = {};

    GumStalker* _stalker;
    GumStalkerTransformer* _transformer;
    GumEventSink* _event_sink = nullptr;

    CallbackContext* callback_context_instance;

    static void transform_callback(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data);
    const std::string* in_range_module(size_t address);
    const RangeInfo* find_range_by_address(uintptr_t addr);
    const std::map<std::string, std::size_t>& get_module_by_name(const std::string &module_name);
    void follow();
    void unfollow();

    static void callout_callback(GumCpuContext *cpu_context, gpointer user_data);
    static void event_sink_callback(const GumEvent *event, GumCpuContext *cpu_context, gpointer user_data);

    char buffer[BUFFER_SIZE] = {};
    int buffer_offset = 0;
    REG_LIST write_reg_list;

    GUM_OPTIONS options;
    std::vector<RangeInfo> safa_ranges;
    TRACE_PAUSE_CALL_CONFIG pause_call_config;
    TRACE_PAUSE_CALL_STATE pause_call_state;

    std::unordered_map<size_t, std::string> svc_func_maps;
    std::unordered_map<size_t, std::string> func_fds;

    uintptr_t atomic_addr = 0;
    int atomic_width = 0;
    uintptr_t atomic_counter = 10;

    static gchar *resolve_symbol_safe(gpointer raw_addr);
    bool should_pause_trace_for_call(const GumCpuContext *cpu_context, uintptr_t module_base, uint64_t insn_id, __uint128_t jump_addr);
    bool is_trace_paused_for_call(const GumCpuContext *cpu_context);
    void resume_trace_after_call();
    void configure_pause_trace_call(uintptr_t callsite_offset, uintptr_t callee_offset);

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
