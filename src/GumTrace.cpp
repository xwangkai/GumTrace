//
// Created by lidongyooo on 2026/2/6.
//

#include "GumTrace.h"
#include "Utils.h"
#include "FuncPrinter.h"
#include <cstdio>
#include <dlfcn.h>
#include <sys/mman.h>

static thread_local TRACE_BREADCRUMB g_trace_breadcrumb;

namespace {
constexpr bool kMinimalStalkerOnlyMode = false;
constexpr bool kMinimalNoopCalloutMode = false;
constexpr bool kMinimalEventSinkExecMode = false;
constexpr bool kMinimalInstructionTraceMode = false;
constexpr bool kSelectiveCalloutMode = false;

static uint64_t get_current_tid_safe() {
    return static_cast<uint64_t>(syscall(SYS_gettid));
}

struct TraceFpSnapshot {
    bool initialized = false;
    uint64_t last_sequence = 0;
    uintptr_t last_pc = 0;
    uintptr_t last_fp = 0;
};

static thread_local TraceFpSnapshot g_trace_fp_snapshot;

static bool is_block_trace_mode(const GumTrace *self) {
    return self != nullptr && self->options.mode == GUM_OPTIONS_MODE_BLOCK;
}

static bool is_full_callout_probe_mode(const GumTrace *self) {
    return !is_block_trace_mode(self);
}

const char *get_reg_name_safe(arm64_reg reg) {
    static const char *kWRegs[] = {
        "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
        "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
        "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
        "w24", "w25", "w26", "w27", "w28", "w29", "w30"
    };
    static const char *kXRegs[] = {
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28"
    };
    static const char *kQRegs[] = {
        "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
        "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15",
        "q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23",
        "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31"
    };
    static const char *kDRegs[] = {
        "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
        "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
        "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
        "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31"
    };
    static const char *kSRegs[] = {
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
        "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
        "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
        "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31"
    };
    static const char *kHRegs[] = {
        "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7",
        "h8", "h9", "h10", "h11", "h12", "h13", "h14", "h15",
        "h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23",
        "h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31"
    };
    static const char *kBRegs[] = {
        "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
        "b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15",
        "b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
        "b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31"
    };
    static const char *kVRegs[] = {
        "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
        "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
        "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
        "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    };
    static thread_local char fallback[32];

    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
        return kWRegs[reg - ARM64_REG_W0];
    }
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        return kXRegs[reg - ARM64_REG_X0];
    }
    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) {
        return kQRegs[reg - ARM64_REG_Q0];
    }
    if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) {
        return kDRegs[reg - ARM64_REG_D0];
    }
    if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) {
        return kSRegs[reg - ARM64_REG_S0];
    }
    if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
        return kHRegs[reg - ARM64_REG_H0];
    }
    if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
        return kBRegs[reg - ARM64_REG_B0];
    }
    if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) {
        return kVRegs[reg - ARM64_REG_V0];
    }

    switch (reg) {
        case ARM64_REG_SP:
            return "sp";
        case ARM64_REG_WSP:
            return "wsp";
        case ARM64_REG_FP:
            return "fp";
        case ARM64_REG_LR:
            return "lr";
        case ARM64_REG_XZR:
            return "xzr";
        case ARM64_REG_WZR:
            return "wzr";
        case ARM64_REG_NZCV:
            return "nzcv";
        case ARM64_REG_INVALID:
            return "invalid";
        default:
            snprintf(fallback, sizeof(fallback), "reg_%d", reg);
            return fallback;
    }
}
}

GumTrace *GumTrace::get_instance() {
    static GumTrace instance;
    return &instance;
}

GumTrace::GumTrace() {
    _transformer = gum_stalker_transformer_make_from_callback(transform_callback, nullptr, nullptr);
    callback_context_instance = CallbackContext::get_instance();
}

GumTrace::~GumTrace() {
    if (_stalker) g_object_unref(_stalker);
    if (_transformer) g_object_unref(_transformer);
    if (_event_sink) g_object_unref(_event_sink);
}

void GumTrace::configure_pause_trace_call(uintptr_t callsite_offset, uintptr_t callee_offset) {
    pause_call_config.enabled = callsite_offset != 0 && callee_offset != 0;
    pause_call_config.callsite_offset = callsite_offset;
    pause_call_config.callee_offset = callee_offset;
    pause_call_state.active = false;
    pause_call_state.return_address = 0;
    pause_call_state.return_sp = 0;
}

void GumTrace::configure_single_callout(uintptr_t instruction_offset) {
    single_callout_config.enabled = instruction_offset != 0;
    single_callout_config.instruction_offset = instruction_offset;
}

void GumTrace::configure_block_trace_range(uintptr_t function_offset, uintptr_t function_size) {
    block_trace_config.enabled = function_offset != 0 && function_size != 0;
    block_trace_config.start_offset = function_offset;
    block_trace_config.end_offset = function_offset + function_size;
}

bool GumTrace::should_pause_trace_for_call(const GumCpuContext *cpu_context,
                                           uintptr_t module_base,
                                           uint64_t insn_id,
                                           __uint128_t jump_addr) {
    if (!pause_call_config.enabled || pause_call_state.active) {
        return false;
    }

    if (insn_id != ARM64_INS_BL) {
        return false;
    }

    uintptr_t pc = cpu_context->pc;
    uintptr_t pc_offset = pc - module_base;
    if (pc_offset != pause_call_config.callsite_offset) {
        return false;
    }

    uintptr_t target_offset = (uintptr_t) jump_addr - module_base;
    if (target_offset != pause_call_config.callee_offset) {
        return false;
    }

    pause_call_state.active = true;
    pause_call_state.return_address = cpu_context->lr;
    pause_call_state.return_sp = cpu_context->sp;
    return true;
}

bool GumTrace::is_trace_paused_for_call(const GumCpuContext *cpu_context) {
    if (!pause_call_state.active) {
        return false;
    }

    if (cpu_context->pc == pause_call_state.return_address &&
        cpu_context->sp == pause_call_state.return_sp) {
        resume_trace_after_call();
        return false;
    }

    return true;
}

void GumTrace::resume_trace_after_call() {
    pause_call_state.active = false;
    pause_call_state.return_address = 0;
    pause_call_state.return_sp = 0;
}

#if PLATFORM_ANDROID
JNIEnv *GumTrace::get_run_time_env() {
    return nullptr;
}
#endif

gchar * GumTrace::resolve_symbol_safe(gpointer raw_addr) {
    if (raw_addr == nullptr) {
        return nullptr;
    }

    gpointer stripped = gum_strip_code_pointer(GSIZE_TO_POINTER(raw_addr));

    /*
    gchar *name = gum_symbol_name_from_address(stripped);
    if (name) {
        return name;  // 直接返回，调用方负责 g_free
    }

    GumDebugSymbolDetails details;
    if (gum_symbol_details_from_address(stripped, &details)) {
        return g_strdup_printf("%s+0x%lx",
                               details.module_name,
                               (uint64_t)stripped - (uint64_t)details.address);
    }*/

    gpointer page = (gpointer)((uintptr_t)raw_addr & ~0xFFFULL);
    if(!(msync(page, 1, MS_ASYNC) == 0)){
        return nullptr;
    }

    Dl_info info;
    if (dladdr(stripped, &info)) {
        if (info.dli_sname) {
            // 有符号名
            return g_strdup(info.dli_sname);
        }

        if (info.dli_fname) {
            // 没有符号名，返回 模块名+偏移
            return g_strdup_printf("%s+0x%lx",
                                   info.dli_fname,
                                   (uint64_t)stripped - (uint64_t)info.dli_saddr);
        }

        GumDebugSymbolDetails details;
        if (gum_symbol_details_from_address(stripped, &details)) {
            return g_strdup_printf("%s+0x%lx",
                                details.module_name,
                                (uint64_t)stripped - (uint64_t)details.address);
        }
    }

    return nullptr;//g_strdup("");
}


void GumTrace::callout_callback(GumCpuContext *cpu_context, gpointer user_data) {
    auto self = get_instance();
    auto callback_ctx = (CALLBACK_CTX *)user_data;
    if (callback_ctx == nullptr) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(self->trace_file_mutex);
        if (self->trace_file.is_open()) {
            char line[512];
            int written = snprintf(
                line,
                sizeof(line),
                "[callout-enter] seq=%llu tid=%llu [%s] 0x%llx!0x%llx %s %s sp=0x%llx fp=0x%llx lr=0x%llx\n",
                (unsigned long long) callback_ctx->sequence,
                (unsigned long long) get_current_tid_safe(),
                callback_ctx->module_name != nullptr ? callback_ctx->module_name : "",
                (unsigned long long) cpu_context->pc,
                (unsigned long long) (cpu_context->pc - callback_ctx->module_base),
                callback_ctx->instruction.mnemonic,
                callback_ctx->instruction.op_str,
                (unsigned long long) cpu_context->sp,
                (unsigned long long) cpu_context->fp,
                (unsigned long long) cpu_context->lr);
            if (written > 0) {
                size_t safe_written = static_cast<size_t>(written);
                if (safe_written >= sizeof(line)) {
                    safe_written = sizeof(line) - 1;
                }
                self->trace_file.write(line, static_cast<std::streamsize>(safe_written));
                self->trace_file.flush();
            }
        }
    }

    if (is_full_callout_probe_mode(self)) {
        const uintptr_t current_fp = static_cast<uintptr_t>(cpu_context->fp);
        const bool fp_just_became_zero = g_trace_fp_snapshot.initialized &&
            g_trace_fp_snapshot.last_fp != 0 &&
            current_fp == 0;

        if (fp_just_became_zero) {
            std::lock_guard<std::mutex> lock(self->trace_file_mutex);
            if (self->trace_file.is_open()) {
                char line[512];
                int written = snprintf(
                    line,
                    sizeof(line),
                    "[fp-zero-transition] tid=%llu prev_seq=%llu prev_pc=0x%llx cur_seq=%llu cur_pc=0x%llx lr=0x%llx sp=0x%llx\n",
                    (unsigned long long) get_current_tid_safe(),
                    (unsigned long long) g_trace_fp_snapshot.last_sequence,
                    (unsigned long long) g_trace_fp_snapshot.last_pc,
                    (unsigned long long) callback_ctx->sequence,
                    (unsigned long long) cpu_context->pc,
                    (unsigned long long) cpu_context->lr,
                    (unsigned long long) cpu_context->sp);
                if (written > 0) {
                    size_t safe_written = static_cast<size_t>(written);
                    if (safe_written >= sizeof(line)) {
                        safe_written = sizeof(line) - 1;
                    }
                    self->trace_file.write(line, static_cast<std::streamsize>(safe_written));
                    self->trace_file.flush();
                }
            }
        }

        g_trace_fp_snapshot.initialized = true;
        g_trace_fp_snapshot.last_sequence = callback_ctx->sequence;
        g_trace_fp_snapshot.last_pc = static_cast<uintptr_t>(cpu_context->pc);
        g_trace_fp_snapshot.last_fp = current_fp;
    }

    if (kMinimalNoopCalloutMode || kSelectiveCalloutMode || is_full_callout_probe_mode(self)) {
        return;
    }

    if (kMinimalInstructionTraceMode) {
        char line[512];
        const char *mnemonic = callback_ctx->instruction.mnemonic[0] != '\0'
            ? callback_ctx->instruction.mnemonic
            : "";
        const char *op_str = callback_ctx->instruction.op_str[0] != '\0'
            ? callback_ctx->instruction.op_str
            : "";
        int written = snprintf(
            line,
            sizeof(line),
            "[%s] 0x%llx!0x%llx %s %s\n",
            callback_ctx->module_name != nullptr ? callback_ctx->module_name : "",
            (unsigned long long) cpu_context->pc,
            (unsigned long long) (cpu_context->pc - callback_ctx->module_base),
            mnemonic,
            op_str);
        if (written > 0) {
            size_t safe_written = static_cast<size_t>(written);
            if (safe_written >= sizeof(line)) {
                safe_written = sizeof(line) - 1;
            }

            std::lock_guard<std::mutex> lock(self->trace_file_mutex);
            if (self->trace_file.is_open()) {
                self->trace_file.write(line, static_cast<std::streamsize>(safe_written));
            }
        }
        return;
    }

    std::lock_guard<std::mutex> callback_lock(self->callback_state_mutex);
    g_trace_breadcrumb.pc = cpu_context->pc;
    g_trace_breadcrumb.module_base = callback_ctx->module_base;
    g_trace_breadcrumb.insn_id = callback_ctx->instruction.id;
    strncpy(g_trace_breadcrumb.mnemonic, callback_ctx->instruction.mnemonic, sizeof(g_trace_breadcrumb.mnemonic) - 1);
    g_trace_breadcrumb.mnemonic[sizeof(g_trace_breadcrumb.mnemonic) - 1] = '\0';
    char *buff = self->buffer;
    int &buff_n = self->buffer_offset;

    if (buff_n > BUFFER_SIZE - 1024) {
        std::lock_guard<std::mutex> lock(self->trace_file_mutex);
        self->trace_file.write(buff, buff_n);
        buff_n = 0;
    }

    if (self->write_reg_list.num > 0) {
        for (int i = 0; i < self->write_reg_list.num; i++) {
            __uint128_t reg_value = 0;
            if (Utils::get_register_value(self->write_reg_list.regs[i], cpu_context, reg_value)) {
                if (i == 0) {
                    Utils::append_string(buff, buff_n, "-> ");
                }

                const char *reg_name = get_reg_name_safe(self->write_reg_list.regs[i]);
                Utils::append_string(buff, buff_n, reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(reg_value, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }
        }

        Utils::append_char(buff, buff_n, '\n');
        self->write_reg_list.num = 0;
    }

    if (self->last_func_context.call) {
        if (buff_n > 0) {
            std::lock_guard<std::mutex> lock(self->trace_file_mutex);
            self->trace_file.write(buff, buff_n);
            buff_n = 0;
        }

        self->last_func_context.call = false;
#        if PLATFORM_ANDROID
        FuncPrinter::after(&self->last_func_context, cpu_context);
#        else

            FuncPrinter::after(&self->last_func_context, cpu_context);

#endif

        {
            std::lock_guard<std::mutex> lock(self->trace_file_mutex);
            self->trace_file.write(self->last_func_context.info, self->last_func_context.info_n);
        }
    }

    const bool trace_paused = self->is_trace_paused_for_call(cpu_context);
    if (trace_paused) {
        self->trace_flush++;
        if (self->options.mode == GUM_OPTIONS_MODE_DEBUG) {
            if (self->trace_flush > 20) {
                if (buff_n > 0) {
                    std::lock_guard<std::mutex> lock(self->trace_file_mutex);
                    self->trace_file.write(buff, buff_n);
                    buff_n = 0;
                }

                std::lock_guard<std::mutex> lock(self->trace_file_mutex);
                self->trace_file.flush();
                self->trace_flush = 0;
            }
        }
        return;
    }

    Utils::append_char(buff, buff_n, '[');
    Utils::append_string(buff, buff_n, callback_ctx->module_name);
    Utils::append_string(buff, buff_n, "] 0x");
    Utils::append_uint64_hex(buff, buff_n, cpu_context->pc);
    Utils::append_string(buff, buff_n, "!0x");
    Utils::append_uint64_hex(buff, buff_n, cpu_context->pc - callback_ctx->module_base);
    Utils::append_char(buff, buff_n, ' ');
    Utils::append_string(buff, buff_n, callback_ctx->instruction.mnemonic);
    Utils::append_char(buff, buff_n, ' ');
    Utils::append_string(buff, buff_n, callback_ctx->instruction.op_str);
    Utils::append_string(buff, buff_n, "; ");

    bool is_write = false;
    uintptr_t mem_r_addr = 0x0;
    for (int i = 0; i < callback_ctx->instruction_detail.arm64.op_count; i++) {
        cs_arm64_op &op = callback_ctx->instruction_detail.arm64.operands[i];
        __uint128_t reg_value = 0;
        if ((op.access & CS_AC_READ) && (op.access & CS_AC_WRITE) && op.type == ARM64_OP_REG) {
            if (Utils::get_register_value(op.reg, cpu_context, reg_value)) {

                const char *reg_name = get_reg_name_safe(op.reg);
                Utils::append_string(buff, buff_n, reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(reg_value, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }
            is_write = true;
            if (self->write_reg_list.num < (int)(sizeof(self->write_reg_list.regs) / sizeof(self->write_reg_list.regs[0]))) {
                self->write_reg_list.regs[self->write_reg_list.num++] = op.reg;
            }
        } else if (op.access & CS_AC_READ && op.type == ARM64_OP_REG) {
            if (Utils::get_register_value(op.reg, cpu_context, reg_value)) {

                const char *reg_name = get_reg_name_safe(op.reg);
                Utils::append_string(buff, buff_n, reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(reg_value, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }
        } else if ((op.access & CS_AC_WRITE) && (op.access & CS_AC_READ) && op.type == ARM64_OP_MEM) {
            __uint128_t base = 0;
            __uint128_t index = 0;
            bool flag = true;

            if (op.mem.base != ARM64_REG_INVALID) {
                flag = Utils::get_register_value(op.mem.base, cpu_context, base);
                const char *base_reg_name = get_reg_name_safe(op.mem.base);
                Utils::append_string(buff, buff_n, base_reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(base, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }

            if (op.mem.index != ARM64_REG_INVALID) {
                flag = Utils::get_register_value(op.mem.index, cpu_context, index);
                const char *index_reg_name = get_reg_name_safe(op.mem.index);
                Utils::append_string(buff, buff_n, index_reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(index, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }

            if (flag) {
                uintptr_t shifted_index = Utils::apply_shift(index, op.shift.type, op.shift.value);
                uintptr_t write_address = base + shifted_index + op.mem.disp;
                Utils::append_string(buff, buff_n, callback_ctx->instruction.mnemonic[0] == 'l' ? "mem_r=0x" : "mem_w=0x");
                Utils::append_uint64_hex(buff, buff_n, write_address);
                Utils::append_char(buff, buff_n, ' ');
            }

            if (strstr(callback_ctx->instruction.op_str, "],") || strstr(callback_ctx->instruction.op_str, "]!")) {
                is_write = true;
                if (self->write_reg_list.num < (int)(sizeof(self->write_reg_list.regs) / sizeof(self->write_reg_list.regs[0]))) {
                    self->write_reg_list.regs[self->write_reg_list.num++] = op.mem.base;
                }
            }
        }  else if ((op.access & CS_AC_WRITE) && op.type == ARM64_OP_MEM) {
            __uint128_t base = 0;
            __uint128_t index = 0;
            bool flag = true;

            if (op.mem.base != ARM64_REG_INVALID) {
                flag = Utils::get_register_value(op.mem.base, cpu_context, base);
                const char *base_reg_name = get_reg_name_safe(op.mem.base);
                Utils::append_string(buff, buff_n, base_reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(base, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }

            if (op.mem.index != ARM64_REG_INVALID) {
                flag = Utils::get_register_value(op.mem.index, cpu_context, index);
                const char *index_reg_name = get_reg_name_safe(op.mem.index);
                Utils::append_string(buff, buff_n, index_reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(index, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }

            if (flag) {
                uintptr_t shifted_index = Utils::apply_shift(index, op.shift.type, op.shift.value);
                uintptr_t write_address = base + shifted_index + op.mem.disp;
                Utils::append_string(buff, buff_n, "mem_w=0x");
                Utils::append_uint64_hex(buff, buff_n, write_address);
                Utils::append_char(buff, buff_n, ' ');
            }
        } else if ((op.access & CS_AC_READ) && op.type == ARM64_OP_MEM) {
            __uint128_t base = 0;
            __uint128_t index = 0;
            bool flag = true;

            if (op.mem.base != ARM64_REG_INVALID) {
                flag = Utils::get_register_value(op.mem.base, cpu_context, base);
                const char *base_reg_name = get_reg_name_safe(op.mem.base);
                Utils::append_string(buff, buff_n, base_reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(base, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }
            if (op.mem.index != ARM64_REG_INVALID) {
                flag = Utils::get_register_value(op.mem.index, cpu_context, index);
                const char *index_reg_name = get_reg_name_safe(op.mem.index);
                Utils::append_string(buff, buff_n, index_reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(index, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }
            if (flag) {
                uintptr_t shifted_index = Utils::apply_shift(index, op.shift.type, op.shift.value);
                uintptr_t read_address = base + shifted_index + op.mem.disp;
                mem_r_addr = read_address;
                Utils::append_string(buff, buff_n, "mem_r=0x");
                Utils::append_uint64_hex(buff, buff_n, read_address);
                Utils::append_char(buff, buff_n, ' ');
            }
        } else if (op.access & CS_AC_WRITE && op.type == ARM64_OP_REG) {
            if (Utils::get_register_value(op.reg, cpu_context, reg_value)) {

                const char *reg_name = get_reg_name_safe(op.reg);
                Utils::append_string(buff, buff_n, reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(reg_value, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }

            is_write = true;
            if (self->write_reg_list.num < (int)(sizeof(self->write_reg_list.regs) / sizeof(self->write_reg_list.regs[0]))) {
                self->write_reg_list.regs[self->write_reg_list.num++] = op.reg;
            }
        }
    }

    if (is_write == false) {
        Utils::append_char(buff, buff_n, '\n');
    }

    if (callback_ctx->instruction.id == ARM64_INS_SVC) {
        auto svc_it = self->svc_func_maps.find(cpu_context->x[8]);
        if (svc_it == self->svc_func_maps.end()) goto skip_call;
        self->last_func_context.info_n = 0;
        self->last_func_context.name = svc_it->second.c_str();
        memcpy(&self->last_func_context.cpu_context, cpu_context, sizeof(GumCpuContext));
        self->last_func_context.call = true;

        FuncPrinter::before(&self->last_func_context);
    } else {
        __uint128_t jump_addr = 0;
        if (callback_ctx->instruction.id == ARM64_INS_BL &&
            callback_ctx->instruction_detail.arm64.operands[0].type == ARM64_OP_IMM) {
            jump_addr = callback_ctx->instruction_detail.arm64.operands[0].imm;
        } else if (callback_ctx->instruction.id == ARM64_INS_BLR &&
                   callback_ctx->instruction_detail.arm64.operands[0].type == ARM64_OP_REG) {
            Utils::get_register_value(callback_ctx->instruction_detail.arm64.operands[0].reg, cpu_context, jump_addr);
        } else if (callback_ctx->instruction.id == ARM64_INS_BR &&
                   callback_ctx->instruction_detail.arm64.operands[0].type == ARM64_OP_REG) {
            Utils::get_register_value(callback_ctx->instruction_detail.arm64.operands[0].reg, cpu_context, jump_addr);
        } else if (callback_ctx->instruction.id == ARM64_INS_B &&
                   callback_ctx->instruction_detail.arm64.operands[0].type == ARM64_OP_IMM) {
            jump_addr = callback_ctx->instruction_detail.arm64.operands[0].imm;
        }

        if (jump_addr > 0) {
            if (self->should_pause_trace_for_call(cpu_context,
                                                  callback_ctx->module_base,
                                                  callback_ctx->instruction.id,
                                                  jump_addr)) {
                goto skip_call;
            }

            const std::string *sym_name = nullptr;
            if (self->func_maps.count(jump_addr) > 0) {
                sym_name = &self->func_maps[jump_addr];
                self->last_func_context.info_n = 0;
                self->last_func_context.address = jump_addr;
                self->last_func_context.name = sym_name->c_str();
                memcpy(&self->last_func_context.cpu_context, cpu_context, sizeof(GumCpuContext));
                self->last_func_context.call = true;

                FuncPrinter::before(&self->last_func_context);
            }
            else {
                // 2. 静态表没有 → 运行时动态解析
                const std::string *module_name_ptr = self->in_range_module(jump_addr);
                if (module_name_ptr == nullptr) {//排除本模块内的地址，不排除的话trace大小会很大
                    if (sym_name == nullptr) {
                        auto cache_it = self->resolved_cache.find(jump_addr);
                        if (cache_it != self->resolved_cache.end()) {
                            sym_name = &cache_it->second;
                        } else {
                            // 3. 缓存也没有 → 运行时动态解析
                            //    这里能正确处理懒加载已解析后的真实地址
                            /*gchar *name = gum_symbol_name_from_address((gpointer)(uintptr_t)jump_addr);
                            if (name != nullptr) {
                                self->resolved_cache[(size_t)jump_addr] = name;
                                sym_name = &self->resolved_cache[(size_t)jump_addr];
                                g_free(name);
                            }*/
                            gchar *name = GumTrace::resolve_symbol_safe((gpointer)(uintptr_t)jump_addr);
                            if (name != nullptr) {
                                self->resolved_cache[(size_t)jump_addr] = name;
                                sym_name = &self->resolved_cache[(size_t)jump_addr];
                                g_free(name);
                            }
                        }

                        if (sym_name != nullptr && !sym_name->empty()) {
                            self->last_func_context.info_n = 0;
                            self->last_func_context.address = jump_addr;
                            self->last_func_context.name = sym_name->c_str();
                            memcpy(&self->last_func_context.cpu_context, cpu_context, sizeof(GumCpuContext));
                            self->last_func_context.call = true;
                            FuncPrinter::before(&self->last_func_context);
                        }
                    }
                }
            }
        }
    }

    skip_call:
    self->trace_flush++;
    if (self->options.mode == GUM_OPTIONS_MODE_DEBUG) {
        if (self->trace_flush > 20) {
            if (buff_n > 0) {
                std::lock_guard<std::mutex> lock(self->trace_file_mutex);
                self->trace_file.write(buff, buff_n);
                buff_n = 0;
            }

            std::lock_guard<std::mutex> lock(self->trace_file_mutex);
            self->trace_file.flush();
            self->trace_flush = 0;
        }
    } 
    
    // else {
    //     if (self->trace_flush > 100000) {
    //         if (buff_n > 0) {
    //             self->trace_file.write(buff, buff_n);
    //             buff_n = 0;
    //         }

    //         self->trace_file.flush();
    //         self->trace_flush = 0;
    //     }
    // }
}

void GumTrace::pause_control_callout(GumCpuContext *cpu_context, gpointer user_data) {
    auto self = get_instance();
    auto callback_ctx = static_cast<CALLBACK_CTX *>(user_data);
    if (self == nullptr || callback_ctx == nullptr || cpu_context == nullptr) {
        return;
    }

    if (self->is_trace_paused_for_call(cpu_context)) {
        return;
    }

    __uint128_t jump_addr = 0;
    if (callback_ctx->instruction.id == ARM64_INS_BL &&
        callback_ctx->instruction_detail.arm64.operands[0].type == ARM64_OP_IMM) {
        jump_addr = callback_ctx->instruction_detail.arm64.operands[0].imm;
    } else if (callback_ctx->instruction.id == ARM64_INS_BLR &&
               callback_ctx->instruction_detail.arm64.operands[0].type == ARM64_OP_REG) {
        Utils::get_register_value(callback_ctx->instruction_detail.arm64.operands[0].reg, cpu_context, jump_addr);
    } else {
        return;
    }

    self->should_pause_trace_for_call(
        cpu_context,
        callback_ctx->module_base,
        callback_ctx->instruction.id,
        jump_addr);
}

void GumTrace::transform_callback(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data) {
    const auto self = get_instance();
    const bool block_trace_mode = is_block_trace_mode(self);
    const bool full_callout_probe_mode = is_full_callout_probe_mode(self);

    cs_insn *p_insn;
    auto *it = iterator;
    if (kMinimalStalkerOnlyMode) {
        while (gum_stalker_iterator_next(it, (const cs_insn **) &p_insn)) {
            gum_stalker_iterator_keep(it);
        }
        return;
    }

    while (gum_stalker_iterator_next(it, (const cs_insn **) &p_insn)) {
        const std::string *module_name_ptr = self->in_range_module(p_insn->address);
        if (module_name_ptr == nullptr) {
            gum_stalker_iterator_keep(it);
            continue;
        }

        GumMemoryAccess access = gum_stalker_iterator_get_memory_access(it);
        if (access != GUM_MEMORY_ACCESS_OPEN) {
            gum_stalker_iterator_keep(it);
            continue;
        }

        // Even in diagnostic modes, keep skipping atomics/exclusive instructions.
        // Those were already treated as special before, and instrumenting them
        // can make it look like "any callout crashes" when the real issue is
        // this instruction class.
        if (Utils::is_lse(p_insn)) {
            gum_stalker_iterator_keep(it);
            continue;
        }

        if (kSelectiveCalloutMode) {
            uintptr_t module_base = self->get_module_by_name(*module_name_ptr).at("base");
            uintptr_t insn_offset = static_cast<uintptr_t>(p_insn->address) - module_base;
            if (self->single_callout_config.enabled &&
                insn_offset == self->single_callout_config.instruction_offset) {
                auto callback_ctx = self->callback_context_instance->pull(
                    p_insn,
                    module_name_ptr->c_str(),
                    module_base);
                if (callback_ctx != nullptr) {
                    callback_ctx->sequence = self->probe_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
                }
                {
                    std::lock_guard<std::mutex> lock(self->trace_file_mutex);
                    if (self->trace_file.is_open()) {
                        char line[320];
                        int written = snprintf(
                            line,
                            sizeof(line),
                            "[callout-arm] seq=%llu tid=%llu [%s] 0x%llx!0x%llx %s %s\n",
                            (unsigned long long) (callback_ctx != nullptr ? callback_ctx->sequence : 0),
                            (unsigned long long) get_current_tid_safe(),
                            module_name_ptr->c_str(),
                            (unsigned long long) p_insn->address,
                            (unsigned long long) insn_offset,
                            p_insn->mnemonic,
                            p_insn->op_str);
                        if (written > 0) {
                            size_t safe_written = static_cast<size_t>(written);
                            if (safe_written >= sizeof(line)) {
                                safe_written = sizeof(line) - 1;
                            }
                            self->trace_file.write(line, static_cast<std::streamsize>(safe_written));
                            self->trace_file.flush();
                        }
                    }
                }
                if (callback_ctx != nullptr) {
                    gum_stalker_iterator_put_callout(it, callout_callback, callback_ctx, CallbackContext::release);
                }
            }
            gum_stalker_iterator_keep(it);
            continue;
        }

        if (kMinimalNoopCalloutMode) {
            gum_stalker_iterator_put_callout(it, callout_callback, nullptr, nullptr);
            gum_stalker_iterator_keep(it);
            continue;
        }

        if (full_callout_probe_mode) {
            const auto &module = self->get_module_by_name(*module_name_ptr);
            uintptr_t module_base = module.at("base");
            uintptr_t insn_offset = static_cast<uintptr_t>(p_insn->address) - module_base;
            auto callback_ctx = self->callback_context_instance->pull(
                p_insn,
                module_name_ptr->c_str(),
                module_base);
            if (callback_ctx != nullptr) {
                callback_ctx->sequence = self->probe_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
            }
            {
                std::lock_guard<std::mutex> lock(self->trace_file_mutex);
                if (self->trace_file.is_open()) {
                    char line[320];
                    int written = snprintf(
                        line,
                        sizeof(line),
                        "[callout-arm] seq=%llu tid=%llu [%s] 0x%llx!0x%llx %s %s\n",
                        (unsigned long long) (callback_ctx != nullptr ? callback_ctx->sequence : 0),
                        (unsigned long long) get_current_tid_safe(),
                        module_name_ptr->c_str(),
                        (unsigned long long) p_insn->address,
                        (unsigned long long) insn_offset,
                        p_insn->mnemonic,
                        p_insn->op_str);
                    if (written > 0) {
                        size_t safe_written = static_cast<size_t>(written);
                        if (safe_written >= sizeof(line)) {
                            safe_written = sizeof(line) - 1;
                        }
                        self->trace_file.write(line, static_cast<std::streamsize>(safe_written));
                        self->trace_file.flush();
                    }
                }
            }
            if (callback_ctx != nullptr) {
                gum_stalker_iterator_put_callout(it, callout_callback, callback_ctx, CallbackContext::release);
            }
            gum_stalker_iterator_keep(it);
            continue;
        }

        if (block_trace_mode || kMinimalEventSinkExecMode) {
            if (block_trace_mode && self->pause_call_config.enabled &&
                (p_insn->id == ARM64_INS_BL || p_insn->id == ARM64_INS_BLR || p_insn->id == ARM64_INS_RET)) {
                const auto &module = self->get_module_by_name(*module_name_ptr);
                auto callback_ctx = self->callback_context_instance->pull(
                    p_insn,
                    module_name_ptr->c_str(),
                    module.at("base"));
                if (callback_ctx != nullptr) {
                    gum_stalker_iterator_put_callout(it, pause_control_callout, callback_ctx, CallbackContext::release);
                }
            }
            gum_stalker_iterator_keep(it);
            continue;
        }

        if (kMinimalInstructionTraceMode) {
            const auto &module = self->get_module_by_name(*module_name_ptr);
            auto callback_ctx = self->callback_context_instance->pull(
                p_insn,
                module_name_ptr->c_str(),
                module.at("base"));
            if (callback_ctx != nullptr) {
                gum_stalker_iterator_put_callout(it, callout_callback, callback_ctx, CallbackContext::release);
            }
            gum_stalker_iterator_keep(it);
            continue;
        }

        const auto& module = self->get_module_by_name(*module_name_ptr);

        auto callback_ctx = self->callback_context_instance->pull(p_insn, module_name_ptr->c_str(),
                                                                  module.at("base"));
        if (callback_ctx != nullptr) {
            gum_stalker_iterator_put_callout(it, callout_callback, callback_ctx, CallbackContext::release);
        }

        gum_stalker_iterator_keep(it);
    }
}

void GumTrace::event_sink_callback(const GumEvent *event, GumCpuContext *cpu_context, gpointer user_data) {
    auto self = static_cast<GumTrace *>(user_data);
    if (self == nullptr || event == nullptr || event->type != GUM_BLOCK) {
        return;
    }

    uintptr_t start = reinterpret_cast<uintptr_t>(event->block.start);
    uintptr_t end = reinterpret_cast<uintptr_t>(event->block.end);
    const std::string *module_name_ptr = self->in_range_module(start);
    if (module_name_ptr == nullptr) {
        return;
    }

    const auto &module = self->get_module_by_name(*module_name_ptr);
    uintptr_t module_base = module.at("base");
    uintptr_t start_offset = start - module_base;
    uintptr_t end_offset = end - module_base;

    if (self->block_trace_config.enabled) {
        const uintptr_t trace_start = self->block_trace_config.start_offset;
        const uintptr_t trace_end = self->block_trace_config.end_offset;
        const bool overlaps = end_offset > trace_start && start_offset < trace_end;
        if (!overlaps) {
            return;
        }
    }

    if (self->pause_call_state.active) {
        const uintptr_t return_address = self->pause_call_state.return_address;
        const bool contains_return = start <= return_address && return_address < end;
        const bool sp_matches = cpu_context == nullptr || cpu_context->sp == self->pause_call_state.return_sp;

        if (!contains_return || !sp_matches) {
            return;
        }

        self->resume_trace_after_call();
    }

    uint64_t block_seq = self->block_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    uint64_t tid = get_current_tid_safe();
    TRACE_BLOCK_NODE current_node{};
    current_node.module_base = module_base;
    current_node.start_offset = start_offset;
    current_node.end_offset = end_offset;

    bool is_new_node = false;
    bool is_new_edge = false;
    TRACE_BLOCK_EDGE current_edge{};

    {
        std::lock_guard<std::mutex> graph_lock(self->block_graph_mutex);
        auto node_result = self->seen_block_nodes.insert(current_node);
        is_new_node = node_result.second;

        auto last_it = self->last_block_by_tid.find(tid);
        if (last_it != self->last_block_by_tid.end()) {
            current_edge.from = last_it->second;
            current_edge.to = current_node;
            auto edge_result = self->seen_block_edges.insert(current_edge);
            is_new_edge = edge_result.second;
        }

        self->last_block_by_tid[tid] = current_node;
    }

    std::lock_guard<std::mutex> lock(self->trace_file_mutex);
    if (!self->trace_file.is_open()) {
        return;
    }

    char line[256];
    if (is_new_edge) {
        int edge_written = snprintf(
            line,
            sizeof(line),
            "[edge] seq=%llu tid=%llu [%s] 0x%llx!0x%llx -> 0x%llx!0x%llx\n",
            (unsigned long long) block_seq,
            (unsigned long long) tid,
            module_name_ptr->c_str(),
            (unsigned long long) (current_edge.from.module_base + current_edge.from.start_offset),
            (unsigned long long) current_edge.from.start_offset,
            (unsigned long long) start,
            (unsigned long long) start_offset);
        if (edge_written > 0) {
            size_t safe_written = static_cast<size_t>(edge_written);
            if (safe_written >= sizeof(line)) {
                safe_written = sizeof(line) - 1;
            }
            self->trace_file.write(line, static_cast<std::streamsize>(safe_written));
        }
    }

    if (is_new_node) {
        int block_written = snprintf(
            line,
            sizeof(line),
            "[block] seq=%llu tid=%llu [%s] 0x%llx!0x%llx -> 0x%llx!0x%llx\n",
            (unsigned long long) block_seq,
            (unsigned long long) tid,
            module_name_ptr->c_str(),
            (unsigned long long) start,
            (unsigned long long) start_offset,
            (unsigned long long) end,
            (unsigned long long) end_offset);
        if (block_written > 0) {
            size_t safe_written = static_cast<size_t>(block_written);
            if (safe_written >= sizeof(line)) {
                safe_written = sizeof(line) - 1;
            }
            self->trace_file.write(line, static_cast<std::streamsize>(safe_written));
        }

        for (uintptr_t insn = start; insn + 4 <= end; insn += 4) {
            uint32_t raw = *reinterpret_cast<const uint32_t *>(insn);
            int insn_written = snprintf(
                line,
                sizeof(line),
                "  0x%llx!0x%llx raw=0x%08x\n",
                (unsigned long long) insn,
                (unsigned long long) (insn - module_base),
                raw);
            if (insn_written <= 0) {
                continue;
            }

            size_t safe_insn_written = static_cast<size_t>(insn_written);
            if (safe_insn_written >= sizeof(line)) {
                safe_insn_written = sizeof(line) - 1;
            }
            self->trace_file.write(line, static_cast<std::streamsize>(safe_insn_written));
        }

        if (end > start && ((end - start) % 4) != 0) {
            int tail_written = snprintf(
                line,
                sizeof(line),
                "  [warn] non-4-byte tail at 0x%llx size=0x%llx\n",
                (unsigned long long) end,
                (unsigned long long) (end - start));
            if (tail_written > 0) {
                size_t safe_tail_written = static_cast<size_t>(tail_written);
                if (safe_tail_written >= sizeof(line)) {
                    safe_tail_written = sizeof(line) - 1;
                }
                self->trace_file.write(line, static_cast<std::streamsize>(safe_tail_written));
            }
        }
    }

    self->trace_file.flush();
}

const std::string *GumTrace::in_range_module(size_t address) {
    struct CachedModule {
        const std::string* name = nullptr;
        size_t base = 0;
        size_t end = 0;
    };
    static thread_local CachedModule tls_last_module_cache;

    if (tls_last_module_cache.name != nullptr &&
        address >= tls_last_module_cache.base &&
        address < tls_last_module_cache.end) {
        return tls_last_module_cache.name;
    }

    for (const auto &pair: modules) {
        const auto &module_map = pair.second;
        size_t base = module_map.at("base");
        size_t size = module_map.at("size");
        size_t end = base + size;
        if (address >= base && address < end) {
            tls_last_module_cache.name = &pair.first;
            tls_last_module_cache.base = base;
            tls_last_module_cache.end = end;
            return &pair.first;
        }
    }
    return nullptr;
}

const RangeInfo* GumTrace::find_range_by_address(uintptr_t addr) {
    if (safa_ranges.empty()) return nullptr;

    int left = 0;
    int right = safa_ranges.size() - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        const auto &info = safa_ranges[mid];

        if (addr >= info.base && addr < info.end) {
            return &info;
        }

        if (addr < info.base) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    return nullptr;
}

const std::map<std::string, std::size_t>& GumTrace::get_module_by_name(const std::string &module_name) {
    return modules[module_name];
}

void GumTrace::follow() {
    trace_thread_id > 0
        ? gum_stalker_follow(_stalker, trace_thread_id, _transformer, nullptr)
        : gum_stalker_follow_me(_stalker, _transformer, nullptr);
}


void GumTrace::unfollow() {
    trace_thread_id > 0 ? gum_stalker_unfollow(_stalker, trace_thread_id) : gum_stalker_unfollow_me(_stalker);
    flush_thread_running.store(false);

    if (flush_thread != 0) {
        pthread_join(flush_thread, nullptr);
        flush_thread = 0;
    }

    std::lock_guard<std::mutex> lock(trace_file_mutex);
    if (trace_file.is_open()) {
        trace_file.write(buffer, buffer_offset);
        buffer_offset = 0;
        trace_file.flush();
        trace_file.close();
    }
}
