//
// Created by lidongyooo on 2026/2/6.
//

#include "GumTrace.h"
#include "Utils.h"
#include "FuncPrinter.h"

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
}

#if PLATFORM_ANDROID

JNIEnv *GumTrace::get_run_time_env() {
    if (java_vm == nullptr) {
        return nullptr;
    }

    if (jni_env == nullptr) {
        java_vm->GetEnv((void**)&jni_env, JNI_VERSION_1_6);
    }

    if (jni_env != nullptr && jni_env_init == false) {
        jni_env_init = true;

        auto jni_func_table = (uint64_t)jni_env->functions;
        int index = 0;
        for (const auto &func_name: jni_func_names) {
            auto func_addr_ptr = (void **)(jni_func_table + index * sizeof(void *));
            auto func_addr = (uint64_t)(*func_addr_ptr);
            jni_func_maps[func_addr] = func_name;
            index++;
        }
    }
    return jni_env;
}

#endif



void GumTrace::callout_callback(GumCpuContext *cpu_context, gpointer user_data) {
    auto self = get_instance();
    auto callback_ctx = (CALLBACK_CTX *)user_data;
    char *buff = self->buffer;
    int &buff_n = self->buffer_offset;

    if (buff_n > BUFFER_SIZE - 1024) {
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

                const char *reg_name = cs_reg_name(callback_ctx->handle, self->write_reg_list.regs[i]);
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
            self->trace_file.write(buff, buff_n);
            buff_n = 0;
        }

        self->last_func_context.call = false;
#        if PLATFORM_ANDROID

        if (self->last_func_context.is_jni) {
            self->last_func_context.is_jni = false;
            FuncPrinter::jni_after(&self->last_func_context, cpu_context);
        } else {
            FuncPrinter::after(&self->last_func_context, cpu_context);
        }

#        else

            FuncPrinter::after(&self->last_func_context, cpu_context);

#endif

        self->trace_file.write(self->last_func_context.info, self->last_func_context.info_n);
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

                const char *reg_name = cs_reg_name(callback_ctx->handle, op.reg);
                Utils::append_string(buff, buff_n, reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(reg_value, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }
            is_write = true;
            self->write_reg_list.regs[self->write_reg_list.num++] = op.reg;
        } else if (op.access & CS_AC_READ && op.type == ARM64_OP_REG) {
            if (Utils::get_register_value(op.reg, cpu_context, reg_value)) {

                const char *reg_name = cs_reg_name(callback_ctx->handle, op.reg);
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
                const char *base_reg_name = cs_reg_name(callback_ctx->handle, op.mem.base);
                Utils::append_string(buff, buff_n, base_reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(base, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }

            if (op.mem.index != ARM64_REG_INVALID) {
                flag = Utils::get_register_value(op.mem.index, cpu_context, index);
                const char *index_reg_name = cs_reg_name(callback_ctx->handle, op.mem.index);
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
                self->write_reg_list.regs[self->write_reg_list.num++] = op.mem.base;
            }
        }  else if ((op.access & CS_AC_WRITE) && op.type == ARM64_OP_MEM) {
            __uint128_t base = 0;
            __uint128_t index = 0;
            bool flag = true;

            if (op.mem.base != ARM64_REG_INVALID) {
                flag = Utils::get_register_value(op.mem.base, cpu_context, base);
                const char *base_reg_name = cs_reg_name(callback_ctx->handle, op.mem.base);
                Utils::append_string(buff, buff_n, base_reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(base, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }

            if (op.mem.index != ARM64_REG_INVALID) {
                flag = Utils::get_register_value(op.mem.index, cpu_context, index);
                const char *index_reg_name = cs_reg_name(callback_ctx->handle, op.mem.index);
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
                const char *base_reg_name = cs_reg_name(callback_ctx->handle, op.mem.base);
                Utils::append_string(buff, buff_n, base_reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(base, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }
            if (op.mem.index != ARM64_REG_INVALID) {
                flag = Utils::get_register_value(op.mem.index, cpu_context, index);
                const char *index_reg_name = cs_reg_name(callback_ctx->handle, op.mem.index);
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

                const char *reg_name = cs_reg_name(callback_ctx->handle, op.reg);
                Utils::append_string(buff, buff_n, reg_name);
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(reg_value, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }

            is_write = true;
            self->write_reg_list.regs[self->write_reg_list.num++] = op.reg;
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
            // 1. 优先查静态符号表
            const std::string *sym_name = nullptr;
            auto it = self->func_maps.find(jump_addr);
            if (it != self->func_maps.end()) {
                sym_name = &it->second;
            }

            // 2. 静态表没有 → 查运行时缓存（避免重复调用 gum_symbol_name_from_address）
            const std::string *module_name_ptr = self->in_range_module(jump_addr);
            if (module_name_ptr == nullptr) {//排除本模块内的地址，不排除的话trace大小会很大
                if (sym_name == nullptr) {
                    auto cache_it = self->resolved_cache.find(jump_addr);
                    if (cache_it != self->resolved_cache.end()) {
                        sym_name = &cache_it->second;
                    } else {
                        // 3. 缓存也没有 → 运行时动态解析
                        //    这里能正确处理懒加载已解析后的真实地址
                        gchar *name = gum_symbol_name_from_address((gpointer)(uintptr_t)jump_addr);
                        if (name != nullptr) {
                            self->resolved_cache[(size_t)jump_addr] = name;
                            sym_name = &self->resolved_cache[(size_t)jump_addr];
                            g_free(name);
                        }
                    }
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
#            if PLATFORM_ANDROID
            else if (self->get_run_time_env() != nullptr && self->jni_func_maps.count(jump_addr) > 0) {
                self->last_func_context.info_n = 0;
                self->last_func_context.address = jump_addr;
                self->last_func_context.name = self->jni_func_maps[jump_addr].c_str();
                memcpy(&self->last_func_context.cpu_context, cpu_context, sizeof(GumCpuContext));
                self->last_func_context.call = true;
                self->last_func_context.is_jni = true;

                FuncPrinter::jni_before(&self->last_func_context);
            }
#endif

        }
    }

    skip_call:
    self->trace_flush++;
    if (self->options.mode == GUM_OPTIONS_MODE_DEBUG) {
        if (self->trace_flush > 20) {
            if (buff_n > 0) {
                self->trace_file.write(buff, buff_n);
                buff_n = 0;
            }

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

void GumTrace::transform_callback(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data) {
    const auto self = get_instance();

    cs_insn *p_insn;
    auto *it = iterator;
    while (gum_stalker_iterator_next(it, (const cs_insn **) &p_insn)) {
        const std::string *module_name_ptr = self->in_range_module(p_insn->address);
        if (module_name_ptr == nullptr) {
            gum_stalker_iterator_keep(it);
            continue;
        }

        if (Utils::is_lse(p_insn) == false) {
            const auto& module = self->get_module_by_name(*module_name_ptr);

            auto callback_ctx = self->callback_context_instance->pull(p_insn, gum_stalker_iterator_get_capstone(it),
                                                                      module_name_ptr->c_str(), module.at("base"));

            gum_stalker_iterator_put_callout(it, callout_callback, callback_ctx, nullptr);
        }

        gum_stalker_iterator_keep(it);
    }
}

const std::string *GumTrace::in_range_module(size_t address) {
    if (last_module_cache.name != nullptr && address >= last_module_cache.base && address < last_module_cache.end) {
        return last_module_cache.name;
    }

    for (const auto &pair: modules) {
        const auto &module_map = pair.second;
        size_t base = module_map.at("base");
        size_t size = module_map.at("size");
        size_t end = base + size;
        if (address >= base && address < end) {
            last_module_cache.name = &pair.first;
            last_module_cache.base = base;
            last_module_cache.end = end;
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

    if (trace_file.is_open()) {
        trace_file.write(buffer, buffer_offset);
        buffer_offset = 0;
        trace_file.flush();
        trace_file.close();
    }
}
