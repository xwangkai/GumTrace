//
// Created by lidongyooo on 2026/2/6.
//

#ifndef GUMTRACE_CALLBACKCONTEXT_H
#define GUMTRACE_CALLBACKCONTEXT_H
#include "Utils.h"

#define CALLBACK_CTX_SIZE 102400

struct CALLBACK_CTX {
    uint64_t sequence = 0;
    const char* module_name;
    uint64_t module_base;
    cs_insn instruction{};
    cs_detail instruction_detail{};
};

class CallbackContext {
public:
    static CallbackContext *get_instance();
    CALLBACK_CTX* pull(const cs_insn* _instruction, const char* module_name, uint64_t module_base);
    static void release(gpointer data);
private:
    CallbackContext();

    ~CallbackContext();

    CallbackContext(const CallbackContext &) = delete;

    CallbackContext &operator=(const CallbackContext &) = delete;
};

#endif //GUMTRACE_CALLBACKCONTEXT_H
