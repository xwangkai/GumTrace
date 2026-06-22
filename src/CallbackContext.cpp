//
// Created by lidongyooo on 2026/2/6.
//

#include "CallbackContext.h"

#include <utility>


CallbackContext *CallbackContext::get_instance() {
    static CallbackContext instance;
    return &instance;
}


CallbackContext::CallbackContext() {
}

CallbackContext::~CallbackContext() {
}

CALLBACK_CTX* CallbackContext::pull(const cs_insn* _instruction, const char* module_name, uint64_t module_base) {
    auto *ctx = static_cast<CALLBACK_CTX *>(calloc(1, sizeof(CALLBACK_CTX)));
    if (ctx == nullptr) {
        return nullptr;
    }

    ctx->module_name = module_name;
    ctx->module_base = module_base;
    memcpy(&ctx->instruction, _instruction, sizeof(cs_insn));
    if (_instruction->detail) {
        memcpy(&ctx->instruction_detail, _instruction->detail, sizeof(cs_detail));
    }
    
    return ctx;
}

void CallbackContext::release(gpointer data) {
    free(data);
}



