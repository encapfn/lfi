#pragma once

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LFI_BOX_FULL,
    LFI_BOX_STORES,
    LFI_BOX_BUNDLEJUMPS,
} LFIBoxType;

typedef enum {
    LFI_BUNDLE_NONE,
    LFI_BUNDLE8,
    LFI_BUNDLE16,
    LFI_BUNDLE32,
} LFIBundleType;

typedef enum {
    LFI_METER_NONE,
    LFI_METER_BRANCH,
    LFI_METER_FP,
    LFI_METER_TIMER,
} LFIMeterType;

typedef struct {
    bool decl;
    bool poc;
    LFIBoxType box;
    size_t p2size;
    LFIBundleType bundle;
    LFIMeterType meter;

    void (*err)(char* msg, size_t sz);
} LFIvOpts;

typedef struct {
    LFIvOpts opts;
    bool (*verify)(void* code, size_t size, uintptr_t addr, LFIvOpts* opts);
} LFIVerifier;

bool lfiv_verify(LFIVerifier* v, void* code, size_t size, uintptr_t addr);

bool lfiv_verify_arm64(void* code, size_t size, uintptr_t addr, LFIvOpts* opts);

bool lfiv_verify_amd64(void* code, size_t size, uintptr_t addr, LFIvOpts* opts);

#ifdef __cplusplus
}
#endif
