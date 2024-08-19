#pragma once

#include <stdlib.h>

#include "lfi.h"

typedef struct {
    struct lfi* lfimgr;
    uint8_t* (*readfile)(const char* filename, size_t* size);
} Sobox;

typedef struct SoboxLib SoboxLib;

// sbx_init initializes the Sobox library manager.
//
// Multiple libraries can be loaded with this manager, and they will each be
// placed into a separate sandbox. Returns false if an error occurred (out of
// memory).
bool sbx_init(Sobox* sbx, uint8_t* (*readfile)(const char* filename, size_t* size));

// sbx_dlopen opens and loads a new sandboxed shared library.
SoboxLib* sbx_dlopen(Sobox* sbx, const char* filename, int flags);

// sbx_dlclose closes a sandboxed library.
int sbx_dlclose(SoboxLib* lib);

// sbx_dlsym looks up a symbol in a sandboxed library.
//
// This should only be used to look up non-function symbols. To look up a
// function, use sbx_dlsymfn.
void* sbx_dlsym(SoboxLib* lib, const char* symbol);

// sbx_dlsymfn looks up a function symbol in a sandboxed library.
//
// The type signature must be provided in the 'ty' parameter. This type
// information is used to generate a trampoline that properly copies arguments
// into the sandbox according to the calling convention.
void* sbx_dlsymfn(SoboxLib* lib, const char* symbol, const char* ty);

// sbx_dlsymfnstk looks up a function symbol in a sandboxed library.
//
// The amount of data to copy from the stack is passed in 'stkamt'. This amount
// can be derived from the type signature of the function and the calling
// convention. The sbx_dlsymfn derives this automatically from a 'ty' string
// but this function allows you to provide the information manually.
void* sbx_dlsymfnstk(SoboxLib* lib, const char* symbol, size_t stkamt);

// sbx_malloc allocates memory inside the sandbox.
void* sbx_malloc(SoboxLib* lib, size_t size);

// sbx_free frees memory that was allocated inside the sandbox.
void sbx_free(SoboxLib* lib, void* ptr);

// sbx_deinit deletes the Sobox sandbox manager.
void sbx_deinit(Sobox* sbx);
