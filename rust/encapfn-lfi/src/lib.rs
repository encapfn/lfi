#![feature(
    naked_functions,
    linked_list_retain,
    thread_local,
    maybe_uninit_as_bytes,
    maybe_uninit_write_slice
)]
#![allow(named_asm_labels)]

use std::collections::LinkedList;
use std::ffi::{c_void, CStr};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::mem::MaybeUninit;

use log::info;

pub use encapfn;

use encapfn::abi::calling_convention::{Stacked, AREG0, AREG1, AREG2, AREG3, AREG4, AREG5};
use encapfn::abi::sysv_aarch64::SysVAArch64ABI;
use encapfn::branding::EFID;
use encapfn::rt::sysv_aarch64::{SysVAArch64BaseRt, SysVAArch64InvokeRes, SysVAArch64Rt};
use encapfn::rt::EncapfnRt;
use encapfn::{EFResult, EFError};
use encapfn::types::{AccessScope, AllocScope, AllocTracker};

use libsobox_sys::{sbx_dlopen, sbx_init, Sobox, sbx_dlsymfn, sbx_invoke, lfi_regs_arg, sbx_lfi_proc_regs};

const ENABLE_DEBUG: bool = true;

static ENCAPFN_LFI_RT_COUNT: AtomicUsize = AtomicUsize::new(0);

static SOBOX_LIBRARY_MANAGER: Mutex<Option<SoboxSendWrapper>> = Mutex::new(None);

struct SoboxSendWrapper(Sobox);
unsafe impl Send for SoboxSendWrapper {}

#[derive(Clone, Debug)]
enum SoboxLibraryManagerError {
    InitializationError,
    LockPoisoned,
}

fn with_sobox_library_manager<R>(
    f: impl FnOnce(&mut Sobox) -> R,
) -> Result<R, SoboxLibraryManagerError> {
    let mut sobox_lg = SOBOX_LIBRARY_MANAGER
        .lock()
        .map_err(|_| SoboxLibraryManagerError::LockPoisoned)?;

    if sobox_lg.is_none() {
        let mut sbx = unsafe { std::mem::zeroed() };

        if !(unsafe { sbx_init(&mut sbx) }) {
            return Err(SoboxLibraryManagerError::InitializationError);
        } else {
            *sobox_lg = Some(SoboxSendWrapper(sbx));
        }
    }

    // When we reach this statement, sobox_lg must be Some(_):
    Ok(f(sobox_lg
        .as_mut()
        .map(|SoboxSendWrapper(ref mut sbx)| sbx)
        .unwrap()))
}

#[repr(C)]
pub struct EncapfnLFIRtAsmState {
    sobox_lib_handle: *mut c_void,

    //    // Foreign stack pointer, read by the protection-domain switch assembly
    //    // and used as a base to copy stacked arguments & continue execution from:
    //    foreign_stack_ptr: Cell<*mut ()>,
    //
    //    // Foreign stack top (exclusive). Stack grows downward from here:
    //    foreign_stack_top: *mut (),
    //
    //    // Foreign stack bottom (inclusive). Last usable stack address:
    //    foreign_stack_bottom: *mut (),
    //
    //    // PKRU value while foreign code is running:
    //    foreign_code_pkru: u32,
    //
    //    // Scratch-space for the protection-domain switch assembly to store the
    //    // Rust stack pointer while executing foreign code.
    //    rust_stack_ptr: UnsafeCell<*mut ()>,
    //
    //    // Scratch-space to store the InvokeRes pointer for encoding the function's
    //    // return value while executing foreign code:
    //    invoke_res_ptr: UnsafeCell<*mut EncapfnLFIInvokeResInner>,
    //
    // Log-prefix String. Contained in asm state, as it should be accessible to
    // callbacks running before the runtime struct is fully built:
    log_prefix: String,
}

#[repr(C)]
pub struct EncapfnLFIRt<ID: EFID> {
    // This struct is used both in the protection-domain switch assembly,
    // and in regular Rust code. However, we want to avoid hard-coding offsets
    //
    // into this struct in assembly, but instead use ::core::ptr::offset_of!
    // to resolve offsets of relevant fields at compile. Unfortunately, that is
    // not possible, in general, for a generic type without knowing the generic
    // argument. Instead, we move all assembly-relevant state into a separate
    // struct `EncapfnLFIRtAsmState`, which does not have generic parameters.
    // We ensure that this struct is placed at the very beginning of the
    // `EncapfnLFIRt` type, for every possible combination of generic
    // parameters, through an assertion in its constructor.
    asm_state: EncapfnLFIRtAsmState,

    // A unique ID of this instance, to address it at runtime.
    id: usize,

    _id: PhantomData<ID>,

    // Ensure that the runtime is !Sync. Currently the runtime cannot be shared
    // across threads!
    //
    // For this we'd need to support multiple threads, think about concurrent
    // accesses to foreign memory, etc.
    //
    // We cannot directly impl !Sync, as that is still unstable. Instead, we
    // use a !Send and !Sync member type to enforce these negative trait
    // bounds, as proposed here:
    // https://users.rust-lang.org/t/negative-trait-bounds-are-not-yet-fully-implemented-use-marker-types-for-now/64495/2
    //
    //impl<ID: EFID> !Sync for EncapfnLFIRt<ID> {}
    _not_sync: PhantomData<*const ()>,
}

#[derive(Clone, Debug)]
pub enum EncapfnLFIRtError {
    SoboxInitializationError,
    SoboxDlopenFail,
    InternalError,
}

impl<ID: EFID> EncapfnLFIRt<ID> {
    pub fn new(
        library: impl AsRef<CStr>,
        _id: ID,
    ) -> Result<
        (
            Self,
            AllocScope<'static, EncapfnLFIRtAllocTracker, ID>,
            AccessScope<ID>,
        ),
        EncapfnLFIRtError,
    > {
        // See the EncapfnLFIRt type definition for an explanation of this
        // const assertion. It is required to allow us to index into fields
        // of the nested `EncapfnLFIRtAsmState` struct from within assembly.
        //
        // Unfortunately, we cannot make this into a const assertion, as
        // constants are instantiated outside of the `impl` block.
        let _: () = assert!(std::mem::offset_of!(Self, asm_state) == 0);

        // Obtain a new ID, for globally addressing this runtime instance:
        let id = ENCAPFN_LFI_RT_COUNT.fetch_add(1, Ordering::Relaxed);
        info!("Initializing new EncapfnLFIRt instance, id {}", id);
        let log_prefix = format!("EncapfnLFIRt[#{}]:", id);

        // Load the library into a new sandbox:
        let sobox_lib_handle: *mut c_void = with_sobox_library_manager(|sbx: &mut Sobox| unsafe {
            sbx_dlopen(sbx, library.as_ref().as_ptr(), 0)
        })
        .map_err(|sobox_err| match sobox_err {
            SoboxLibraryManagerError::InitializationError => {
                EncapfnLFIRtError::SoboxInitializationError
            }
            SoboxLibraryManagerError::LockPoisoned => EncapfnLFIRtError::InternalError,
        })?;

        if sobox_lib_handle == std::ptr::null_mut() {
            return Err(EncapfnLFIRtError::SoboxDlopenFail);
        }
        
        println!("Created lib handle {:?}", sobox_lib_handle);

        let asm_state = EncapfnLFIRtAsmState {
            sobox_lib_handle,

            //    foreign_stack_ptr: Cell::new(foreign_stack_top),
            //    foreign_stack_bottom,
            //    foreign_stack_top,
            //    foreign_code_pkru: 0, // run cb init without memory protection for now

            //    // Scratch-space, initialize with dummy value:
            //    rust_stack_ptr: UnsafeCell::new(std::ptr::null_mut()),

            //    // Scratch-space, initialize with dummy value:
            //    invoke_res_ptr: UnsafeCell::new(std::ptr::null_mut()),
            log_prefix,
        };

        let rt = EncapfnLFIRt {
            asm_state,
            id,
            //rt_lib_handle,
            //rt_lmid,
            //lib_handles,
            //pkey_library,
            //pkey_library_ro,
            //pkey_rust,
            _id: PhantomData,
            _not_sync: PhantomData,
        };

        Ok((
            rt,
            unsafe {
                AllocScope::new(EncapfnLFIRtAllocTracker {
                    // TODO: hook into the sandbox for memory allocations? Or be able to query
                    // which allocations are readable / writeable, and which ones are executable
                    // and thus read-only? 
                    allocations: LinkedList::new(),
                })
            },
            unsafe { AccessScope::new() },
        ))
    }

    //#[naked]
    //unsafe extern "C" fn rt_init(
    //    rt: *const Self,
    //    runtime_init_addr: *const (),
    //    res: *mut EncapfnLFIInvokeRes<Self, ()>,
    //    top: *const (),
    //    bottom: *const (),
    //    environ: *const *const std::ffi::c_char,
    //) {
    //    core::arch::asm!(
    //        "
    //        // We don't rely on the foreign function to retain our
    //        // callee-saved registers, hence stack them. This is written
    //        // to match the assumptions in generic_invoke:
    //        push rbx
    //        push rbp
    //        push r12
    //        push r13
    //        push r14
    //        push r15

    //        // Load required parameters for generic_invoke into
    //        // non-argument registers and continue execution in the
    //        // generic protection-domain switch routine:
    //        mov r10, rdi                   // Load runtime pointer into r10
    //        mov r11, rsi                   // Load function pointer into r11
    //        mov r12, rdx                   // Load invoke res pointer into r12
    //        mov r13, 0                     // Copy the stack-spill immediate into r12

    //        // Load the function arguments:
    //        // - rdi: callback_addr
    //        // - rsi: heap_top
    //        // - rdx: heap_bottom
    //        // - rcx: environ
    //        lea rdi, [rip - {raw_callback_handler_sym}]
    //        mov rsi, rcx
    //        mov rdx, r8
    //        mov rcx, r9

    //        // Continue execution at generic_invoke, which will return from
    //        // this function for us:
    //        lea r14, [rip - {generic_invoke_sym}]
    //        jmp r14
    //        ",
    //        generic_invoke_sym = sym Self::generic_invoke,
    //        raw_callback_handler_sym = sym Self::raw_callback_handler,
    //        options(noreturn),
    //    );
    //}

    //unsafe extern "C" fn callback_handler(
    //    asm_state: &EncapfnLFIRtAsmState,
    //    id: usize,
    //    arg0: usize,
    //    arg1: usize,
    //    arg2: usize,
    //    arg3: usize,
    //) {
    //    // It is not always legal to upgrade our asm_state pointer to a runtime
    //    // pointer. Some initial entries into the foreign library (and
    //    // subsequent callbacks) are made without the fully constructed
    //    // Runtime). Hence, check whether it's constructed before casting
    //    // `asm_state` to an `rt: &Self`!

    //    // TODO: debug segfaults here, not good. Why?
    //    eprintln!(
    //        "{} Got callback with ID {}, args: {:016x}, {:016x}, {:016x}, {:016x}",
    //        asm_state.log_prefix, id, arg0, arg1, arg2, arg3
    //    );
    //    std::io::stdout().flush().unwrap();
    //}

    //#[naked]
    //unsafe extern "C" fn raw_callback_handler() {
    //    core::arch::asm!(
    //        "
    //            // We arrive here with the LFI protection mechanism still
    //            // engaged. Thus, disable those first, and then restore the
    //            // necessary Rust environment:

    //            // Foreign code may have passed arguments in rcx and rdx,
    //            // however we do need to clobber them. Thus we temporarily
    //            // move those registers into other callee-saved registers:
    //            mov r10, rcx
    //            mov r11, rdx

    //            // Restore access to all PKEYs. All of rax, rcx and rdx are
    //            // caller-saved, so we can clobber them here:
    //            xor rax, rax           // Clear rax, used to write PKRU
    //            xor rcx, rcx           // Clear rcx, required for WRPKRU
    //            xor rdx, rdx           // Clear rdx, required for WRPKRU
    //            wrpkru

    //            // Restore the argument registers:
    //            mov rdx, r11
    //            mov rcx, r10

    //            // We're back in 'trusted code' here. To avoid any spurious SIGSEGV's
    //            // later on, make sure that untrusted code has indeed cleared PKRU
    //            // correctly:
    //            test eax, eax
    //            jz 100f                // If zero, PKRU cleared correctly.
    //            ud2                    // If not zero, crash with an illegal insn

    //          100: // _pkru_cleared
    //            // Now, load the runtime pointer again and restore the Rust stack.
    //            // We load the runtime pointer into a callee-saved register that,
    //            // by convention, is reserved by all callback invocations:
    //            mov rdi, qword ptr [rip - {rust_thread_state_static} + {rts_runtime_offset}]

    //            // Update the foreign stack pointer in our runtime struct, such
    //            // that the callback handler can access it and we use it to
    //            // restore the stack pointer after the callback has been run:
    //            mov qword ptr [rdi + {rtas_foreign_stack_ptr_offset}], rsp

    //            // Now, restore the Rust stack. We did not use the red-zone in
    //            // the invoke functions, and hence can just align the stack
    //            // down to 16 bytes to call the function:
    //            mov rsp, qword ptr [rdi + {rtas_rust_stack_ptr_offset}]
    //            and rsp, -16

    //            // Push all values that we intend to retain on the Rust stack.
    //            // The Rust function follows the C ABI, so we don't need to
    //            // worry about this introducing any additional clobbers.
    //            //
    //            // For now, we only need to save the runtime pointer:
    //            push rdi               // Save rt pointer on Rust stack

    //            // Finally, invoke the callback handler:
    //            call {callback_handler_sym}

    //            // Restore the runtime pointer from the Rust stack:
    //            pop rdi

    //            // Restore the userspace stack pointer:
    //            mov rsp, qword ptr [rdi + {rtas_foreign_stack_ptr_offset}]

    //            // Now, switch back the PKEYs. For this, we need to preserve
    //            // the return value registers rax and rdx. This may overflow
    //            // the stack. TODO: should we handle this?
    //            push rax               // Save rax to the foreign stack
    //            push rdx               // Save rdx to the foreign stack

    //            // Move the intended PKRU value into the thread-local static, such
    //            // that we can compare it after we run the WRPKRU instruction.
    //            // This prevents it from being used as a gadget by untrusted code.
    //            mov eax, dword ptr [rdi + {rtas_foreign_code_pkru_offset}]
    //            mov dword ptr [rip - {rust_thread_state_static} + {rts_pkru_shadow_offset}], eax

    //            xor rcx, rcx           // Clear rcx, required for WRPKRU
    //            xor rdx, rdx           // Clear rdx, required for WRPKRU
    //            wrpkru

    //            // It is important that we now check that we have actually loaded the
    //            // intended value into the PKRU register. The RUST_THREAD_STATE static
    //            // is accessible read-only to foreign code, so read its PKRU shadow
    //            // copy and make sure that its value matches rax.
    //            //
    //            // We clobber the r13 scratch register for this, which we don't
    //            // need to save:
    //            push r13 // TODO!
    //            mov r13d, dword ptr [rip - {rust_thread_state_static} + {rts_pkru_shadow_offset}]
    //            cmp eax, r13d
    //            je 500f
    //            ud2                    // Crash with an illegal instruction

    //         500: // _pkru_loaded_verified
    //            pop r13

    //            // Restore the callback return values:
    //            pop rdx                // Pop rdx from foreign stack, still accessible
    //            pop rax                // Pop rax from foreign stack, still accessible

    //            // Now it is safe to return to the calling function on the
    //            // foreign stack:
    //            ret
    //        ",
    //        // Rust callback handler:
    //        callback_handler_sym = sym Self::callback_handler,
    //        // Rust thread-local state and offsets:
    //        rust_thread_state_static = sym RUST_THREAD_STATE,
    //        rts_runtime_offset = const std::mem::offset_of!(RustThreadState, runtime),
    //        rts_pkru_shadow_offset = const std::mem::offset_of!(RustThreadState, pkru_shadow),
    //        // Runtime ASM state offsets:
    //        rtas_rust_stack_ptr_offset = const std::mem::offset_of!(EncapfnLFIRtAsmState, rust_stack_ptr),
    //        rtas_foreign_stack_ptr_offset = const std::mem::offset_of!(EncapfnLFIRtAsmState, foreign_stack_ptr),
    //        rtas_foreign_code_pkru_offset = const std::mem::offset_of!(EncapfnLFIRtAsmState, foreign_code_pkru),
    //        options(noreturn),
    //    )
    //}

    unsafe extern "C" fn generic_invoke(
      function_call_env: *const AArch64FunctionCallEnv,
      original_sp: *const (),
      stack_spill: usize,
      rt: *const Self,
      function_ptr: *const (),
      // We use InvokeResInner as we don't know the return type at this stage:
      invoke_res: *mut EncapfnLFIInvokeResInner,
    ) -> () {

        // This function is called on top of a stack frame allocated from within
        // assembly. We **must** not panic in here. Be sure to catch all unwinds
        // of any potentially panicing functions here.

        // Safety: the caller of this function guarantees that this parameter
        // is created from a valid, immutable &Self reference.
        let rt: &Self = &*rt;

        // Safety: the caller of this function guarantees that all of the values
        // of this struct have been initialized from the actual machine state
        // that the original function was invoked with. It is allocated on its
        // stack and not aliased anywhere else.
        let function_call_env: &AArch64FunctionCallEnv = unsafe { &*function_call_env };

        // Safety: the rt.asm_state.sobox_lib_handle must be initialized for
        // the Self::new constructor to return such a handle. The !Sync
        // restrictions we place on `Self` ensure that we cannot concurrently
        // access the Sobox lib handle: 
        println!("Getting regs for lib handle {:?}", rt.asm_state.sobox_lib_handle);

        let lfi_regs = unsafe { sbx_lfi_proc_regs(rt.asm_state.sobox_lib_handle) };
        unsafe { *lfi_regs_arg(lfi_regs, 0) = function_call_env.x0 as u64; }
        unsafe { *lfi_regs_arg(lfi_regs, 1) = function_call_env.x1 as u64; }
        unsafe { *lfi_regs_arg(lfi_regs, 2) = function_call_env.x2 as u64; }
        unsafe { *lfi_regs_arg(lfi_regs, 3) = function_call_env.x3 as u64; }
        unsafe { *lfi_regs_arg(lfi_regs, 4) = function_call_env.x4 as u64; }
        unsafe { *lfi_regs_arg(lfi_regs, 5) = function_call_env.x5 as u64; }
        //unsafe { *lfi_regs_arg(lfi_regs, 6) = function_call_env.x6 as u64; }
        //unsafe { *lfi_regs_arg(lfi_regs, 7) = function_call_env.x7 as u64; }
        
   
        // TODO: for now, sbx_invoke assumes that the function result is placed
        // in x0, which we then copy into our InvokeRes. 
        let res = unsafe { sbx_invoke(rt.asm_state.sobox_lib_handle, function_ptr as *mut c_void) };

        // Safety: the caller of this function guarantees that `invoke_res` is
        // a unique pointer to an `EncapfnLFIInvokeRes` type that is valid over
        // the duration of this function, and the `EncapfnLFIInvokeResInner` is
        // located at an offset of 0 bytes within this struct.
        let invoke_res: &mut EncapfnLFIInvokeResInner = unsafe { &mut *invoke_res };
        invoke_res.error = EncapfnLFIInvokeError::NoError;
        invoke_res.x0 = res as usize;

        // Return to the calling assembly function:
    }
}

#[derive(Clone, Debug)]
pub struct EncapfnLFIRtAllocTracker {
    allocations: LinkedList<(*mut (), usize)>,
}

unsafe impl AllocTracker for EncapfnLFIRtAllocTracker {
    fn is_valid(&self, ptr: *const (), len: usize) -> bool {
        // TODO: check all other mutable/immutable pages as well!
        self.is_valid_mut(ptr as *mut (), len)
    }

    fn is_valid_mut(&self, ptr: *mut (), len: usize) -> bool {
        self.allocations
            .iter()
            .find(|(aptr, alen)| {
                (ptr as usize) >= (*aptr as usize)
                    && ((ptr as usize)
                        .checked_add(len)
                        .map(|end| end <= (*aptr as usize) + alen)
                        .unwrap_or(false))
            })
            .is_some()
    }
}

pub struct EncapfnLFISymbolTable<const SYMTAB_SIZE: usize> {
    symbols: [*const (); SYMTAB_SIZE],
}

unsafe impl<ID: EFID> EncapfnRt for EncapfnLFIRt<ID> {
    type ID = ID;
    type AllocTracker<'a> = EncapfnLFIRtAllocTracker;
    type ABI = SysVAArch64ABI;
    type SymbolTableState<const SYMTAB_SIZE: usize, const FIXED_OFFSET_SYMTAB_SIZE: usize> =
        EncapfnLFISymbolTable<SYMTAB_SIZE>;

    fn resolve_symbols<const SYMTAB_SIZE: usize, const FIXED_OFFSET_SYMTAB_SIZE: usize>(
        &self,
        symbol_table: &'static [&'static CStr; SYMTAB_SIZE],
        _fixed_offset_symbol_table: &'static [Option<&'static CStr>; FIXED_OFFSET_SYMTAB_SIZE],
    ) -> Option<Self::SymbolTableState<SYMTAB_SIZE, FIXED_OFFSET_SYMTAB_SIZE>> {
        // TODO: this might use an excessive amount of stack space:
        let mut err: bool = false;

        let symbols = symbol_table.clone().map(|symbol_name| {
            if err {
                // If we error on one symbol, don't need to look up others.
                std::ptr::null()
            } else {
                let symbol = unsafe { sbx_dlsymfn(self.asm_state.sobox_lib_handle, symbol_name.as_ptr(), c"".as_ptr()) };

                if symbol == std::ptr::null_mut() {
                // Did not find a library that exposes this symbol:
                err = true;
                std::ptr::null_mut()
                } else {
                    symbol as *const _
                }
            }
        });

        if err {
            None
        } else {
            Some(EncapfnLFISymbolTable { symbols })
        }
    }
    fn lookup_symbol<const SYMTAB_SIZE: usize, const FIXED_OFFSET_SYMTAB_SIZE: usize>(
        &self,
        index: usize,
        symtabstate: &Self::SymbolTableState<SYMTAB_SIZE, FIXED_OFFSET_SYMTAB_SIZE>,
    ) -> Option<*const ()> {
        symtabstate.symbols.get(index).copied()
    }

    fn allocate_stacked_untracked_mut<F, R>(
        &self,
        requested_layout: core::alloc::Layout,
        fun: F,
    ) -> Result<R, EFError>
    where
        F: FnOnce(*mut ()) -> R,
    {
        unimplemented!()
//        if requested_layout.size() == 0 {
//            return Err(EFError::AllocInvalidLayout);
//        }
//
//        let mut fsp = self.asm_state.foreign_stack_ptr.get() as usize;
//        let original_fsp = fsp;
//
//        // Move the stack pointer downward by the requested size. We always use
//        // saturating_sub() to avoid underflows:
//        fsp = fsp.saturating_sub(requested_layout.size());
//
//        // Now, adjust the foreign stack pointer downward to the required
//        // alignment. The saturating_sub should be optimized away here:
//        fsp = fsp.saturating_sub(original_fsp % requested_layout.align());
//
//        // Check that we did not produce a stack overflow. If that happened, we
//        // must return before saving this stack pointer, or writing to the
//        // pointer.
//        if fsp < self.asm_state.foreign_stack_bottom as usize {
//            return Err(EFError::AllocNoMem);
//        }
//
//        // Save the new stack pointer:
//        self.asm_state.foreign_stack_ptr.set(fsp as *mut ());
//
//        // Call the closure with our pointer:
//        let res = fun(fsp as *mut ());
//
//        // Finally, restore the previous stack pointer:
//        self.asm_state
//            .foreign_stack_ptr
//            .set(original_fsp as *mut ());
//
//        // Fin:
//        Ok(res)
    }


    fn allocate_stacked_mut<'a, F, R>(
        &self,
        layout: core::alloc::Layout,
        alloc_scope: &mut AllocScope<'_, Self::AllocTracker<'_>, ID>,
        fun: F,
    ) -> Result<R, EFError>
    where
        F: for<'b> FnOnce(*mut (), &'b mut AllocScope<'_, Self::AllocTracker<'_>, Self::ID>) -> R,
    {
        self.allocate_stacked_untracked_mut(layout, move |ptr| {
            // Add allocation to the tracker, to allow creation of references
            // pointing into this memory:
            alloc_scope
                .tracker_mut()
                .allocations
                // Use the requested layout here, we don't give access to padding
                // that may be added by `alloc_stacked_untracked`.
                .push_back((ptr, layout.size()));

            let ret = fun(ptr, alloc_scope);

            // Remove this allocation from the tracker. Allocations are made by the
            // global heap allocator, which will never alias allocations, so we can
            // uniquely identify ours by its pointer:
            alloc_scope
                .tracker_mut()
                .allocations
                .retain(|(alloc_ptr, _)| *alloc_ptr != ptr);

            ret
        })
    }
}

#[repr(usize)]
enum EncapfnLFIInvokeError {
    NoError,
    NotCalled,
}

// Depending on the size of the return value, it will be either passed
// as a pointer on the stack as the first argument, or be written to
// %rax and %rdx. In either case, this InvokeRes type is passed by
// reference (potentially on the stack), such that we can even encode
// values that exceed the available two return registers. If a return
// value was passed by invisible reference, we will be passed a
// pointer to that:
#[repr(C)]
pub struct EncapfnLFIInvokeResInner {
    error: EncapfnLFIInvokeError,
    x0: usize,
    x1: usize,
    x8: usize,
}

#[repr(C)]
pub struct EncapfnLFIInvokeRes<RT: SysVAArch64BaseRt, T> {
    inner: EncapfnLFIInvokeResInner,
    _t: PhantomData<T>,
    _rt: PhantomData<RT>,
}

impl<RT: SysVAArch64BaseRt, T> EncapfnLFIInvokeRes<RT, T> {
    fn encode_eferror(&self) -> Result<(), EFError> {
        match self.inner.error {
            EncapfnLFIInvokeError::NotCalled => panic!(
                "Attempted to use / query {} without it being used by an invoke call!",
                std::any::type_name::<Self>()
            ),

            EncapfnLFIInvokeError::NoError => Ok(()),
        }
    }
}

unsafe impl<RT: SysVAArch64BaseRt, T> SysVAArch64InvokeRes<RT, T> for EncapfnLFIInvokeRes<RT, T> {
    fn new() -> Self {
        // Required invariant by our assembly:
        let _: () = assert!(std::mem::offset_of!(Self, inner) == 0);

        EncapfnLFIInvokeRes {
            inner: EncapfnLFIInvokeResInner {
                error: EncapfnLFIInvokeError::NotCalled,
                x0: 0,
                x1: 0,
                x8: 0,
            },
            _t: PhantomData,
            _rt: PhantomData,
        }
    }

    fn into_result_registers(self, _rt: &RT) -> EFResult<T> {
        self.encode_eferror()?;

        // Basic assumptions in this method:
        // - sizeof(usize) == sizeof(u64)
        // - little endian
        assert!(std::mem::size_of::<usize>() == std::mem::size_of::<u64>());
        assert!(cfg!(target_endian = "little"));

        // This function must not be called on types larger than two
        // pointers (128 bit), as those cannot possibly be encoded in the
        // two available 64-bit return registers:
        assert!(std::mem::size_of::<T>() <= 2 * std::mem::size_of::<*const ()>());

        // Allocate space to construct the final (unvalidated) T from
        // the register values. During copy, we treat the memory of T
        // as integers:
        let mut ret_uninit: MaybeUninit<T> = MaybeUninit::uninit();

        // TODO: currently, we only support power-of-two return values.
        // It is not immediately obvious how values that are, e.g.,
        // 9 byte in size would be encoded into registers.
        let x0_bytes = u64::to_le_bytes(self.inner.x0 as u64);
        let x1_bytes = u64::to_le_bytes(self.inner.x1 as u64);
        let ret_bytes = [
            x0_bytes[0],
            x0_bytes[1],
            x0_bytes[2],
            x0_bytes[3],
            x0_bytes[4],
            x0_bytes[5],
            x0_bytes[6],
            x0_bytes[7],
            x1_bytes[0],
            x1_bytes[1],
            x1_bytes[2],
            x1_bytes[3],
            x1_bytes[4],
            x1_bytes[5],
            x1_bytes[6],
            x1_bytes[7],
        ];

        MaybeUninit::copy_from_slice(
            ret_uninit.as_bytes_mut(),
            &ret_bytes[..std::mem::size_of::<T>()],
        );

        EFResult::Ok(ret_uninit.into())
    }

    unsafe fn into_result_stacked(self, _rt: &RT, stacked_res: *mut T) -> EFResult<T> {
        self.encode_eferror()?;

        unimplemented!()
        //// Allocate space to construct the final (unvalidated) T from
        //// the register values. During copy, we treat the memory of T
        //// as integers:
        //let mut ret_uninit: MaybeUninit<T> = MaybeUninit::uninit();

        //// Now, we simply to a memcpy from our pointer. We trust the caller
        //// that is allocated, non-aliased over any Rust struct, not being
        //// mutated and accessible to us. We cast it into a layout-compatible
        //// MaybeUninit pointer:
        //unsafe {
        //    std::ptr::copy_nonoverlapping(stacked_res as *const T, ret_uninit.as_mut_ptr(), 1)
        //};

        //EFResult::Ok(ret_uninit.into())
    }
}

#[repr(C)]
struct AArch64FunctionCallEnv {
    x0: usize,
    x1: usize,
    x2: usize,
    x3: usize,
    x4: usize,
    x5: usize,
    x6: usize,
    x7: usize,
}

/// The amount of bytes to push onto a well-aligned (16 byte) stack pointer to
/// fit the `AArch64FunctionCallEnv` struct and keep the stack pointer well
/// aligned.
const AARCH64_FUNCTION_CALL_ENV_STACK_SIZE: usize =
    (core::mem::size_of::<AArch64FunctionCallEnv>() + 0x0F) & !(0x0F);

macro_rules! invoke_impl_rtloc_register {
    ($regtype:ident, $rtloc:expr, $fnptrloc:expr, $resptrloc:expr) => {
        impl<const STACK_SPILL: usize, ID: EFID>
            SysVAArch64Rt<STACK_SPILL, $regtype<SysVAArch64ABI>>
            for EncapfnLFIRt<ID>
        {
            #[naked]
            unsafe extern "C" fn invoke() {
                core::arch::naked_asm!(
                    concat!(
                        "
                        // Create a new stack frame with a layout compatible to that of
                        // `AArch64FunctionCallEnv`, which contains all parameters
                        // required to invoke the original requested function, but that
                        // we'd override by dispatching to a different C function.
                        //
                        // Save the original stack pointer in a temporary. x9 currently
                        // contains the address of this naked function symbol, which we
                        // are free to overwrite:
                        mov x9,  sp

                        // Create a new stack frame which fits AArch64FunctionCallEnv
                        // and allows us to return back to the original link register. 
                        // The current stack pointer must be aligned to a 16 byte
                        // boundary. Push xzr and x30 (LR) to move the stack pointer
                        // down another 16 byte:
                        stp xzr, x30, [sp, #-0x10]!

                        // Make room for the `AArch64FunctionCallEnv`:
                        sub sp, sp, #{aarch64_function_call_env_stack_size}

                        // Push the argument registers:
                        str x0, [sp, #{aarch64_function_call_env_offset_x0}]
                        str x1, [sp, #{aarch64_function_call_env_offset_x1}]
                        str x2, [sp, #{aarch64_function_call_env_offset_x2}]
                        str x3, [sp, #{aarch64_function_call_env_offset_x3}]
                        str x4, [sp, #{aarch64_function_call_env_offset_x4}]
                        str x5, [sp, #{aarch64_function_call_env_offset_x5}]
                        str x6, [sp, #{aarch64_function_call_env_offset_x6}]
                        str x7, [sp, #{aarch64_function_call_env_offset_x7}]

                        // Load generic_invoke parameters in the saved argument registers
                        // and continue execution in the generic protection-domain
                        // switch routine:
                        // 
                        // We first load the parameters contained in registers into temporaries,
                        // as we otherwise risk overwriting arguments when copying into argument
                        // registers.
                        // 
                        // TODO: this is not always necessary for all permutations of registers.
                        // Maybe we can optimize this away?
                        mov x10, ", $rtloc, "          // Load runtime pointer into x10
                        mov x11, ", $fnptrloc, "       // Load function pointer into x11
                        mov x12, ", $resptrloc, "      // Load the InvokeRes pointer into x12
                        //
                        // Now, prepare the arguments for the generic_invoke function:
                        mov x0,  sp                    // Load AArch64FunctionCallEnv pointer into x0
                        mov x1,  x9                    // Load original function call stack pointer into x1
                        ldr x2,  ={stack_spill}        // Load amount of stack spill into x2
                        mov x3,  x10                   // Load runtime pointer into x3
                        mov x4,  x11                   // Load function pointer into x4
                        mov x5,  x12                   // Load the InvokeRes pointer into x5
                        
                        // Load the generic invoke symbol into x9 and call it:
                        bl  {invoke_fn}
                        //blr x9
                        //udf #0

                        // When we return from the generic_invoke function, we can
                        // restore our original stack pointer and return as well:
                        add sp, sp, #{aarch64_function_call_env_stack_size}
                        ldp xzr, x30, [sp], #0x10
                        ret
                        "
                    ),
                    stack_spill = const STACK_SPILL,
                    invoke_fn = sym Self::generic_invoke,

                    aarch64_function_call_env_stack_size = const AARCH64_FUNCTION_CALL_ENV_STACK_SIZE,
                    aarch64_function_call_env_offset_x0 = const core::mem::offset_of!(AArch64FunctionCallEnv, x0),
                    aarch64_function_call_env_offset_x1 = const core::mem::offset_of!(AArch64FunctionCallEnv, x1),
                    aarch64_function_call_env_offset_x2 = const core::mem::offset_of!(AArch64FunctionCallEnv, x2),
                    aarch64_function_call_env_offset_x3 = const core::mem::offset_of!(AArch64FunctionCallEnv, x3),
                    aarch64_function_call_env_offset_x4 = const core::mem::offset_of!(AArch64FunctionCallEnv, x4),
                    aarch64_function_call_env_offset_x5 = const core::mem::offset_of!(AArch64FunctionCallEnv, x5),
                    aarch64_function_call_env_offset_x6 = const core::mem::offset_of!(AArch64FunctionCallEnv, x6),
                    aarch64_function_call_env_offset_x7 = const core::mem::offset_of!(AArch64FunctionCallEnv, x7),
               );
            }
        }
    };
}

invoke_impl_rtloc_register!(AREG0, "x0", "x1", "x2");
invoke_impl_rtloc_register!(AREG1, "x1", "x2", "x3");
invoke_impl_rtloc_register!(AREG2, "x2", "x3", "x4");
invoke_impl_rtloc_register!(AREG3, "x3", "x4", "x5");
invoke_impl_rtloc_register!(AREG4, "x4", "x5", "x6");
invoke_impl_rtloc_register!(AREG5, "x5", "x6", "x7");

//impl<const STACK_SPILL: usize, const RT_STACK_OFFSET: usize, ID: EFID>
//    SysVAArch64Rt<STACK_SPILL, Stacked<RT_STACK_OFFSET, SysVAArch64ABI>> for EncapfnLFIRt<ID>
//{
//    #[naked]
//    unsafe extern "C" fn invoke() {
//        core::arch::asm!(
//            "
//            // This pushes the stack down by {pushed} bytes. We rely on this
//            // offset below. ALWAYS UPDATE THEM IN TANDEM.
//            push rbx
//            push rbp
//            push r12
//            push r13
//            push r14
//            push r15
//            // BEFORE CHANGING THE ABOVE, DID YOU READ THE COMMENT?
//
//            // Load required parameters in non-argument registers and
//            // continue execution in the generic protection-domain
//            // switch routine:
//            mov r10, [rsp + {pushed} + {rt_stack_offset} + 8]  // Load runtime pointer into r10 from stack offset + 8
//            mov r11, [rsp + {pushed} + {rt_stack_offset} + 16] // Load function pointer into r11 from stack offset + 16
//            mov r12, [rsp + {pushed} + {rt_stack_offset} + 24] // Load the InvokeRes pointer into r12 from stack offset + 24
//            mov r13, ${stack_spill}                            // Copy the stack-spill immediate into r13
//            lea r14, [rip - {invoke_fn}]
//            jmp r14
//            ",
//            stack_spill = const STACK_SPILL,
//            rt_stack_offset = const RT_STACK_OFFSET,
//            invoke_fn = sym Self::generic_invoke,
//            // How many bytes we pushed onto the stack above. This value is also used in
//            // generic_invoke. When updating this value, ALSO UPDATE IT IN GENERIC INVOKE.
//            pushed = const 48,
//            options(noreturn),
//        );
//    }
//}

impl<ID: EFID> SysVAArch64BaseRt for EncapfnLFIRt<ID> {
    type InvokeRes<T> = EncapfnLFIInvokeRes<Self, T>;
}
