
<h1>LFI <img src="assets/lfi-logo.svg" alt="logo" width="30px"/></h1>

![Test Workflow](https://github.com/zyedidia/lfi/actions/workflows/test.yaml/badge.svg)
[![MPL License](https://img.shields.io/badge/license-MPL%202.0-blue)](https://github.com/zyedidia/lfi/blob/master/LICENSE)

LFI is a performant and secure software sandboxing system targeting the ARM64
and x86-64 architectures. LFI allows you to run ~64K (ARM64) or ~3K (x86-64)
sandboxes in a single address space while guaranteeing that the sandboxes
cannot read or write each other's memory. Each sandbox may be given up to 4GiB
of memory. These sandboxes are very efficient: on ARM64 they run with
roughly 7% overhead compared to native code when sandboxing reads and writes,
and 1.5% overhead when only sandboxing writes (x86-64 has slightly higher
overheads). Since all sandboxes exist in the same address space, context
switches do not require changing the CPU's privilege level (i.e., transitioning
to kernel mode).

LFI's support for x86-64 is in-progress and does not yet include a complete
static verifier. The scalability limit of 3K sandboxes on x86-64 will also be
configurable, allowing up to 32K sandboxes at the cost of some additional
overhead. At the moment, we have measured overheads of ~9-10% on x86-64 for
full sandboxing.

# Technical Summary

The LFI sandboxer only accepts ELF binaries that pass a verification step to
ensure they are safe to run. This verifier works by analyzing binary machine
code to ensure that the program will not access memory outside of its 4GiB
region or execute any system calls or other "unsafe" instructions. The verifier
is extremely simple, and is implemented in only a few hundred lines of code,
located in `lfi-verify/src/verifier.rs`. Thanks to the verifier, the compiler
used to generate the code is untrusted, so bugs in LLVM or GCC cannot cause
security vulnerabilities. This approach is both more secure and more performant
than current approaches that rely on a trusted compiler like Cranelift. The
verifier is also efficient, and can process machine code at a throughput of
roughly 30 MiB/s on a Macbook Air. On ARM64, we also have optimizations that
allow the verifier to process code at a throughput of 500 MiB/s, and we are
working on adapting this to x86-64.

In addition, LFI binaries may be generated by any LFI-compatible compiler
toolchain. LFI-compatible Clang and GCC toolchains are provided.

The core of the LFI toolchain is an assembly rewriter that reads arbitrary GNU
assembly files (`.s`) and produces assembly files that will pass verification
when compiled and linked. This rewriter is implemented as a set of PEG parsers
that are compiled to C using Leg, and consists of roughly 2,000 lines of code
total (ARM64 and x86-64). It is located in `lfi-leg/`.

LFI-compatible programs are performant: on the SPEC 2017 benchmark suite, we
measured a runtime overhead of 7% and a code size overhead of 14% for full
isolation. This compares well with LLVM-based ahead-of-time WebAssembly
compilers, which incur upwards of 20% runtime overhead. Additionally, LFI can
be used for pure fault isolation, where sandboxes may read, but not write,
each other's memory. In this case, we measured a runtime overhead of around 1.5%.

LFI is also secure: the compiler toolchain used to
produce LFI-compatible programs is not a part of the trusted code base, and LFI
is significantly more Spectre-resistant compared to WebAssembly.

LFI supports all source-level language features and targets the ARMv8.0-A ISA
(including SIMD) plus the ARMv8.1 LSE extension.

The last component of an LFI system is the runtime, which loads programs and
handles runtime calls (e.g., syscalls) on their behalf. To create your own
runtime, you can use `liblfi`, which provides utility functions for creating and
running sandboxes, and handling runtime calls (it is up to you what runtime
calls are available and what they do).

The `lfi-run` program is an example LFI runtime that behaves like a subset of
Linux, and can be used to run many programs compiled for Linux with an LFI
toolchain. This runtime is useful for running benchmarks such as SPEC 2017.

LFI is currently in development and is a research project.

# Publication

Zachary Yedidia. "Lightweight Fault Isolation: Practical, Efficient, and Secure Software Sandboxing." ASPLOS 2024. [Link](https://zyedidia.github.io/papers/lfi_asplos24.pdf).

# Tools

The LFI project provides the following tools:

* `lfi-leg`: reads a `.s` file, and produces an LFI-compatible `.s` file.
* `lfi-verify`: verifies ELF binaries for LFI-compatibility.
* `lfi-postlink`: patches binaries after linking (required for metering and
  certain x86-64 optimizations).
* `lfi-run`: runs an LFI-compatible binary.
* `lfi-compile`: acts like a compiler, but creates an intermediate `.s`
  file during compilation and runs `lfi-leg` on it. Meant to be used with
  `clang`/`clang++`.

# Installation

There are two components to LFI: a compiler toolchain that can build
LFI-compatible binaries, and a runtime library for creating, verifying, and
managing sandboxes. For either of these components, you can either use prebuilt
versions provided with releases, or build from source.

## Prebuilt distribution

Prebuilt toolchains are provided in the GitHub releases:
https://github.com/zyedidia/lfi/releases/. The prebuilt toolchain includes
a full GCC compiler, as well as LLVM runtime libraries and Clang wrappers.
Note: to use the Clang toolchain you must have an externally installed
version of Clang, while the GCC toolchain provides all necessary binaries
internally.

When you download a prebuilt toolchain, you will see the following directories:

* `bin/`: contains the LFI rewriter, verifier, and runtime. Put this on your
  `PATH`.
* `gcc/`: contains a complete LFI GCC toolchain. The C and C++ compilers can be
  found in `gcc/aarch64_lfi-linux-musl/bin/` as `aarch64_lfi-linux-musl-gcc`
  and `aarch64_lfi-linux-musl-g++`. You may want to put this directory on your
  `PATH` (`gcc/aarch64_lfi-linux-musl/bin/`).
* `clang/`: contains a Clang-compatible LFI sysroot and runtime libraries,
  plus wrapper scripts. You can run the `lfi-clang` and `lfi-clang++` scripts
  in `clang/bin/` to invoke your system Clang with the LFI sysroot. You may
  want to put this directory on your `PATH` (`clang/bin/`).

The x86-64 toolchain only supports GCC by default (patches to LLVM are required
to use Clang).

You will also find libraries in the prebuilt archives. The `liblfi` and
`liblfiverify` libraries allow you to write your own runtime with your own
runtime call API. The `liblfileg` library allows you to use the rewriter as a
library. See the files installed to `include` and `lib` in the provided
archives for details.

## Building from source

To install the tools, you must have the following dependencies installed:

* Go for `lfi-compile` and running tests.
* GCC or Clang for `lfi-leg`/`lfi-verify`/`lfi-postlink`/liblfi`.
* LDC (`apt install ldc`) for `lfi-run`.

LFI uses the Meson build system with Ninja. When configuring the build you will
be alerted of any missing dependencies.

To perform a complete build of all tools and of both a GCC and Clang toolchain run

```
./install-toolchain.sh $PWD/lfi-toolchain $ARCH # ARCH is aarch64_lfi or x86-64
```

Note: if you get an error about `asm/types.h` not found while building LLVM
libc++, you may have to symlink `/usr/include/asm-generic` to
`/usr/include/asm`.

Running the script may take a long time (10-15 minutes) as it will build a
compiler toolchain for you along with the standard LFI tools/libraries.

To build just the LFI tools/libraries from source, run the following:

```
meson setup build --prefix=$PWD/install
cd build
ninja install
```

You will find the generated binaries, libraries, and headers in `$PWD/install`
(or in your prefix of choice). Before building a compiler toolchain, you should
make sure the installed `bin` directory is on your `PATH`.

For more details about building a compiler toolchain, see
[lfi-gcc](https://github.com/zyedidia/lfi-gcc) and
[lfi-clang](https://github.com/zyedidia/lfi-clang). These are included as
submodules in the `toolchain` directory.

# Example

Once you have installed all the tools, you can build simple programs.

```
#include <stdio.h>
int main() {
    printf("Hello from LFI\n");
    return 0;
}
```

With Clang:

```
$ lfi-clang hello.c -O2 -o hello
$ lfi-verify hello # check if it verifies (also performed by lfi-run)
verifying test
verification passed (3.2 MB/s)
$ lfi-run hello
Hello from LFI
```

And with GCC:

```
$ aarch64_lfi-linux-musl-gcc hello.c -O2 -o hello -static-pie
$ lfi-run hello
Hello from LFI
```

# Advanced Usage

The `lfi-leg` rewriter tool supports options for configuring the sandboxing approach.

```
Usage: lfi-leg [OPTION...] INPUT
lfi-gen: rewrite assembly files to be compatible with LFI

  -a, --arch=ARCH            Set the target architecture (arm64,amd64)
      --cfi=TYPE             Select CFI mechanism (bundle16,bundle32)
      --no-guard-elim        Do not run redundant guard elimination
      --no-segue             Do not use segment register to store the sandbox
                             base
  -o, --output=FILE          Output to FILE instead of standard output
      --poc                  Produce position-oblivious code (implies
                             --sys-external)
      --single-thread        Specify single-threaded target
      --sys-external         Store runtime call table outside sandbox
  -s, --sandbox=TYPE         Select sandbox type
                             (full,stores,bundle-jumps,none)
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

Some notes:

* By default, LFI on x86-64 uses 16-byte bundles. We have measured better
  performance with 32-byte bundles on Intel machines, and better performance
  with 16-byte bundles on AMD machines.
* The `--sandbox` option can be used to configure isolation granularity. With
  `stores`, only stores and control-flow is sandboxed. Programs are allowed to
  read outside of their memory. With `bundle-jumps`, LFI only enforces that
  bundles are the targets of jumps, but does not enforce that jumps are
  constrained to the sandbox, and does not enforce memory isolation.
* The `--single-thread` option in combination with `--sandbox=bundle-jumps`
  allows for more efficient return sequences, but is only applicable when
  sandboxed programs are single-threaded.

# Roadmap

The LFI project is currently under development. The focus is on the following
features:

* New capabilities and full security for the runtime.
* Optimized integration with WebAssembly (efficiently run WebAssembly inside LFI).
* Support for dynamic recompilation to other architectures.
* Native support for x86-64 and RISC-V.
* Instrumentation of static binaries, so you don't need to recompile your program.
* Support for cool new features that are not yet announced.
* Support for Arm software context IDs for mitigating Spectre attacks (requires
  modifications to Linux, which Arm will hopefully implement soon).
