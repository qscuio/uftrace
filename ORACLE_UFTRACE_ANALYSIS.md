# Oracle uftrace Project Analysis

## Scope

This document records the analysis of the `uftrace` checkout on the Oracle/aarch64 workspace.

Workspace path:

```text
/home/ubuntu/work/uftrace
```

Analyzed branch:

```text
feature/dynamic-console-trace
```

The project is not a clean upstream-only checkout.  It is an experimental branch based on uftrace with additional work around real-time streaming, attaching to already-running processes, and library/plugin injection.

## Executive Summary

The base uftrace record/live/replay path is still usable.  A small set of existing tests passed after building the tree.  The new `stream` command has a working prototype for `-pg`/mcount workloads and can emit live function entry/exit records to the console.

The newer `attach` and `inject` work is not yet production-ready.  The code has the right direction, but there are correctness, security, and maintainability issues that need to be fixed before it should be used as a stable debugging facility for long-running daemons.

Current practical classification:

```text
Original uftrace record/live/replay path: mostly usable
stream command: prototype works for simple cases
attach command: design is useful, but currently fragile
inject command: proof of concept, not stable enough yet
plugins: experimental
```

## Repository State Observed

At the time of analysis, the latest commits were:

```text
df0d8ad8 more
481790e3 attach: Fix config file always written for PLT hooking
2941b921 attach: Add debug logging for PLT hook diagnosis
8647851b attach: Fix PLT hooking config propagation
23507511 attach: Enable PLT hooking for attached processes
```

There were untracked test files:

```text
?? tests/arm_test
?? tests/arm_test.c
?? tests/arm_test_fi
```

Those files are ARM32/armhf artifacts, while the Oracle host is aarch64.  Running them directly on the host fails because the armhf dynamic loader is not installed:

```text
/lib/ld-linux-armhf.so.3
```

Recommendation: do not commit these files as normal tests in their current form.  Either remove them or move them under a clearly documented manual/cross-architecture test directory that uses QEMU or an armhf root filesystem.

## Host and Build Environment

Host summary:

```text
Linux qscuio 6.17.0-1011-oracle aarch64
CPU: Neoverse-N1
ptrace_scope: 1
```

The project configuration shows an aarch64 build:

```text
ARCH := aarch64
CC   := gcc
```

A full build completed successfully with:

```bash
make -j2
```

The build produced warnings, but no fatal errors.  Notable warning areas:

```text
utils/eh-frame.c: mixed declarations / unused variable / maybe-uninitialized
utils/inject.c: readelf command snprintf truncation warning
plugins/netlinkmon.c: fprintf format warning
plugins/sockmon.c: unused variables
```

These warnings do not block the build, but they show that the experimental code needs cleanup before upstream-quality use.

## Functional Validation Performed

A few existing uftrace tests were run using gcc, `-pg`, and `-O0`:

```bash
python3 tests/runtest.py -p -c gcc -O 0 -t 10 001 -v
python3 tests/runtest.py -p -c gcc -O 0 -t 10 002 -v
python3 tests/runtest.py -p -c gcc -O 0 -t 10 009 -v
```

Results:

```text
001 basic    OK
002 argument OK
009 fork     OK
```

This indicates that the original record/live/replay path has not been fundamentally broken by the current branch.

Manual stream validation was performed with a small aarch64 test program compiled with `-pg` and with a non-instrumented build for dynamic patching.  The following pattern is important when testing local build artifacts:

```bash
./uftrace ... --libmcount-path=/home/ubuntu/work/uftrace ...
```

Without `--libmcount-path`, tests may accidentally use an installed/system `libmcount` instead of the just-built one.

Observed behavior:

```text
stream + -pg: works for simple programs
stream + -P function: produces live output, but symbol resolution can degrade to raw addresses
```

## New Functionality Added by the Branch

### `stream` Command

The branch adds a `stream` subcommand:

```bash
uftrace stream [options] <program>
```

Implementation summary:

```text
cmds/stream.c
  -> sets opts->stream = true
  -> calls command_record()

libmcount/stream.c
  -> sends UFTRACE_MSG_STREAM_TRACE messages for function entry/exit
```

The stream message currently carries:

```text
time
function address
tid
depth
entry/exit type
duration for exit records
```

This is a useful direction because it turns uftrace from a mostly offline record/replay tool into a live console tracing tool.  That is valuable for debugging long-running services and control-plane daemons.

Limitations:

- Output formatting is still basic.
- Symbol resolution is incomplete in some dynamic patching cases.
- Argument/return-value display is not integrated into streaming output.
- Module/source-line information is not yet on par with replay/report output.

### `attach` Command

The branch adds:

```bash
uftrace attach <PID>
```

Design summary:

```text
cmds/attach.c
  -> creates /tmp/uftrace-attach/<pid>.sock FIFO
  -> writes /tmp/uftrace-attach/<pid>.cfg
  -> injects libmcount.so into the target process
  -> reads stream records back from the FIFO

libmcount/mcount.c
  -> detects attached mode
  -> starts mcount_attached_init_thread
  -> initializes PLT/dynamic/mcount tracing paths
  -> emits stream records through the attached FIFO
```

The design is useful, but the current implementation should be treated as experimental.

### `inject` Command

The branch adds:

```bash
uftrace inject <PID> --lib <plugin.so>
```

Related files:

```text
cmds/inject.c
utils/inject.c
utils/hook.h
plugins/*.c
```

The intended hook strategy is:

```text
External/library functions: GOT patching
Local/static functions: symbol-file lookup plus aarch64 inline trampoline
```

The plugin API is centered around exported symbols such as:

```text
uftrace_hooks
uftrace_hooks_count
uftrace_features
uftrace_features_count
```

This is a proof-of-concept foundation for runtime instrumentation plugins, but it is not yet robust enough for production use.

## Key Problems Found

### 1. `ptrace_scope` Handling Blocks Valid Attach Cases

`utils/inject.c` currently rejects injection when `/proc/sys/kernel/yama/ptrace_scope` is greater than zero:

```c
scope = check_ptrace_scope();
if (scope > 0) {
    pr_warn(...);
    return -1;
}
```

This is too strict.  `ptrace_scope=1` does not always mean attach is impossible.  Attach can still be valid for root, for suitable parent/child relationships, for targets that call `PR_SET_PTRACER`, or when the process has the required capability.

Observed result: a test target that called `PR_SET_PTRACER, PR_SET_PTRACER_ANY` still failed before a real attach attempt because the code returned early.

Recommended fix: warn when `ptrace_scope > 0`, but do not return early.  Attempt `PTRACE_ATTACH` and report the real kernel error if it fails.

### 2. Attach Options Are Not Reliably Propagated to the Target

`cmds/attach.c` sets many options using `setenv()` in the uftrace process:

```text
UFTRACE_DEPTH
UFTRACE_THRESHOLD
UFTRACE_FILTER
UFTRACE_TRIGGER
UFTRACE_ARGUMENT
UFTRACE_RETVAL
UFTRACE_PATCH
UFTRACE_CALLER
UFTRACE_PATTERN
```

But the target process is already running.  Environment changes in the injector process do not modify the target process environment.

The code also writes a small cfg file for attached mode, but currently only a subset of options is written there, mainly:

```text
UFTRACE_PLTHOOK
UFTRACE_SYMBOL_DIR
```

Recommended fix: write all attach-time options into `/tmp/uftrace-attach/<pid>.cfg` and make the attached libmcount initialization read configuration exclusively from that file or from an explicit control channel.

### 3. Fixed `/tmp/uftrace-attach` Path Is Unsafe

The attached-mode IPC currently uses a fixed directory:

```text
/tmp/uftrace-attach
```

and PID-based FIFO names:

```text
/tmp/uftrace-attach/<pid>.sock
```

Issues:

- predictable global path
- directory mode is not private enough
- PID-only naming can collide or be raced
- file extension says `.sock` even though the object is a FIFO
- unlink/create patterns invite race conditions

Recommended fix: use a per-user private directory such as:

```text
/run/user/<uid>/uftrace-attach
```

or a secure `mkdtemp()` directory with mode `0700`, plus a random session identifier.

### 4. `utils/inject.c` Is Too Large and Mixed-Concern

`utils/inject.c` now mixes many layers:

```text
ptrace attach/detach
remote dlopen/dlclose
x86_64 remote call logic
aarch64 remote call logic
GOT lookup
shell-based readelf/nm parsing
inline patching
plugin hook processing
uninject logic
```

This makes the code difficult to review and unsafe to extend.

Recommended split:

```text
utils/ptrace-remote.c
utils/remote-call-aarch64.c
utils/remote-call-x86_64.c
utils/elf-reloc.c
utils/hook-got.c
utils/hook-inline-aarch64.c
utils/inject-plugin.c
cmds/inject.c
```

### 5. Shelling Out to `readelf`, `grep`, `awk`, and `nm` Is Fragile

The code currently uses shell commands to locate symbols and relocations.  Example pattern:

```text
nm <file> | grep ... | awk ...
readelf -r <file> | grep ... | awk ...
```

Issues:

- paths and symbols are not safely shell-escaped
- paths with spaces can break
- error handling is weak
- performance is poor
- address calculations are easy to get wrong
- this duplicates functionality uftrace already has around ELF/symbol handling

Recommended fix: use libelf or existing uftrace symbol/ELF helpers to parse symbols and relocations directly.

### 6. PIE Address Calculation Is Likely Incorrect in Some Cases

Several paths use formulas equivalent to:

```text
runtime_address = executable_mapping_start + symbol_or_relocation_offset
```

For PIE and ELF virtual addresses, this is not generally correct.  The mapping file offset must be considered:

```text
load_bias = map_start - map_offset
runtime_address = load_bias + elf_virtual_address
```

Recommended fix: centralize runtime address calculation and always account for mapping offset/load bias.

### 7. aarch64 Inline Trampoline Hooking Is Not Production-Safe Yet

The local-function hook path writes a 16-byte inline trampoline:

```asm
ldr x16, #8
br  x16
.quad hook_addr
```

Problems:

- no validation that the function prologue is safely patchable
- no BTI/PAC handling
- no stop-the-world handling for all threads
- no robust original-function trampoline support
- no reliable restore/unhook path
- `struct uftrace_hook.original` is not fully honored

Recommended fix: treat this as a demo-only mechanism until it has instruction decoding, trampoline generation, thread coordination, and restoration support.

### 8. SIGUSR1/SIGUSR2 Control Can Conflict With Target Applications

Attached mode currently uses signals for control:

```text
SIGUSR1: enable/start attached tracing
SIGUSR2: disable/stop attached tracing
```

Many daemons already use these signals for their own semantics.  This is risky for production service debugging.

Recommended fix: use the attach FIFO/socket control channel for start/stop commands, or allow the signals to be configured explicitly.

## Recommended Work Plan

### Phase 1: Stabilize the Useful Minimum

Target minimal reliable workflow:

```bash
uftrace attach -D3 -F <function> <pid>
```

Required fixes:

1. Do not return early on `ptrace_scope > 0`.
2. Write all attach options to the cfg/control channel.
3. Make attached-mode libmcount read all config from that channel.
4. Add a simple attach integration test for an aarch64 `-pg` target.
5. Ensure `--libmcount-path` is honored and documented for local builds.

### Phase 2: Make `stream` Usable for Real Debugging

Improve live output parity with replay:

1. Reliable symbol/module resolution for `-pg` and `-P`.
2. Optional module name output.
3. Optional argument/return-value output.
4. Better formatting and color handling.
5. Clear behavior for filtering and depth/time thresholds.

### Phase 3: Harden IPC and Cleanup

1. Replace fixed `/tmp/uftrace-attach` with a private per-user/session directory.
2. Rename FIFO/socket paths accurately.
3. Avoid signal-based control by default.
4. Add cleanup for stale attach files.

### Phase 4: Rework Injection Internals

1. Split `utils/inject.c` by responsibility.
2. Replace shell-based symbol/relocation parsing.
3. Fix PIE/load-bias address handling.
4. Add real original-function trampoline support.
5. Add safe unhook/restore semantics.

## Suggested Tests to Add

Minimum tests for this branch:

```text
stream_pg_basic: stream a -pg aarch64 test binary
stream_dynamic_basic: stream a -P function dynamic-patched binary
attach_pg_basic: attach to a running -pg target and capture a known function
attach_filter_depth: verify -F and -D are honored in attached mode
inject_got_puts: inject a plugin that hooks puts/printf through GOT
pie_load_bias: verify hooks work for PIE and non-PIE binaries
```

The existing untracked `tests/arm_test*` should not be used as native tests on the aarch64 host unless a QEMU/armhf execution environment is explicitly configured.

## Practical Value for Control-Plane Debugging

The most useful direction for this branch is not generic plugin injection first.  The immediate value is real-time attach-based tracing for long-running daemons.

A stable version of this would be useful for investigating paths like:

```text
CLI/config input
  -> config daemon
  -> state/database layer
  -> routing/switching daemon
  -> ASIC/programming daemon
```

For timeout and latency problems, the desired end state is to run something like:

```bash
uftrace attach -D3 -F db_write <pid>
```

and immediately see the function-level path and timing without restarting the daemon.

## Bottom Line

This branch has a valuable direction: extend uftrace from an offline record/replay tracer into a live attach/stream debugging tool.  The `stream` path is the strongest part today.  The `attach` and `inject` paths need correctness and safety work before they can be trusted.

Recommended next step: pause feature expansion and stabilize `attach + stream` first.  Once that path reliably traces a running aarch64 `-pg` daemon with filters and depth control, revisit plugin injection and inline hooking.
