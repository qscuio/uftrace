# uftrace Streaming Trace Implementation

## Overview

This document summarizes the implementation of the `--stream` option for uftrace, which enables real-time trace output to the console as the program executes.

## Feature Summary

The `--stream` option allows users to see function call traces in real-time, rather than waiting for the program to complete:

```bash
$ ./uftrace --stream --no-libcall ./your_program
          [12345] main() {
          [12345]   foo() {
  1.280 us [12345]     } /* foo */
  3.640 us [12345]   } /* main */
```

---

## Implementation Flow

### Phase 1: Command-Line Interface

1. **Added `--stream` option** in `uftrace.c`
   - Parsed as a boolean flag
   - Stored in `struct uftrace_opts.stream`

2. **Added message type** in `uftrace.h`
   - `UFTRACE_MSG_STREAM_TRACE = 50`
   - `struct uftrace_msg_stream` containing: time, addr, tid, depth, type, duration

### Phase 2: libmcount (Tracer Side)

3. **Created `libmcount/stream.c`**
   - Implemented `stream_trace_entry()` function
   - Sends trace data via the existing pipe to the recorder

4. **Modified `libmcount/mcount.c`**
   - Read `UFTRACE_STREAM` environment variable in `mcount_startup()`
   - Added streaming calls to entry/exit filter functions (both slow and fast paths)

5. **Updated `libmcount/internal.h`**
   - Declared `extern bool mcount_stream_mode;`
   - Declared `stream_trace_entry()` function

### Phase 3: Recorder Side (Symbol Resolution)

6. **Modified `cmds/record.c`**
   - Set `UFTRACE_STREAM=1` environment variable when `--stream` is enabled
   - Implemented `read_live_proc_maps()` to read `/proc/[pid]/maps` from the traced process
   - Added `UFTRACE_MSG_STREAM_TRACE` handler to receive and print trace events
   - Integrated symbol resolution using `find_symtabs()` and `symbol_getname()`

---

## Problems Encountered and Debugging

### Problem 1: Streaming Output Not Appearing

**Symptom**: When running with `--stream`, no trace output appeared on the console.

**Root Cause**: The streaming logic was placed in `record_trace_data()` in `libmcount/record.c`, which:
- Is only called when the trace buffer is flushed
- Not called frequently enough for real-time output
- When using `libmcount-fast.so`, this path is rarely executed

**Debug Method**:
- Added `fprintf(stderr, "DEBUG: ...")` statements to trace execution flow
- Discovered that `mcount_entry_filter_record()` and `mcount_exit_filter_record()` were the correct places for streaming calls

**Solution**: Moved streaming calls to `mcount_entry_filter_record()` and `mcount_exit_filter_record()` functions in `libmcount/mcount.c`, which are called on every function entry/exit.

---

### Problem 2: Wrong libmcount Being Loaded

**Symptom**: Debug prints in modified code didn't appear.

**Root Cause**: System-installed version of `libmcount.so` was being loaded instead of the locally built one.

**Debug Method**:
- Used `ldd` and checked library paths
- Verified with `--libmcount-path` option

**Solution**: Always use `--libmcount-path=$(pwd)` during development to load the local build.

---

### Problem 3: Segmentation Fault During Symbol Resolution

**Symptom**: When attempting to resolve symbols using `find_symtabs()`, uftrace crashed with a segfault.

**Root Cause**: Multiple issues:
1. `stream_sym_info.maps` was not properly populated
2. Symbol loading infrastructure expects a fully initialized environment

**Debug Method**:
- Added step-by-step debug prints around symbol resolution code
- Temporarily disabled symbol resolution to isolate the issue
- Used conditional compilation to test different approaches

**Solution**: Implemented `read_live_proc_maps()` function to properly read and parse `/proc/[pid]/maps` from the traced process.

---

### Problem 4: All Addresses Treated as Kernel Addresses

**Symptom**: Symbol lookup returned NULL for all addresses. Debug output showed `map=0x1` (which is `MAP_KERNEL`).

**Root Cause**: `stream_sym_info.kernel_base` was 0 (default value). The check `addr >= sinfo->kernel_base` (i.e., `addr >= 0`) returned true for ALL addresses, causing them to be treated as kernel addresses.

**Debug Method**:
```c
pr_dbg2("Stream: addr=%lx map=%p\n", (unsigned long)stream.addr, m);
// Output: map=0x1  (MAP_KERNEL constant)
```

This revealed that `find_map()` was returning `MAP_KERNEL` instead of the actual memory map.

**Solution**: Set `stream_sym_info.kernel_base = -1ULL` (maximum 64-bit value) to ensure no user-space address is classified as a kernel address.

```c
/* Set to max value to disable kernel address detection */
stream_sym_info.kernel_base = -1ULL;
```

---

### Problem 5: Symbol Names Showing as `<address>` Format

**Symptom**: Output showed `<400874>` instead of `main`.

**Root Cause**: `symbol_getname()` returns formatted addresses when it can't find a symbol. This happens when `find_symtabs()` returns NULL.

**Debug Method**:
```c
sym = find_symtabs(&stream_sym_info, stream.addr);
name = symbol_getname(sym, stream.addr);
pr_dbg2("Stream: addr=%lx sym=%p name=%s\n", stream.addr, sym, name);
// Output: sym=(nil) name=<400874>
```

**Solution**: This was a symptom of Problem 4. Once `kernel_base` was fixed, symbols resolved correctly.

---

## Key Code Changes

### New Files
- `libmcount/stream.c` - Streaming trace entry implementation

### Modified Files
| File | Changes |
|------|---------|
| `uftrace.h` | Added stream option, message type, and struct |
| `uftrace.c` | Added --stream CLI option parsing |
| `libmcount/internal.h` | Declared streaming mode and function |
| `libmcount/mcount.c` | Added streaming calls and env var reading |
| `cmds/record.c` | Added live proc maps reading and symbol resolution |

---

## Lessons Learned

1. **Understand the execution paths**: Different compiler flags (`-O2` vs no optimization) cause different libmcount variants to be used (fast vs slow path).

2. **Initialize all fields**: Uninitialized struct fields (like `kernel_base = 0`) can cause subtle bugs that are hard to diagnose.

3. **Use debug prints strategically**: Adding debug prints at each stage of processing helps identify where things go wrong.

4. **Verify the right code is running**: When modifying shared libraries, ensure the correct version is being loaded.

5. **Test incrementally**: Disable features (like symbol resolution) to isolate which component is causing issues.

---

## Testing

```bash
# Build
make clean && make -j4

# Test with non-PIE
gcc -pg -no-pie -o /tmp/test test.c
./uftrace --libmcount-path=$(pwd) --stream --no-libcall /tmp/test

# Test with PIE (default)
gcc -pg -o /tmp/test_pie test.c
./uftrace --libmcount-path=$(pwd) --stream --no-libcall /tmp/test_pie
```

Both should show proper function names in real-time.
