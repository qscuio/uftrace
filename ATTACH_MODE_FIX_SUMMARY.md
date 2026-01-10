# Attach Mode Tracing Fix Summary

## Target

Enable **local function tracing** in `uftrace`'s **attached mode**. When `uftrace attach <pid>` is used to trace an already-running process, local functions (compiled with `-pg`) should be traced, but they were not appearing in the output.

---

## Problems Encountered

### Problem 1: Understanding the Attach Mode Flow

**Challenge:** The attach mode has a complex initialization flow involving:
- Library injection via `ptrace` and `dlopen`
- FIFO-based communication between uftrace and the traced process
- Symbol resolution from `/proc/[pid]/maps`
- Multiple tracing mechanisms (mcount rebind, dynamic patching)

**Resolution:** Traced through the code to understand:
1. `cmds/attach.c` creates a FIFO and injects `libmcount.so`
2. `libmcount/mcount.c` detects attached mode via the FIFO existence
3. `mcount_attached_init_thread` runs asynchronously to set up tracing

---

### Problem 2: Rebind Succeeds but No Traces

**Observation:** Debug prints showed:
```
[attach-dbg] rebind returned 1, exec_map->start=...
[attach-dbg] rebind SUCCESS, returning
```

The `mcount_rebind_trace_syms` function was returning success (1 symbol rebound), indicating the GOT entry for `_mcount` was patched. However, no trace output appeared.

**Hypothesis:** The rebind was patching the GOT with the wrong address.

---

### Problem 3: Symbol Interposition (ROOT CAUSE)

**Debugging:** Added debug prints to compare addresses:
```c
extern void uftrace__mcount(void);
fprintf(stderr, "mcount_arch_ops.entry[MCOUNT]=%#lx, uftrace__mcount=%p\n",
    mcount_arch_ops.entry[UFT_ARCH_OPS_MCOUNT], (void *)uftrace__mcount);
```

**Discovery:**
```
mcount_arch_ops.entry[MCOUNT]=0xefa1d76efc40  (glibc's _mcount)
uftrace__mcount=0xefa1d75bed20                 (libmcount's _mcount)
```

**The addresses were different!** The `mcount_arch_ops` struct was pointing to **glibc's `_mcount`** instead of **libmcount's `_mcount`**.

**Root Cause:** When `libmcount.so` is `dlopen`'d into a process that already has glibc loaded, the `_mcount` symbol reference in the static initializer:
```c
const struct mcount_arch_ops mcount_arch_ops = {
    .entry = {
        [UFT_ARCH_OPS_MCOUNT] = (unsigned long)_mcount,  // Resolves to glibc!
        ...
    },
    ...
};
```
...was being resolved to glibc's `_mcount` due to **symbol interposition**. Since glibc's `_mcount` is a no-op profiling stub, the GOT was being patched to point to a function that does nothing.

---

### Problem 4: Build Artifacts Not Updated

**Issue:** After making code changes, the old `.o` files were sometimes being used.

**Resolution:** Performed `make clean && make` to ensure all changes were properly compiled.

---

## Debugging Steps

1. **Added fprintf debug statements** to `libmcount/mcount.c`:
   - Traced `mcount_attached_init_thread` execution
   - Logged `trace_type` from `check_trace_functions`
   - Logged rebind result and `exec_map->start`

2. **Added debug to `libmcount/plthook.c`**:
   - Logged the old and new GOT values being patched

3. **Discovered the mismatch**:
   ```
   old=0xfa5141d4fc40, new=0xfa5141d4fc40  (same!)
   ```
   The "new" value was the same as "old", meaning we were patching with the wrong address.

4. **Compared symbol addresses**:
   - Used `extern void uftrace__mcount(void)` to get the hidden alias address
   - Compared with `mcount_arch_ops.entry[UFT_ARCH_OPS_MCOUNT]`
   - Found they were different, confirming symbol interposition

5. **Verified with `nm` and `readelf`**:
   ```bash
   nm ./libmcount/libmcount.so | grep mcount
   nm -D /usr/lib/aarch64-linux-gnu/libc.so.6 | grep mcount
   ```

---

## The Fix

### Files Modified

#### 1. `arch/aarch64/mcount-support.c`

Changed from using plain symbols to hidden aliases:

```diff
-extern void _mcount(void);
-extern void plt_hooker(void);
-extern void __fentry__(void);
-extern void __dentry__(void);
+extern void uftrace__mcount(void);
+extern void uftrace_plt_hooker(void);
+extern void uftrace___fentry__(void);
+extern void uftrace___dentry__(void);

 const struct mcount_arch_ops mcount_arch_ops = {
     .entry = {
-        [UFT_ARCH_OPS_MCOUNT] = (unsigned long)_mcount,
-        [UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plt_hooker,
-        [UFT_ARCH_OPS_FENTRY] = (unsigned long)__fentry__,
-        [UFT_ARCH_OPS_DYNAMIC] = (unsigned long)__dentry__,
+        [UFT_ARCH_OPS_MCOUNT] = (unsigned long)uftrace__mcount,
+        [UFT_ARCH_OPS_PLTHOOK] = (unsigned long)uftrace_plt_hooker,
+        [UFT_ARCH_OPS_FENTRY] = (unsigned long)uftrace___fentry__,
+        [UFT_ARCH_OPS_DYNAMIC] = (unsigned long)uftrace___dentry__,
     },
     ...
 };
```

#### 2. `arch/aarch64/plthook.S`

Changed `plt_hooker` from `ENTRY` to `GLOBAL` to create the hidden alias:

```diff
-ENTRY(plt_hooker)
+GLOBAL(plt_hooker)
```

The `GLOBAL` macro (defined in `utils/asm.h`) creates both the plain symbol and a hidden `uftrace_` prefixed alias:
```c
#define GLOBAL(sym)             \
    .global sym;                \
    .type sym, %function;       \
sym:                            \
    .global uftrace_ ## sym;    \
    .hidden uftrace_ ## sym;    \
    .type uftrace_ ## sym, %function; \
uftrace_ ## sym:
```

---

## Verification

After the fix:
```
mcount_arch_ops.entry[MCOUNT]=0xe0c3639edd50
uftrace__mcount=0xe0c3639edd50
(Addresses SAME!)

[attach-dbg] mcount_entry called 1 times, child=0xbd3162f10b90
```

The addresses now match, and `mcount_entry` is being called, confirming that the instrumentation is working correctly.

---

## Key Takeaways

1. **Symbol interposition** can cause unexpected behavior when a shared library defines the same symbol as an already-loaded library.

2. **Hidden symbols** (using `.hidden` in assembly or `__attribute__((visibility("hidden")))` in C) are resolved locally within the shared object and are immune to interposition.

3. **The `GLOBAL` vs `ENTRY` macros** in uftrace's assembly code have different purposes:
   - `ENTRY`: Creates a hidden local symbol
   - `GLOBAL`: Creates both a public symbol and a hidden `uftrace_` prefixed alias

4. **Debug prints** comparing expected vs actual addresses are invaluable for diagnosing symbol resolution issues.
