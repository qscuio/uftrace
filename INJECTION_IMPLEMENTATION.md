# Function Hooking Implementation Session Summary

## Date: 2026-01-11

---

## 1. Target Objective

Implement robust **function hooking** for the `uftrace inject` command to support hooking both:
1. **External library functions** (e.g., `puts`, `printf`, custom shared library functions)
2. **Local/static functions** in stripped binaries (using an external symbol file)

The key challenges addressed:
- **GOT patching** for external functions (reliable, no range limits)
- **Trampoline-based hooking** for local functions (overcoming branch range limits)
- **`--with-sym` option** for providing symbols when hooking stripped binaries

---

## 2. Architecture

**Target Platform:** aarch64 (ARM64) Linux

### Key Architectural Constraints

| Constraint | Impact | Solution |
|------------|--------|----------|
| Branch instruction range: ±128MB | Direct `b` instruction cannot reach distant hook functions | Inline trampoline with absolute address |
| Little-endian byte order | Instruction encoding must account for byte order | Correct 64-bit word construction |
| PIE executables | Base address varies at runtime | Parse `/proc/PID/maps` for actual base |
| Stripped binaries | No symbol table | Use external symbol file via `--with-sym` |

### aarch64 Instruction Reference

```
ldr x16, #8   = 0x58000050  (PC-relative literal load, 8 bytes ahead)
br x16        = 0xd61f0200  (unconditional branch to register)
b <offset>    = 0x14000000 | (offset >> 2)  (26-bit signed offset, ±128MB)
```

---

## 3. Implementation Details

### 3.1 Files Modified

| File | Changes |
|------|---------|
| `cmds/inject.c` | Added `--with-sym` option, updated usage, option parsing |
| `utils/inject.c` | Core hooking logic: GOT patching, trampoline, symbol lookup |
| `utils/inject.h` | Function declarations |
| `utils/hook.h` | Plugin API structures |

### 3.2 Key Functions Implemented

#### `find_any_symbol_offset()` - Find LOCAL symbols
```c
static unsigned long find_any_symbol_offset(const char *filepath, const char *symbol)
{
    // Uses nm to find both LOCAL and GLOBAL symbols
    snprintf(cmd, sizeof(cmd), 
             "nm %s 2>/dev/null | grep -E ' [tTwW] %s$' | awk '{print $1}'",
             filepath, symbol);
    // Returns offset on success, 0 on failure
}
```

**Why needed:** `dlsym()` only finds GLOBAL symbols. Static functions have LOCAL binding and require parsing the ELF symbol table directly.

#### `find_got_entry()` - Locate GOT entry for external functions
```c
static int find_got_entry(pid_t pid, const char *func_name, 
                          unsigned long *got_addr, unsigned long *plt_addr)
{
    // Uses readelf -r to find relocation entries
    // Pattern matches both versioned (func@GLIBC) and unversioned symbols
    snprintf(path, sizeof(path),
             "readelf -r %s 2>/dev/null | grep -E ' %s(@|$| )' | awk '{print $1}'",
             exe_path, func_name);
}
```

#### `patch_got_entry()` - Modify GOT directly
```c
int patch_got_entry(pid_t pid, unsigned long got_addr,
                    unsigned long new_func, unsigned long *old_func)
{
    // Read original GOT value
    orig_val = ptrace(PTRACE_PEEKDATA, pid, got_addr, NULL);
    // Write new function address
    ptrace(PTRACE_POKEDATA, pid, got_addr, new_func);
}
```

#### `patch_function_far_aarch64()` - 16-byte inline trampoline
```c
int patch_function_far_aarch64(pid_t pid, unsigned long target,
                               unsigned long far_addr, unsigned char *saved_bytes)
{
    // Build inline trampoline:
    //   ldr x16, #8   (0x58000050) - load address from PC+8
    //   br x16        (0xd61f0200) - branch to x16
    //   .quad addr    - 8-byte target address
    
    trampoline[0] = (0xd61f0200UL << 32) | 0x58000050UL;
    trampoline[1] = far_addr;
    
    ptrace(PTRACE_POKETEXT, pid, target, trampoline[0]);
    ptrace(PTRACE_POKETEXT, pid, target + 8, trampoline[1]);
}
```

#### `apply_hooks_advanced()` - Main hooking orchestration
```c
int apply_hooks_advanced(pid_t pid, unsigned long lib_base,
                         const char *libpath, const char *sym_path)
{
    // 1. Try GOT patching first (most reliable)
    if (find_got_entry(pid, target_name, &got_addr, NULL) == 0) {
        if (patch_got_entry(pid, got_addr, replacement_ptr, NULL) == 0) {
            // Success - external function hooked via GOT
            continue;
        }
    }
    
    // 2. Fall back to direct patching using symbol file
    if (sym_path && exe_base != 0) {
        unsigned long sym_offset = find_any_symbol_offset(sym_path, target_name);
        if (sym_offset != 0) {
            unsigned long target_addr = exe_base + sym_offset;
            patch_function_far_aarch64(pid, target_addr, replacement_ptr, NULL);
        }
    }
}
```

### 3.3 Command-Line Interface

```
uftrace inject [options] <PID>

OPTIONS:
    --lib=PATH       Inject shared library into the target process
    --uninstall=PATH Unload a previously injected library
    --hook=SPEC      Hook a function (format: target=replacement)
    --with-sym=PATH  Symbol file for stripped targets (local func hooks)
    -h, --help       Show this help message

EXAMPLES:
    # Inject a library with hooks
    uftrace inject 1234 --lib /path/to/hooks.so
    
    # Hook local functions in stripped binary
    uftrace inject 1234 --lib hooks.so --with-sym /path/to/unstripped-binary
```

---

## 4. Problems Encountered

### Problem 1: Branch Offset Out of Range

**Symptom:**
```
ERROR: branch offset out of range: 9235879837632
```

**Cause:** The original `patch_function_aarch64()` used a single 4-byte `b` (branch) instruction with a 26-bit signed offset, limiting range to ±128MB. When the hook function (in the injected library) is far from the target function (in the executable), the offset exceeds this limit.

**Solution:** Implemented `patch_function_far_aarch64()` using a 16-byte inline trampoline that places an absolute 64-bit address at the function prologue.

---

### Problem 2: `find_got_entry()` Not Finding Unversioned Symbols

**Symptom:**
```
WARN: GOT hook failed for my_function, function may not be hooked
```

**Cause:** The grep pattern used `' %s@'` which only matched versioned symbols like `puts@GLIBC_2.17`. Custom library functions like `my_function` have no version suffix.

**Original (broken):**
```c
snprintf(path, sizeof(path),
         "readelf -r %s | grep ' %s@' | awk '{print $1}'",
         exe_path, func_name);
```

**Fixed:**
```c
snprintf(path, sizeof(path),
         "readelf -r %s | grep -E ' %s(@|$| )' | awk '{print $1}'",
         exe_path, func_name);
```

---

### Problem 3: `find_symbol_offset()` Not Finding LOCAL Symbols

**Symptom:**
```
WARN: hook failed for local_func (no GOT entry, no symbol)
```

**Cause:** `find_symbol_offset()` uses `dlsym()` which only finds symbols with GLOBAL binding. Static functions (`static void local_func()`) have LOCAL binding in the ELF symbol table.

**Solution:** Created `find_any_symbol_offset()` that uses `nm` to find symbols of any binding:
```c
snprintf(cmd, sizeof(cmd), 
         "nm %s | grep -E ' [tTwW] %s$' | awk '{print $1}'",
         filepath, symbol);
```

The regex `[tTwW]` matches:
- `t` - local text (code) symbol
- `T` - global text symbol
- `w` - weak symbol
- `W` - weak symbol (global)

---

### Problem 4: Missing `#if defined(__aarch64__)` Guard

**Symptom:**
```
error: #endif without #if
```

**Cause:** When adding `patch_function_far_aarch64()`, the function was placed outside the `#if defined(__aarch64__)` preprocessor block.

**Solution:** Added the missing guard:
```c
#if defined(__aarch64__)

int patch_function_far_aarch64(pid_t pid, unsigned long target, ...)
{
    // ...
}

int create_trampoline_aarch64(...)
{
    // ...
}

#elif defined(__x86_64__)
// ...
#endif
```

---

### Problem 5: Test Output Not Visible (Terminal Capture Issue)

**Symptom:** Test commands returned empty output even when the process was running correctly.

**Cause:** The test harness shell environment had issues with stdout/stderr capture for background processes.

**Debug Method:** Created test programs that write to files instead of stdout:
```c
static void local_func(const char *msg) {
    FILE *f = fopen("/tmp/app_out.txt", "a");
    if (f) { fprintf(f, "local: %s\n", msg); fclose(f); }
}
```

**Verification Command:**
```bash
cat /tmp/app_out.txt
# Output:
# local: test      ← Original function
# local: test
# [HOOKED] test    ← After hook applied
# [HOOKED] test
```

---

## 5. Debug Methods Used

### 5.1 Verbose Logging
```bash
./uftrace -v inject $PID --lib /tmp/hooks.so --with-sym /tmp/binary
```

Output example:
```
inject: found local symbol local_func at offset 7d8 in /tmp/test_local
inject: found local_func in symbol file at offset 7d8 (addr c4887f9007d8)
inject: patched c4887f9007d8 with inline trampoline -> ec01791f06d8
hooked local_func via trampoline at c4887f9007d8
applied 1 function hooks
```

### 5.2 Symbol Verification
```bash
# Check symbol binding and offset
nm /tmp/test_local | grep local_func
# Output: 00000000000007d8 t local_func
#                        ^ lowercase = LOCAL binding

# Check GOT/PLT entries
readelf -r /tmp/test_local | grep my_function
# Output: 00000001ffc8  ... R_AARCH64_JUMP_SL ... my_function + 0
```

### 5.3 Instruction Encoding Verification
```bash
# Verify trampoline opcodes
cat > /tmp/test.s << 'EOF'
    ldr x16, target
    br x16
target:
    .quad 0x1234567890abcdef
EOF
as -o /tmp/test.o /tmp/test.s
objdump -d /tmp/test.o
# Output:
#    0: 58000050    ldr     x16, 8 <target>
#    4: d61f0200    br      x16
```

### 5.4 File-Based Output Testing
When terminal output capture fails, use file-based verification:
```c
// Hook writes to file
void hooked_func(const char *msg) {
    FILE *f = fopen("/tmp/output.txt", "a");
    fprintf(f, "[HOOKED] %s\n", msg);
    fclose(f);
}
```

---

## 6. Final Verification Results

### External Function Hook (GOT-based)
```
# Before hook
Hello from target
Hello from target

# After hook (puts -> hooked_puts)
[HOOKED] Hello from target
[HOOKED] Hello from target
```

### Library Function Hook (GOT-based)
```
# Before hook
mylib: Hello from lib caller

# After hook (my_function -> hooked_my_function)
[LIB-HOOKED] intercepted: Hello from lib caller
```

### Local Function Hook (Trampoline-based, stripped binary)
```
# Before hook
local: test
local: test
local: test

# After hook (local_func -> hooked_local via trampoline)
[HOOKED] test
[HOOKED] test
[HOOKED] test
```

---

## 7. Summary

| Feature | Method | Status |
|---------|--------|--------|
| External library functions | GOT patching | ✅ Working |
| Custom library functions | GOT patching (fixed grep pattern) | ✅ Working |
| Local/static functions | Inline trampoline | ✅ Working |
| Stripped binary support | `--with-sym` + `find_any_symbol_offset()` | ✅ Working |

### Key Lessons Learned

1. **GOT patching is most reliable** for external functions - no range limits, works on stripped binaries
2. **LOCAL symbols require special handling** - `dlsym()` doesn't find them, use `nm` instead
3. **Inline trampolines solve range limits** - 16 bytes is enough for absolute jump on aarch64
4. **Grep patterns matter** - version suffixes (`@GLIBC`) vs unversioned symbols need different matching
5. **File-based testing is more reliable** than stdout capture for debugging injection issues
