# Cross-Compile Testing Guide for uftrace

This document describes how to cross-compile uftrace for different architectures (ARM32, AArch64) and test the builds using QEMU user-mode emulation.

## Prerequisites

### Installing Cross-Compile Toolchains

On Ubuntu/Debian systems:

```bash
# For ARM32 (armhf)
sudo apt-get install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf libc6-armhf-cross

# For AArch64 (arm64)
sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-arm64-cross

# QEMU user-mode emulators
sudo apt-get install qemu-user qemu-user-static binfmt-support
```

### Verifying Installation

```bash
# Check ARM32 compiler
arm-linux-gnueabihf-gcc --version

# Check AArch64 compiler
aarch64-linux-gnu-gcc --version

# Check QEMU
qemu-arm --version
qemu-aarch64 --version
```

---

## Cross-Compiling uftrace

### ARM32 Build

```bash
# Clean previous build
make clean

# Configure for ARM32
./configure --arch=arm --cross-compile=arm-linux-gnueabihf-

# Build
make -j$(nproc)

# Verify the binary
file uftrace
# Expected: ELF 32-bit LSB pie executable, ARM, EABI5 version 1 (SYSV)...

# Verify libmcount libraries
file libmcount/libmcount.so
# Expected: ELF 32-bit LSB shared object, ARM, EABI5...
```

### AArch64 Build

```bash
# Clean previous build
make clean

# Configure for AArch64
./configure --arch=aarch64 --cross-compile=aarch64-linux-gnu-

# Build
make -j$(nproc)

# Verify the binary
file uftrace
# Expected: ELF 64-bit LSB pie executable, ARM aarch64...
```

---

## Testing with QEMU User-Mode

### Basic Execution Test

```bash
# ARM32 - Verify uftrace runs
qemu-arm -L /usr/arm-linux-gnueabihf ./uftrace --version

# AArch64 - Verify uftrace runs  
qemu-aarch64 -L /usr/aarch64-linux-gnu ./uftrace --version
```

### Creating Test Programs

Create a simple test program (`test_hello.c`):

```c
#include <stdio.h>

__attribute__((noinline))
int add(int a, int b) {
    return a + b;
}

__attribute__((noinline))
int multiply(int a, int b) {
    return a * b;
}

__attribute__((noinline))
int compute(int x, int y) {
    int sum = add(x, y);
    int prod = multiply(x, y);
    return sum + prod;
}

int main(void) {
    int result = compute(3, 4);
    printf("Result: %d\n", result);
    return 0;
}
```

### Compiling Test Programs

```bash
# For ARM32 with mcount instrumentation (-pg)
arm-linux-gnueabihf-gcc -pg -g -o test_hello_arm test_hello.c

# For ARM32 with instrument-functions
arm-linux-gnueabihf-gcc -finstrument-functions -g -o test_hello_arm_fi test_hello.c

# For AArch64
aarch64-linux-gnu-gcc -pg -g -o test_hello_aarch64 test_hello.c
```

### Verifying Test Programs Run

```bash
# ARM32
qemu-arm -L /usr/arm-linux-gnueabihf ./test_hello_arm
# Expected output: Result: 19

# AArch64
qemu-aarch64 -L /usr/aarch64-linux-gnu ./test_hello_aarch64
# Expected output: Result: 19
```

---

## QEMU Limitations

> [!WARNING]
> QEMU user-mode emulation has **known limitations** with dynamic tracing features:
> 
> - `LD_PRELOAD` with libmcount may hang or not work as expected
> - Signal-based profiling (`SIGPROF`) may not function correctly  
> - Dynamic memory mapping operations may behave differently
> - Multi-threading support is limited

### What Works in QEMU

- ✅ Basic uftrace command execution
- ✅ Building and linking cross-compiled binaries
- ✅ Verifying binary format and symbols
- ✅ Simple program execution without tracing

### What May Not Work in QEMU

- ❌ Full `uftrace record` with LD_PRELOAD
- ❌ Dynamic patching at runtime
- ❌ Complex multi-threaded tracing
- ❌ Kernel-level tracing features

---

## Real Hardware Testing

For complete functionality verification, test on actual hardware:

### Raspberry Pi (ARM32/AArch64)

```bash
# Copy binaries to target device
scp -r uftrace libmcount/ test_hello_arm pi@raspberrypi:~/

# On the Raspberry Pi
cd ~
./uftrace record -D 3 ./test_hello_arm
./uftrace replay
./uftrace report
```

### Docker with QEMU (binfmt)

For a more complete testing environment:

```bash
# Set up binfmt for automatic QEMU execution
sudo update-binfmts --enable qemu-arm

# Run ARM container
docker run --rm -v $(pwd):/work arm32v7/debian:latest /work/uftrace --version
```

---

## Verifying Dynamic Patching Code

### Check Compiled Object Files

```bash
# ARM32 dynamic patching objects
ls -la arch/arm/*.op

# Expected files:
# arch/arm/mcount-dynamic.op     - Dynamic patching C code
# arch/arm/dynamic.op            - __dentry__ assembly
# arch/arm/fentry.op             - __fentry__ assembly  
# arch/arm/mcount-insn.op        - Instruction analysis
# arch/arm/xray.op               - XRay instrumentation
```

### Disassemble Key Functions

```bash
# Check __dentry__ implementation
arm-linux-gnueabihf-objdump -d arch/arm/dynamic.op | head -60

# Check test binary instrumentation
arm-linux-gnueabihf-objdump -d test_hello_arm | grep -A5 'add>:'
```

---

## Automated Build Verification Script

Create `scripts/cross-build-test.sh`:

```bash
#!/bin/bash
set -e

ARCHES=("arm:arm-linux-gnueabihf" "aarch64:aarch64-linux-gnu")

for entry in "${ARCHES[@]}"; do
    ARCH="${entry%%:*}"
    CROSS="${entry##*:}"
    
    echo "=== Building for $ARCH [$CROSS] ==="
    
    make clean
    ./configure --arch=$ARCH --cross-compile=$CROSS-
    make -j$(nproc)
    
    echo "Verifying build..."
    file uftrace
    file libmcount/libmcount.so
    
    if [ "$ARCH" = "arm" ]; then
        ls arch/arm/*.op | head -5
    elif [ "$ARCH" = "aarch64" ]; then
        ls arch/aarch64/*.op | head -5
    fi
    
    echo "=== $ARCH build complete ==="
    echo
done

echo "All cross-compile builds successful!"
```

---

## Troubleshooting

### "qemu: uncaught target signal 6 (Aborted)"

This typically indicates:
- Library incompatibility between host and target sysroot
- Missing dependent libraries
- Signal handling issues in user-mode emulation

**Solution**: Run with `-strace` for debugging:
```bash
qemu-arm -L /usr/arm-linux-gnueabihf -strace ./uftrace record ... 2>&1 | tail -50
```

### "cannot find libmcount.so"

Ensure the library path is correct:
```bash
qemu-arm -L /usr/arm-linux-gnueabihf ./uftrace --libmcount-path=./libmcount ...
```

### Build Errors: Missing Headers

Install cross-dev packages:
```bash
sudo apt-get install libdw-dev:armhf   # for ARM32
sudo apt-get install libdw-dev:arm64   # for AArch64
```

---

## Architecture-Specific Notes

### ARM32

- Uses `__gnu_mcount_nc` for `-pg` builds
- Dynamic patching replaces prologue with `PUSH {fp, lr}; BL trampoline`
- BL instruction has ±32MB range limitation
- Supports both ARM and Thumb mode (ARM mode preferred for tracing)

### AArch64

- Uses `_mcount` for `-pg` builds  
- Dynamic patching uses `STP x29, x30`; `BL trampoline` sequence
- Full 64-bit address handling via `LDR x16, [pc, #offset]`
- No Thumb equivalent - always 64-bit ARM mode

---

## Summary

| Task | ARM32 Command | AArch64 Command |
|------|---------------|-----------------|
| Configure | `./configure --arch=arm --cross-compile=arm-linux-gnueabihf-` | `./configure --arch=aarch64 --cross-compile=aarch64-linux-gnu-` |
| Build | `make -j$(nproc)` | `make -j$(nproc)` |
| Verify | `file uftrace` | `file uftrace` |
| QEMU Test | `qemu-arm -L /usr/arm-linux-gnueabihf ./uftrace --version` | `qemu-aarch64 -L /usr/aarch64-linux-gnu ./uftrace --version` |

For complete tracing functionality verification, use actual ARM/AArch64 hardware or properly configured Docker/VM environments with full system emulation.
