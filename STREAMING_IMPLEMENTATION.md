# uftrace Stream Subcommand and Attach Improvements

## Overview

This document describes two enhancements to uftrace:

1. **Stream Subcommand**: A new `uftrace stream` command for real-time trace output
2. **Attach Options Support**: Extended `uftrace attach` to support all record options

---

## 1. Stream Subcommand

### Summary

The new `stream` subcommand provides an easier way to enable real-time trace output:

```bash
$ uftrace stream -D2 ./your_program
          [12345] main() {
          [12345]   foo() {
  1.280 us [12345]     } /* foo */
  3.640 us [12345]   } /* main */
```

This is equivalent to `uftrace record --stream` but more intuitive.

### Implementation

**New Files:**
- `cmds/stream.c` - Thin wrapper that sets `opts->stream = true` and calls `command_record()`

**Modified Files:**
- `uftrace.h` - Added `UFTRACE_MODE_STREAM` constant and `command_stream()` declaration
- `uftrace.c` - Added stream mode routing in `update_subcmd()` and main switch

### Usage

```bash
# Real-time streaming with depth filter
uftrace stream -D2 ./program

# With function filter
uftrace stream -F main ./program

# All record options work
uftrace stream --no-libcall -t 1ms ./program
```

---

## 2. Attach Options Support

### Summary

Extended `uftrace attach` to support all options available in `uftrace record`, enabling advanced filtering when attaching to running processes.

### Implementation

**Modified File:**
- `cmds/attach.c` - Extended `setup_attach_environ()` to pass all record options via environment variables

**Supported Options:**
- `-F, --filter` - Function filter
- `-T, --trigger` - Trigger actions  
- `-A, --argument` - Function arguments
- `-R, --retval` - Return values
- `-P, --patch` - Dynamic patching
- `--caller` - Caller filter
- `-D, --depth` - Call depth limit
- `-t, --time-filter` - Time threshold
- `-Z, --size-filter` - Size filter
- `--match` - Pattern matching type

### Usage

```bash
# Attach with function filter
sudo uftrace attach -F outer_func <PID>

# Attach with depth and time filter
sudo uftrace attach -D3 -t 100us <PID>

# Attach with triggers
sudo uftrace attach -T foo@trace-on <PID>
```

---

## Changes Made

### Files Modified
- **cmds/attach.c**: +40 lines (added all record options)
- **uftrace.c**: +5, -8 lines (added stream subcommand)
- **uftrace.h**: +2 lines (stream mode constant and declaration)
- **cmds/stream.c**: +20 lines (new file)

### Removed
- Custom `--lib-path` parsing from attach.c (global parser handles it)

---

## Testing

```bash
# Test stream subcommand
./uftrace stream -D2 /tmp/test_program

# Test attach with options
/tmp/test_program &
PID=$!
sudo ./uftrace attach -D2 -F main $PID
```
