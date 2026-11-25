# frida_stalker_detection

Three standalone arm64 tools for detecting — and understanding — Frida Stalker
from inside the target process. No root, no ptrace, libc only.

| file | what it is |
|---|---|
| [`wd00.c`](wd00.c) | **WD-00 only.** Kernel-delivered PC sampling: DETECTED when the interrupted PC leaves every loaded module. No `/proc`, no memory scan, no constants. |
| [`stalker_check.c`](stalker_check.c) | **Layered check.** IC magic + `GumExecCtx` header + `brk #14` literal binding + 256 KiB prolog frame, with a state-aware verdict: `STALKED` / `RECENT` / `SUSPECT` / `CLEAN`. |
| [`longjmp_probe.c`](longjmp_probe.c) | **The false-negative proof.** Shows that one `siglongjmp` out of a signal handler drops a followed thread out of Stalker's code cache while `ctx->state` stays `ACTIVE`. |

## Build

```sh
NDK=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
$NDK/aarch64-linux-android31-clang -O2 -Wall -Wextra -static -o wd00 wd00.c
$NDK/aarch64-linux-android31-clang -O2 -Wall -Wextra          -o stalker_check stalker_check.c
$NDK/aarch64-linux-android31-clang -O2 -Wall -Wextra          -o longjmp_probe longjmp_probe.c
```

## `wd00.c` — the cheapest real detector

```
STALKER  DETECTED sampled=79 inside=0 outside=79  (100% outside)
```

More than 95 of 95 followed windows, 0 of 217 false positives on the test device.
`uc_mcontext.pc` is the PC the kernel saved in the signal frame; Stalker
rewrites `BL`/`ADR`/`ADRP` in userland but cannot rewrite that.

Caveats: only sees threads that run user code (a thread parked in `read()` /
`usleep()` yields no samples); clear the signal mask in JNI-spawned threads.

## `stalker_check.c` — content + structure, with an honest verdict

```
STALKED flags=0x0f ctx=0x76a4874000 tid=29020 state=0 stalker=0x76a5e046f0 \
        stack=0x76a4834000 magic=36 brk14=842 bind=841 maps=199
```

Bits: `0x01` IC magic, `0x02` validated ctx header, `0x04` `brk #14` + valid
literal for **this tid**, `0x08` prolog frame on a 256 KiB RW mapping.

| verdict | condition |
|---|---|
| `STALKED` | valid ctx for `gettid()`, `state == 0`, and at least one structural bit |
| `RECENT` | valid ctx but `state == 1/2` (disarmed or pending GC) |
| `SUSPECT` | IC magic only, no ctx for this tid |
| `CLEAN` | nothing found, and the sentinel ran |

Measured on Redmi 9, arm64-v8a, Android 12, frida-server 17.26.2:

```
native            CLEAN   flags=0x00 magic=0  brk14=0  bind=0
followed (live)   STALKED flags=0x0f magic=36 brk14=842 bind=841 state=0
followed, ended   RECENT  flags=0x0c magic=5  brk14=19  bind=19  state=2
```

`RECENT` is the usual false positive in this family: after `Stalker.unfollow()`
the context sits in `DESTROY_PENDING` and the slab survives until GC.

## `longjmp_probe.c` — why "payload not translated" was wrong

Two 400-byte payloads, one `sigsetjmp` + `raise(SIGUSR1)` + `siglongjmp` at a
chosen point, then a self-scan for exact 400-byte matches:

```sh
./longjmp_probe nojump     # p1=4 p2=3
./longjmp_probe jumpafter  # p1=4 p2=3
./longjmp_probe            # p1=4 p2=1   <- after the jump, nothing is translated
```

`3` = original + translated + snapshot, `1` = original only. A `siglongjmp`
restores the real PC/SP/LR saved by `sigsetjmp`, i.e. an address outside the
code cache, and Stalker has no hook for it. This is the mechanism behind the
`payload=0` false negative in the scanner: the scanner's own fault guard
`siglongjmp`s 2–3 times per 1.6 s scan window.

## Limits

* arm64 only (`uc_mcontext.pc`; x86-64 uses `gregs[REG_RIP]`).
* Constants are versioned: re-derive them when Frida changes
  (`GUM_IC_MAGIC_EMPTY`, `brk #14`, `GUM_STALKER_STACK_SIZE`,
  `GUM_RESTORATION_PROLOG_SIZE`).
* In-process checks need read access to your own mappings; out-of-process needs
  root. Neither detects frida-server itself, only a Stalker context.
