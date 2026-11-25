# stalker

Checking whether a thread is being followed by Frida Stalker, from inside the
process. arm64, libc only, no root.

All numbers below come from a Redmi 9 (Android 12) with frida-server 17.26.2.

## Checks

- **WD-00** — the PC ends up outside every loaded module. Sample it with a
  signal and count. 95 of 95 windows while followed, 0 of 217 false positives.
- **WD-01** — a 400-byte function I call shows up twice in the code slab.
  `payload=2`.
- **WD-02** — the second copy is a byte-for-byte snapshot of the original,
  `0/28` words differ.
- **WD-03** — every translated block ends with `brk #14`. 875 on the CLI,
  398–429 in the app, none at all without a follow.
- **WD-04** — unused inline caches are stamped `0xbaadd00ddeadface`.
  93–100 on the CLI, 113 in the app.
- **WD-05** — the context is a single `0x4D000` rwx mapping, plus an 8 MiB
  overflow slab and a separate rw data slab.
- **WD-06** — if all you want is "is Stalker here", scan for the sentinel
  alone: 34 ms per 88 MB instead of ~120.
- **WD-07** — only the PC-relative instructions change in the copy. 26/28
  identical on the CLI, 24/28 in the app, where `adr` becomes `adrp`+`add`.
- **WD-08** — data the code points at is not copied. Only code and the
  snapshot are.
- **WD-09** — absolute addresses get rebuilt as literal loads, so the copy
  points into Stalker's own pool instead of the original page.
- **WD-10** — the snapshot lands about `0x134`–`0x138` after the code, which
  is why you get two hits per block.
- **WD-11** — all of the above also works from inside an APK. Two hits in a
  1.6 GB address space.
- **WD-12** — the fault happens in the copy, not in the module: the `SIGILL`
  PC was in the anonymous slab.
- **WD-13** — the catch. It depends on where the follow lands. If it lands
  inside a long call, the thread may never come back into the code cache, so
  you can get `payload=0` while Stalker is clearly running. That is a false
  negative, not a missing copy.

## Files

- `wd00.c` — just WD-00. Samples the PC and checks it against the loaded
  modules. No `/proc`, no memory scan.
- `stalker_check.c` — the bigger check: inline-cache magic, context header,
  `brk #14` literal binding, prolog frame. Prints STALKED / RECENT / SUSPECT /
  CLEAN, where RECENT means the context is still mapped but no longer active.
- `longjmp_probe.c` — the test that shows one `siglongjmp` is enough to drop a
  followed thread out of the cache.

## Build

```sh
# NDK r28, API 31
CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang

$CC -O2 -Wall -Wextra -static -o wd00 wd00.c
$CC -O2 -Wall -Wextra -o stalker_check stalker_check.c
$CC -O2 -Wall -Wextra -o longjmp_probe longjmp_probe.c
```

Push them, run them, that's it. `stalker_check --wait 4000` burns CPU instead
of sleeping so a follow actually lands on your loop before the check runs.

## Blog

<!-- paste the link below -->
coming soon
