# stalker

arm64. libc only. no root.

1. **PC sampling** — the PC leaves every loaded module. `wd00.c`
2. **Code-cache artifacts** — IC magic, ctx header, `brk #14` binding, prolog frame. `stalker_check.c`
3. **Coverage** — one `siglongjmp` drops a followed thread out of the cache. `longjmp_probe.c`

```sh
CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang

$CC -O2 -Wall -Wextra -static -o wd00 wd00.c
$CC -O2 -Wall -Wextra -o stalker_check stalker_check.c
$CC -O2 -Wall -Wextra -o longjmp_probe longjmp_probe.c
```

## Blog

<!-- paste the link below -->
coming soon
