/*
 * wd01.c - WD-01: prove that Stalker copied your instructions.
 *
 * The payload below is 100 straight-line ADD instructions with different
 * immediates, followed by RET.  None of them is PC-relative and none is a
 * branch, so GumArm64Relocator copies the bytes verbatim:
 *
 *     gum_arm64_relocator_write_one()
 *       -> if (!rewritten)
 *            gum_arm64_writer_put_bytes(ctx->output, insn->bytes, insn->size);
 *
 * Under Stalker the payload appears twice in anonymous memory:
 *
 *     1. the translated block in the RWX code slab
 *     2. the byte-exact snapshot stored next to it
 *
 * Native:  payload=0 (the scanner skips its own executable)
 * Stalked: payload=2
 *
 * Build:
 *   aarch64-linux-android31-clang -O2 -s -o wd01 wd01.c
 *
 * Run:
 *   ./wd01                   one window, 20 calls, one scan
 *   ./wd01 --loop 300        repeat every 300 ms
 *   ./wd01 --calls 50        call the payload 50x per window
 *   ./wd01 --verbose         print every matching region
 */

#include "scan.h"

#include <errno.h>
#include <stdlib.h>

#define PATTERN_INSNS 100
#define PATTERN_SIZE  (PATTERN_INSNS * 4)

#define ADD_BASE      0x91000129u   /* add x9, x9, #imm (imm = bits 21:10) */
#define ADD_FIRST     0x101u
#define RET_ENCODING  0xD65F03C0u

struct stats
{
  unsigned long long file;
  unsigned long long anon;
  unsigned long long regions;
  unsigned long long scanned;
  uintptr_t first;
};

__attribute__((naked, noinline, used))
static void
payload (void)
{
  __asm__ __volatile__ (
      "  .set pi, 257\n"                      /* 0x101 */
      "  .rept 100\n"
      "    .inst 0x91000129 + (pi << 10)\n"
      "  .set pi, pi + 1\n"
      "  .endr\n"
      "  ret\n");
}

static char g_exe[512];

static int
verify_payload (void)
{
  const uint32_t *p = (const uint32_t *) payload;
  int i;

  for (i = 0; i != PATTERN_INSNS; i++)
  {
    uint32_t want = ADD_BASE | ((ADD_FIRST + (uint32_t) i) << 10);

    if (p[i] != want)
    {
      fprintf (stderr,
          "payload mismatch at insn %d: have 0x%08x want 0x%08x\n",
          i, p[i], want);
      return 0;
    }
  }

  if (p[PATTERN_INSNS] != RET_ENCODING)
  {
    fprintf (stderr, "payload does not end in ret: 0x%08x\n",
        p[PATTERN_INSNS]);
    return 0;
  }

  return 1;
}

static void
scan (struct stats *st, int verbose)
{
  FILE *f;
  char line[512];

  memset (st, 0, sizeof (*st));

  f = fopen ("/proc/self/maps", "r");
  if (f == NULL)
  {
    printf ("WD01 cannot open /proc/self/maps: %s\n", strerror (errno));
    return;
  }

  while (fgets (line, sizeof (line), f) != NULL)
  {
    unsigned long lo, hi;
    char perms[8];
    char path[256];
    char *sp;
    int n;
    uintptr_t p, q;
    size_t len;
    size_t hits;
    uintptr_t first = 0;
    int file_backed;

    path[0] = '\0';
    n = sscanf (line, "%lx-%lx %7s %*s %*s %*s %255[^\n]",
        &lo, &hi, perms, path);
    if (n < 3)
      continue;
    if (perms[0] != 'r')
      continue;

    sp = path;
    while (*sp == ' ')
      sp++;

    if (scan_skip_path (sp, g_exe))
      continue;

    p = (uintptr_t) lo;
    q = (uintptr_t) hi;
    len = (size_t) (q - p);
    if (len == 0)
      continue;

    g_guarded = 1;
    if (sigsetjmp (g_fault, 1) == 0)
    {
      hits = scan_count ((const uint8_t *) p, len,
          (const uint8_t *) payload, PATTERN_SIZE, &first);
    }
    else
    {
      g_guarded = 0;
      if (verbose)
        printf ("       (fault at 0x%lx-0x%lx, skipped)\n", lo, hi);
      continue;
    }
    g_guarded = 0;

    st->scanned += len;

    if (hits != 0)
    {
      file_backed = (*sp != '\0');

      if (file_backed)
        st->file += hits;
      else
        st->anon += hits;

      st->regions++;
      if (st->first == 0)
        st->first = first;

      if (verbose)
      {
        printf ("       0x%lx-0x%lx %s %-9s payload=%zu",
            lo, hi, perms, file_backed ? sp : "<anon>", hits);
        printf (" first=0x%lx (region+0x%lx)\n",
            (unsigned long) first, (unsigned long) (first - lo));
      }
    }
  }

  fclose (f);
}

int
main (int argc, char *argv[])
{
  int loop_ms = 0;
  int calls = 20;
  int verbose = 0;
  int i;

  for (i = 1; i < argc; i++)
  {
    if (strcmp (argv[i], "--loop") == 0)
      loop_ms = (i + 1 < argc) ? atoi (argv[++i]) : 300;
    else if (strcmp (argv[i], "--calls") == 0)
      calls = (i + 1 < argc) ? atoi (argv[++i]) : 20;
    else if (strcmp (argv[i], "--verbose") == 0)
      verbose = 1;
    else if (strcmp (argv[i], "--version") == 0)
    {
      printf ("wd01 1.0.0\n");
      return 0;
    }
    else
    {
      fprintf (stderr,
          "usage: %s [--loop ms] [--calls n] [--verbose]\n", argv[0]);
      return 2;
    }
  }

  if (calls < 1)
    calls = 1;

  if (!verify_payload ())
    return 2;

  scan_read_exe (g_exe, sizeof (g_exe));
  scan_install_faults ();

  printf ("WD01 payload @ %p : %d instructions, %d bytes\n",
      (const void *) payload, PATTERN_INSNS, PATTERN_SIZE);
  fflush (stdout);

  for (;;)
  {
    struct stats st;
    unsigned long long total;

    for (i = 0; i != calls; i++)
      payload ();

    scan (&st, verbose);

    total = st.file + st.anon;
    printf ("WD01 %s payload=%llu file=%llu anon=%llu regions=%llu "
            "first=0x%lx scanned=%.0fMB\n",
        (st.anon != 0) ? "DETECTED" : "CLEAN",
        total, st.file, st.anon, st.regions,
        (unsigned long) st.first,
        (double) st.scanned / (1024.0 * 1024.0));
    fflush (stdout);

    if (loop_ms == 0)
      return (st.anon != 0) ? 1 : 0;

    usleep ((useconds_t) loop_ms * 1000u);
  }
}
