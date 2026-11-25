/*
 * wd02.c - WD-02: the second copy is a byte-exact snapshot.
 *
 * WD-01 proves the body exists in the slab.  WD-02 asks a sharper question:
 * of the two copies, which one is the translated block and which one is the
 * original bytes Stalker keeps for its self-modification check?
 *
 * The corpus below is one straight-line block of 28 words under comparison,
 * plus a terminating RET at word 28.  The first 16 words are a unique ADD
 * sentinel, so the scanner can find both copies.
 * Words 24..27 are deliberately PC-relative / literal loads, so the
 * translated block must differ there.  The snapshot must not differ at all.
 *
 * Expected under Stalker:
 *
 *    ,---------.---------------------------------------.
 *     | hit     | words differing from the original    |
 *     |---------|---------------------------------------|
 *     | first   | 3 / 28   (adr, adrp+add, ldr literal) |
 *     | second  | 0 / 28   (snapshot)                    |
 *     `---------'---------------------------------------'
 *
 * Build:
 *   aarch64-linux-android31-clang -O2 -s -o wd02 wd02.c
 *
 * Run:
 *   ./wd02                   one window, 20 corpus calls, one diff report
 *   ./wd02 --loop 300        repeat every 300 ms
 *   ./wd02 --calls 50        call the corpus 50x per window
 *   ./wd02 --verbose         print every sentinel hit
 */

#include "scan.h"

#include <errno.h>
#include <stdlib.h>

#define CORPUS_WORDS   28
#define CORPUS_INSNS   29
#define SENTINEL_WORDS 16
#define SENTINEL_SIZE  (SENTINEL_WORDS * 4)
#define CORPUS_SIZE    (CORPUS_WORDS * 4)

#define ADD_FIRST     0x201u
#define ADD_BASE      0x91000129u
#define RET_ENCODING  0xD65F03C0u

struct hit
{
  uintptr_t addr;
  uintptr_t end;
  int diffs;
};

static char g_exe[512];

const uint8_t g_blob[64] __attribute__((aligned(16))) =
{
  0xa5, 0x5a, 0x3c, 0xc3, 0x0f, 0xf0, 0x96, 0x69,
  0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44,
  0x55, 0xaa, 0x00, 0xff, 0x7e, 0x81, 0x42, 0xbd,
  0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0,
  0xc0, 0xff, 0xee, 0x00, 0xba, 0xad, 0xf0, 0x0d,
  0x0d, 0xf0, 0xad, 0xba, 0x00, 0xee, 0xff, 0xc0,
  0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
  0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
};

__attribute__((naked, noinline, used))
static void
corpus (void)
{
  __asm__ __volatile__ (
      "  .set ci, 0x201\n"
      "  .rept 16\n"
      "    add x9, x9, #(ci)\n"
      "  .set ci, ci + 1\n"
      "  .endr\n"
      "  eor x3, x3, x4\n"
      "  lsl x5, x5, #3\n"
      "  mul x6, x6, x7\n"
      "  csel x8, x8, x9, eq\n"
      "  and x10, x10, #0xff\n"
      "  orr x11, x11, x12\n"
      "  sub x13, x13, #7\n"
      "  cmp x14, x15\n"
      "  adr x0, g_blob\n"
      "  adrp x1, g_blob\n"
      "  add x1, x1, :lo12:g_blob\n"
      "  ldr x2, g_blob\n"
      "  ret\n");
}

static int
verify_corpus (void)
{
  const uint32_t *p = (const uint32_t *) corpus;
  int i;

  for (i = 0; i != SENTINEL_WORDS; i++)
  {
    uint32_t want = ADD_BASE | ((ADD_FIRST + (uint32_t) i) << 10);

    if (p[i] != want)
    {
      fprintf (stderr, "corpus mismatch at word %d: have 0x%08x want 0x%08x\n",
          i, p[i], want);
      return 0;
    }
  }

  if (p[CORPUS_INSNS - 1] != RET_ENCODING)
  {
    fprintf (stderr, "corpus does not end in ret: 0x%08x\n",
        p[CORPUS_INSNS - 1]);
    return 0;
  }

  return 1;
}

static size_t
find_sentinel (const uint8_t *base, size_t len,
               uintptr_t *hits, size_t max_hits)
{
  const uint8_t *needle = (const uint8_t *) corpus;
  const uint8_t *p = base;
  const uint8_t *end;
  size_t count = 0;

  if (len < SENTINEL_SIZE)
    return 0;

  end = base + len - SENTINEL_SIZE;

  while (p <= end)
  {
    const uint8_t *q = memchr (p, needle[0], (size_t) (end - p) + 1);

    if (q == NULL)
      break;

    if (memcmp (q, needle, SENTINEL_SIZE) == 0)
    {
      if (count < max_hits)
        hits[count] = (uintptr_t) q;
      count++;
    }

    p = q + 1;
  }

  return count;
}

static void
diff_report (int verbose)
{
  FILE *f;
  char line[512];
  struct hit hits[8];
  size_t nhits = 0;
  unsigned long long resource = 0;
  unsigned long long scanned = 0;
  uintptr_t resource_first = 0;
  const uint32_t *orig = (const uint32_t *) corpus;

  memset (hits, 0, sizeof (hits));

  f = fopen ("/proc/self/maps", "r");
  if (f == NULL)
  {
    printf ("WD02 cannot open /proc/self/maps: %s\n", strerror (errno));
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
    size_t found;
    uintptr_t local[8];
    uintptr_t blob_first = 0;

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
      found = find_sentinel ((const uint8_t *) p, len, local, 8);
      scanned += len;

      for (size_t i = 0; i != found && i != 8; i++)
      {
        if (nhits < 8)
        {
          hits[nhits].addr = local[i];
          hits[nhits].end = q;
        }
        nhits++;
      }

      {
        size_t blob = scan_count ((const uint8_t *) p, len,
            g_blob, sizeof (g_blob), &blob_first);

        if (blob != 0 && resource == 0)
          resource_first = blob_first;
        resource += blob;
      }
    }
    else
    {
      g_guarded = 0;
      if (verbose)
        printf ("       (fault at 0x%lx-0x%lx, skipped)\n", lo, hi);
      continue;
    }
    g_guarded = 0;
  }

  fclose (f);

  printf ("WD02 corpus=%d words sentinel_hits=%zu resource=%llu "
          "first_resource=0x%lx scanned=%.0fMB\n",
      CORPUS_WORDS, nhits, resource, (unsigned long) resource_first,
      (double) scanned / (1024.0 * 1024.0));

  for (size_t i = 0; i != nhits && i != 8; i++)
  {
    const uint32_t *copy = (const uint32_t *) hits[i].addr;
    int diffs = 0;
    int shown = 0;

    if (hits[i].addr + CORPUS_SIZE > hits[i].end)
    {
      printf ("        hit 0x%lx  truncated at mapping end\n",
          (unsigned long) hits[i].addr);
      continue;
    }

    for (int w = 0; w != CORPUS_WORDS; w++)
    {
      if (orig[w] == copy[w])
        continue;

      diffs++;
      if (shown++ < 6)
        printf ("        [%2d] orig=%08x copy=%08x\n",
            w, orig[w], copy[w]);
    }

    hits[i].diffs = diffs;
    printf ("        hit 0x%lx  %s  %d/%d words differ\n",
        (unsigned long) hits[i].addr,
        (diffs == 0) ? "snapshot (exact copy)" : "translated",
        diffs, CORPUS_WORDS);
  }
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
      printf ("wd02 1.0.0\n");
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

  if (!verify_corpus ())
    return 2;

  scan_read_exe (g_exe, sizeof (g_exe));
  scan_install_faults ();

  printf ("WD02 corpus @ %p : %d words, sentinel=%d words\n",
      (const void *) corpus, CORPUS_WORDS, SENTINEL_WORDS);
  fflush (stdout);

  for (;;)
  {
    for (i = 0; i != calls; i++)
      corpus ();

    diff_report (verbose);
    fflush (stdout);

    if (loop_ms == 0)
      return 0;

    usleep ((useconds_t) loop_ms * 1000u);
  }
}
