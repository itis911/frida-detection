/*
 * stalker_check.c -- one call, one bitmask: is *this* process being
 * followed by Frida Stalker (arm64, 17.26.x)?
 *
 * Four independent checks, strongest last:
 *
 *   0x01  SC_CTX_MAGIC   GUM_IC_MAGIC_EMPTY found in an anon exec mapping
 *   0x02  SC_CTX_HEADER  that mapping's base validates as a GumExecCtx
 *                        (state 0/1/2, readable stalker ptr, tid == gettid)
 *   0x04  SC_BLOCK_BIND  a brk #14 terminator whose following literal is a
 *                        valid GumExecCtx for this thread
 *   0x08  SC_FRAME       a 0x40000 anon rw- mapping whose [top-16] is our
 *                        stack and whose [top-8] points into anon exec memory
 *
 * Verdict (caller's job, also printed):
 *   STALKED  if (HEADER | BIND | FRAME)
 *   SUSPECT  if MAGIC only
 *   CLEAN    if flags == 0
 *
 * Deliberately no /proc/self/mem, no ptrace, no signals beyond a fault
 * guard, and it never dereferences a candidate that is not inside a
 * readable mapping.
 *
 * Build:
 *   aarch64-linux-android31-clang -O2 -Wall -Wextra -o stalker_check \
 *       stalker_check.c
 *
 * Usage:
 *   stalker_check [--wait ms] [--verbose]
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SC_CTX_MAGIC   0x01u
#define SC_CTX_HEADER  0x02u
#define SC_BLOCK_BIND  0x04u
#define SC_FRAME       0x08u

#define SC_SLAB_INITIAL 0x4d000u
#define SC_STACK_SIZE   0x40000u
#define SC_IC_MAGIC     0xbaadd00ddeadfaceull
#define SC_BRK_BLOCK_END 0xd42001c0u
#define SC_MIN_MAGIC_HITS 8u
#define SC_MIN_EXEC_SIZE  (64u * 1024u)
#define SC_MAX_MAPS      4096

typedef struct
{
  uintptr_t lo;
  uintptr_t hi;
  char perms[5];
  int anon;
  int exec;
} ScMap;

static ScMap g_maps[SC_MAX_MAPS];
static int g_nmaps;

static unsigned g_magic;
static unsigned g_brk14;
static unsigned g_bind;

static sigjmp_buf g_fault;
static volatile sig_atomic_t g_guarded;

static void
on_fault (int sig)
{
  if (g_guarded)
    siglongjmp (g_fault, 1);

  signal (sig, SIG_DFL);
  raise (sig);
}

static void
guard_begin (void)
{
  g_guarded = 1;
}

static void
guard_end (void)
{
  g_guarded = 0;
}

/* ------------------------------------------------------------------ */
/* maps                                                                */
/* ------------------------------------------------------------------ */

static int
parse_maps (void)
{
  FILE * f;
  char line[1024];

  g_nmaps = 0;

  f = fopen ("/proc/self/maps", "r");
  if (f == NULL)
    return 0;

  while (fgets (line, sizeof (line), f) != NULL && g_nmaps != SC_MAX_MAPS)
  {
    unsigned long lo, hi;
    char perms[8];
    int n = 0;
    const char * path;
    ScMap * m;

    if (sscanf (line, "%lx-%lx %7s %*s %*s %*s %n", &lo, &hi, perms, &n) < 3)
      continue;

    path = line + ((n < (int) sizeof (line)) ? n : 0);
    while (*path == ' ')
      path++;

    m = &g_maps[g_nmaps++];
    m->lo = (uintptr_t) lo;
    m->hi = (uintptr_t) hi;
    memcpy (m->perms, perms, 4);
    m->perms[4] = '\0';
    m->anon = (*path == '\0' || *path == '[');
    m->exec = (perms[2] == 'x');
  }

  fclose (f);
  return g_nmaps;
}

static ScMap *
map_of (uintptr_t a)
{
  int lo = 0, hi = g_nmaps - 1;

  while (lo <= hi)
  {
    int mid = (lo + hi) / 2;
    ScMap * m = &g_maps[mid];

    if (a < m->lo)
      hi = mid - 1;
    else if (a >= m->hi)
      lo = mid + 1;
    else
      return m;
  }

  return NULL;
}

static int
readable (uintptr_t a)
{
  ScMap * m = map_of (a);
  return m != NULL && m->perms[0] == 'r';
}

static int
anon_exec (uintptr_t a)
{
  ScMap * m = map_of (a);
  return m != NULL && m->anon && m->exec;
}

static int
anon_writable (uintptr_t a)
{
  ScMap * m = map_of (a);
  return m != NULL && m->anon && m->perms[0] == 'r' && m->perms[1] == 'w';
}

/* ------------------------------------------------------------------ */
/* ctx                                                                 */
/* ------------------------------------------------------------------ */

typedef struct
{
  uintptr_t addr;
  int state;
  uint32_t tid;
  uintptr_t stalker;
} ScCtx;

static int
validate_ctx (uintptr_t a, ScCtx * out)
{
  ScCtx c;

  if (!readable (a) || (a & 7) != 0)
    return 0;

  memcpy (&c.state, (void *) a, 4);
  if (c.state < 0 || c.state > 2)
    return 0;

  memcpy (&c.stalker, (void *) (a + 16), 8);
  if (c.stalker == 0 || !readable (c.stalker))
    return 0;

  memcpy (&c.tid, (void *) (a + 24), 4);
  if (c.tid != (uint32_t) gettid ())
    return 0;

  c.addr = a;
  if (out != NULL)
    *out = c;

  return 1;
}

/* data slab starts at ctx + 0x42000; try page-aligned bases below a magic hit */
static uintptr_t
ctx_from_magic_hit (uintptr_t hit, uintptr_t map_lo, ScCtx * out)
{
  uintptr_t top, a;
  int i;

  if (hit < 0x42000)
    return 0;

  if (validate_ctx (map_lo, out))
    return map_lo;

  /* data slab = ctx + 0x42000, 28 KiB, IC arrays 16-byte aligned */
  top = (hit - 0x42000) & ~(uintptr_t) 0xfff;

  for (i = 0, a = top; i != 8 && a >= map_lo; i++, a -= 0x1000)
  {
    if (validate_ctx (a, out))
      return a;

    if (a < 0x1000)
      break;
  }

  return 0;
}

/* ------------------------------------------------------------------ */
/* passes                                                              */
/* ------------------------------------------------------------------ */

static unsigned
pass_magic_and_header (ScCtx * ctx, int verbose)
{
  unsigned flags = 0;
  int i;

  for (i = 0; i != g_nmaps; i++)
  {
    ScMap * m = &g_maps[i];
    size_t len;
    const uint8_t * p, * end;
    size_t hits = 0;
    uintptr_t first = 0;

    if (!m->anon || !m->exec)
      continue;

    len = (size_t) (m->hi - m->lo);
    if (len < SC_MIN_EXEC_SIZE)
      continue;

    p = (const uint8_t *) m->lo;
    end = p + len;

    for (; p + 8 <= end; p += 8)
    {
      uint64_t v;

      memcpy (&v, p, 8);
      if (v != SC_IC_MAGIC)
        continue;

      hits++;
      if (hits == 1)
        first = (uintptr_t) p;
    }

    if (hits == 0)
      continue;

    g_magic += (unsigned) hits;

    if (verbose)
      printf ("  magic  0x%lx  hits=%zu %s\n", (unsigned long) m->lo, hits,
          m->perms);

    if (hits < SC_MIN_MAGIC_HITS)
      continue;

    flags |= SC_CTX_MAGIC;

    if (ctx->addr == 0 &&
        ctx_from_magic_hit (first, m->lo, ctx) != 0)
      flags |= SC_CTX_HEADER;
  }

  return flags;
}

static unsigned
pass_binding (ScCtx * ctx, int verbose)
{
  unsigned flags = 0;
  unsigned brk14 = 0, bind = 0;
  int i;

  for (i = 0; i != g_nmaps; i++)
  {
    ScMap * m = &g_maps[i];
    size_t len;
    const uint8_t * p, * end;

    if (!m->anon || !m->exec)
      continue;

    len = (size_t) (m->hi - m->lo);
    if (len < 256u * 1024u)
      continue;

    p = (const uint8_t *) m->lo;
    end = p + len;

    for (; p + 12 <= end; p += 4)
    {
      uint32_t w;
      uint64_t lit;
      ScCtx c;

      memcpy (&w, p, 4);
      if (w != SC_BRK_BLOCK_END)
        continue;

      brk14++;

      memcpy (&lit, p + 4, 8);
      if (lit == 0 || !readable ((uintptr_t) lit))
        continue;

      if (!validate_ctx ((uintptr_t) lit, &c))
        continue;

      bind++;
      if (ctx->addr == 0)
        *ctx = c;
    }
  }

  if (verbose)
    printf ("  brk14=%u bind=%u\n", brk14, bind);

  g_brk14 = brk14;
  g_bind = bind;

  if (bind != 0)
    flags |= SC_BLOCK_BIND;

  return flags;
}

static unsigned
pass_frame (ScCtx * ctx, uintptr_t * stack_base, int verbose)
{
  int i;

  for (i = 0; i != g_nmaps; i++)
  {
    ScMap * m = &g_maps[i];
    uintptr_t t;

    if (!m->anon || m->exec)
      continue;
    if (m->perms[0] != 'r' || m->perms[1] != 'w' || m->perms[2] != '-')
      continue;
    if ((m->hi - m->lo) < SC_STACK_SIZE)
      continue;

    /* the stack VMA may be merged with a neighbour, so probe every page
     * boundary that could be the stack top */
    for (t = m->lo + SC_STACK_SIZE; t <= m->hi; t += 0x1000)
    {
      uint64_t sp = 0, c = 0;

      memcpy (&sp, (void *) (t - 16), 8);
      memcpy (&c, (void *) (t - 8), 8);

      if (!anon_writable ((uintptr_t) sp))
        continue;
      if (c == 0 || !anon_exec ((uintptr_t) c))
        continue;

      *stack_base = t - SC_STACK_SIZE;

      if (ctx->addr == 0)
        validate_ctx ((uintptr_t) c, ctx);

      if (verbose)
        printf ("  frame  0x%lx  ctx=0x%lx\n", (unsigned long) *stack_base,
            (unsigned long) c);

      return SC_FRAME;
    }
  }

  return 0;
}

static double
now_ms (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (double) ts.tv_sec * 1000.0 + (double) ts.tv_nsec / 1e6;
}

/* Burn CPU instead of sleeping so a follow lands on our own loop and the
 * code cache actually fills up before we look at it. */
__attribute__((noinline))
static uintptr_t
spin (int ms)
{
  double end = now_ms () + ms;
  uintptr_t x = 1;

  while (now_ms () < end)
  {
    int i;
    for (i = 0; i != 4096; i++)
      x = x * 1103515245u + 12345u;
  }

  return x;
}

/* ------------------------------------------------------------------ */

int
main (int argc, char * argv[])
{
  ScCtx ctx;
  unsigned flags = 0;
  uintptr_t stack_base = 0;
  int verbose = 0;
  int wait_ms = 0;
  int i;
  struct sigaction sa;

  memset (&ctx, 0, sizeof (ctx));

  for (i = 1; i < argc; i++)
  {
    if (strcmp (argv[i], "--wait") == 0 && i + 1 < argc)
      wait_ms = atoi (argv[++i]);
    else if (strcmp (argv[i], "--verbose") == 0)
      verbose = 1;
    else
    {
      fprintf (stderr, "usage: %s [--wait ms] [--verbose]\n", argv[0]);
      return 2;
    }
  }

  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = on_fault;
  sa.sa_flags = SA_NODEFER;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGSEGV, &sa, NULL);
  sigaction (SIGBUS, &sa, NULL);

  if (wait_ms > 0)
    spin (wait_ms);

  if (!parse_maps ())
  {
    printf ("STALKER flags=0x00 maps=0 note=\"maps unavailable\"\n");
    return 1;
  }

  if (sigsetjmp (g_fault, 1) == 0)
  {
    guard_begin ();
    flags |= pass_magic_and_header (&ctx, verbose);
    flags |= pass_binding (&ctx, verbose);
    flags |= pass_frame (&ctx, &stack_base, verbose);
    guard_end ();
  }
  else
  {
    guard_end ();
  }

  {
    const char * verdict;

    if (ctx.addr != 0 && ctx.state == 0 &&
        (flags & (SC_CTX_HEADER | SC_BLOCK_BIND | SC_FRAME)) != 0)
      verdict = "STALKED";
    else if (ctx.addr != 0)
      verdict = "RECENT";            /* state 1/2: followed earlier */
    else if (flags & SC_CTX_MAGIC)
      verdict = "SUSPECT";           /* magic only, no live ctx for us */
    else
      verdict = "CLEAN";

    printf ("%s flags=0x%02x ctx=0x%lx tid=%d", verdict, flags,
        (unsigned long) ctx.addr, (int) gettid ());
    if (ctx.addr != 0)
      printf (" state=%d stalker=0x%lx", ctx.state,
          (unsigned long) ctx.stalker);
    printf (" stack=0x%lx magic=%u brk14=%u bind=%u maps=%d\n",
        (unsigned long) stack_base, g_magic, g_brk14, g_bind, g_nmaps);
  }

  (void) flags;

  return 0;
}

/* https://github.com/itis911/frida_stalker_detection */
