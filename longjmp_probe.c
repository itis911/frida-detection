/*
 * longjmp_probe.c -- does a siglongjmp out of a followed signal handler
 * silently drop the thread out of Stalker's code cache?
 *
 * Two payloads with the same shape (100 x add x9,x9,#imm + ret, 400 bytes):
 *   P1  immediates 0x101..0x164   -- executed in phase 1
 *   P2  immediates 0x201..0x264   -- executed in phase 2
 *
 * Phase 1 (6 s):  P1 x20, usleep(200 ms)          <- follow starts here
 * Phase 2 (6 s):  [jump?] P2 x20, usleep(200 ms)
 * Then one pass over /proc/self/maps counts exact 400-byte matches of P1
 * and P2 in this process.
 *
 *   native control :  ./longjmp_probe nojump   -> p1=2 p2=2
 *   with longjmp   :  ./longjmp_probe          -> p1=2 p2=0  (expected)
 *
 * The jump is sigsetjmp() in the main loop + raise(SIGUSR1) + siglongjmp()
 * from the handler -- i.e. exactly what stalker_scan's fault guard does when
 * it hits a mapping that disappeared while it was walking.
 *
 * Build:
 *   aarch64-linux-android31-clang -O2 -Wall -Wextra -o longjmp-probe-arm64 \
 *       longjmp_probe.c
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

#define PATTERN_INSNS 100
#define PATTERN_SIZE  (PATTERN_INSNS * 4)

__attribute__((naked, noinline, used))
static void
p1 (void)
{
  __asm__ __volatile__ (
      "  .set pi, 0x101\n"
      "  .rept 100\n"
      "    .inst 0x91000129 + (pi << 10)\n"
      "  .set pi, pi + 1\n"
      "  .endr\n"
      "  ret\n");
}

__attribute__((naked, noinline, used))
static void
p2 (void)
{
  __asm__ __volatile__ (
      "  .set pi, 0x201\n"
      "  .rept 100\n"
      "    .inst 0x91000129 + (pi << 10)\n"
      "  .set pi, pi + 1\n"
      "  .endr\n"
      "  ret\n");
}

/* ------------------------------------------------------------------ */
/* the longjmp trigger                                                 */
/* ------------------------------------------------------------------ */

static sigjmp_buf g_jb;
static volatile sig_atomic_t g_armed;

static void
on_usr1 (int sig)
{
  (void) sig;
  if (g_armed)
    siglongjmp (g_jb, 1);
}

static void
jump_once (void)
{
  if (sigsetjmp (g_jb, 1) == 0)
  {
    g_armed = 1;
    raise (SIGUSR1);
    g_armed = 0;
  }
}

/* ------------------------------------------------------------------ */
/* fault-guarded pattern scan (same idea as stalker-scan)              */
/* ------------------------------------------------------------------ */

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

typedef struct
{
  size_t p1;
  size_t p2;
} Counts;

static size_t
count_pattern (const uint8_t * base, size_t len, const uint8_t * needle)
{
  size_t n = 0;
  const uint8_t * p = base;
  const uint8_t * end = base + len;

  while (p + PATTERN_SIZE <= end)
  {
    const uint8_t * q = memmem (p, (size_t) (end - p), needle, PATTERN_SIZE);

    if (q == NULL)
      break;

    n++;
    p = q + 1;
  }

  return n;
}

static void
scan_all (Counts * out)
{
  FILE * f;
  char line[1024];

  out->p1 = 0;
  out->p2 = 0;

  f = fopen ("/proc/self/maps", "r");
  if (f == NULL)
    return;

  while (fgets (line, sizeof (line), f) != NULL)
  {
    unsigned long lo, hi;
    char perms[8];
    uint8_t * p;
    size_t len;

    if (sscanf (line, "%lx-%lx %7s", &lo, &hi, perms) != 3)
      continue;
    if (perms[0] != 'r')
      continue;

    len = (size_t) (hi - lo);
    if (len < PATTERN_SIZE)
      continue;

    p = (uint8_t *) lo;

    if (sigsetjmp (g_fault, 1) == 0)
    {
      g_guarded = 1;
      out->p1 += count_pattern (p, len, (const uint8_t *) p1);
      out->p2 += count_pattern (p, len, (const uint8_t *) p2);
      g_guarded = 0;
    }
  }

  fclose (f);
}

/* ------------------------------------------------------------------ */

int
main (int argc, char * argv[])
{
  int do_jump = 1;
  int jump_after = 0;
  int i;
  struct timespec start;
  struct sigaction sa;

  if (argc > 1 && strcmp (argv[1], "nojump") == 0)
    do_jump = 0;
  else if (argc > 1 && strcmp (argv[1], "jumpafter") == 0)
    jump_after = 1;

  signal (SIGUSR1, on_usr1);

  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = on_fault;
  sa.sa_flags = SA_NODEFER;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGSEGV, &sa, NULL);
  sigaction (SIGBUS, &sa, NULL);

  printf ("longjmp-probe: jump=%d  p1=%p p2=%p\n", do_jump,
      (const void *) p1, (const void *) p2);
  fflush (stdout);

  clock_gettime (CLOCK_MONOTONIC, &start);
  printf ("phase 1: p1 x20, 6 s\n");
  fflush (stdout);
  while (1)
  {
    struct timespec now;
    double dt;

    for (i = 0; i != 20; i++)
      p1 ();

    usleep (200000);

    clock_gettime (CLOCK_MONOTONIC, &now);
    dt = (double) (now.tv_sec - start.tv_sec) +
        (double) (now.tv_nsec - start.tv_nsec) / 1e9;
    if (dt >= 6.0)
      break;
  }

  printf ("phase 2: %s p2 x20, 6 s\n",
      !do_jump ? "(no jump)" : (jump_after ? "p2 then jump" : "jump then p2"));
  fflush (stdout);

  clock_gettime (CLOCK_MONOTONIC, &start);
  while (1)
  {
    struct timespec now;
    double dt;

    if (do_jump && !jump_after)
      jump_once ();

    for (i = 0; i != 20; i++)
      p2 ();

    if (do_jump && jump_after)
      jump_once ();

    usleep (200000);

    clock_gettime (CLOCK_MONOTONIC, &now);
    dt = (double) (now.tv_sec - start.tv_sec) +
        (double) (now.tv_nsec - start.tv_nsec) / 1e9;
    if (dt >= 6.0)
      break;
  }

  {
    Counts c;

    scan_all (&c);
    printf ("PROBE  p1=%zu  p2=%zu\n", c.p1, c.p2);
    fflush (stdout);
  }

  sleep (1);
  return 0;
}

/* https://github.com/itis911/frida_stalker_detection */
