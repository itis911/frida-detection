/*
 * wd00.c -- WD-00 only.
 *
 * "Is this thread executing from Stalker's code cache right now?"
 *
 * The whole detection is three ideas:
 *
 *   1. uc->uc_mcontext.pc is the PC the *kernel* saved when it delivered the
 *      signal. Stalker rewrites BL / ADR / ADRP in userland, but it cannot
 *      rewrite a signal frame, so under Stalker this PC lives in the
 *      anonymous code cache.
 *   2. dl_iterate_phdr() gives every executable PT_LOAD of every loaded
 *      module. No /proc, no maps parsing, no library-name matching.
 *   3. A majority rule over a short window: DETECTED requires >= 3 samples
 *      outside every module and outside * 2 > sampled.
 *
 * No magic constants, no brk #14, no payload copy, no /proc. Nothing else.
 *
 * build:
 *   aarch64-linux-android31-clang -O2 -Wall -Wextra -static -o wd00 wd00.c
 *
 * exit:
 *   0 = CLEAN, 1 = DETECTED, 2 = setup error
 *
 * x86-64 note: only the pc field differs -- uc_mcontext.gregs[REG_RIP]
 * instead of uc_mcontext.pc.
 */

#define _GNU_SOURCE

#include <elf.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>

#define MAX_MODULES 512
#define MAX_SAMPLES 256
#define WINDOW_MS    80      /* sampling window                      */
#define PERIOD_US  1000      /* kernel delivers SIGALRM every 1 ms   */

static struct { uintptr_t lo, hi; } g_mods[MAX_MODULES];
static int g_nmods;

static uintptr_t g_pcs[MAX_SAMPLES];
static volatile sig_atomic_t g_npcs;

/* ---- 1. every executable PT_LOAD of every loaded module ------------- */
static int
add_module (struct dl_phdr_info * info, size_t size, void * data)
{
  int i;

  (void) size;
  (void) data;

  for (i = 0; i != info->dlpi_phnum; i++)
  {
    const ElfW (Phdr) * ph = &info->dlpi_phdr[i];

    if (ph->p_type != PT_LOAD || (ph->p_flags & PF_X) == 0)
      continue;
    if (g_nmods == MAX_MODULES)
      return 0;

    g_mods[g_nmods].lo = info->dlpi_addr + ph->p_vaddr;
    g_mods[g_nmods].hi = g_mods[g_nmods].lo + ph->p_memsz;
    g_nmods++;
  }

  return 0;
}

static int
in_module (uintptr_t pc)
{
  int i;

  for (i = 0; i != g_nmods; i++)
    if (pc >= g_mods[i].lo && pc < g_mods[i].hi)
      return 1;

  return 0;
}

/* ---- 2. the only input: the kernel's saved PC ----------------------- */
static void
on_alarm (int sig, siginfo_t * si, void * context)
{
  ucontext_t * uc = context;
  sig_atomic_t n = g_npcs;

  (void) sig;
  (void) si;

  if (n < MAX_SAMPLES)
  {
    g_pcs[n] = (uintptr_t) uc->uc_mcontext.pc;
    g_npcs = n + 1;
  }
}

static uint64_t
now_ms (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);

  return (uint64_t) ts.tv_sec * 1000u + (uint64_t) ts.tv_nsec / 1000000u;
}

/* ---- 3. keep the thread in user code for the window ----------------- */
/* Pure arithmetic on purpose: the sampled PC must stay inside this
 * function, so the clock call is the only thing that can leave it.       */
__attribute__((noinline))
static void
spin_until (uint64_t deadline_ms)
{
  uint64_t acc = 0x9e3779b97f4a7c15ull;

  while (now_ms () < deadline_ms)
  {
    int i;

    for (i = 0; i != 4096; i++)
    {
      acc = acc * 6364136223846793005ull + 1442695040888963407ull;
      __asm__ __volatile__ ("" : "+r" (acc));
    }
  }
}

/* ---- 4. one window --------------------------------------------------- */
static int
sample_window (int * sampled, int * inside, int * outside)
{
  struct sigaction sa, old_sa;
  struct itimerval it;
  int i;

  memset (&sa, 0, sizeof (sa));
  sa.sa_sigaction = on_alarm;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset (&sa.sa_mask);

  if (sigaction (SIGALRM, &sa, &old_sa) != 0)
    return -1;

  g_npcs = 0;

  memset (&it, 0, sizeof (it));
  it.it_interval.tv_usec = PERIOD_US;
  it.it_value = it.it_interval;
  setitimer (ITIMER_REAL, &it, NULL);

  spin_until (now_ms () + WINDOW_MS);

  memset (&it, 0, sizeof (it));
  setitimer (ITIMER_REAL, &it, NULL);
  sigaction (SIGALRM, &old_sa, NULL);

  *sampled = (int) g_npcs;
  *inside = 0;
  *outside = 0;

  for (i = 0; i != g_npcs; i++)
  {
    if (g_pcs[i] == 0)
      continue;

    if (in_module (g_pcs[i]))
      (*inside)++;
    else
      (*outside)++;
  }

  return 0;
}

/* ---- 5. verdict ------------------------------------------------------ */
static int
decide (int sampled, int outside)
{
  if (sampled <= 0)
    return 0;

  return outside >= 3 && (outside * 2) > sampled;
}

int
main (void)
{
  int sampled, inside, outside, detected;

  dl_iterate_phdr (add_module, NULL);
  if (g_nmods == 0)
    return 2;

  if (sample_window (&sampled, &inside, &outside) != 0)
    return 2;

  detected = decide (sampled, outside);

  printf ("STALKER  %s sampled=%d inside=%d outside=%d (%.0f%% outside)\n",
      detected ? "DETECTED" : "CLEAN",
      sampled, inside, outside,
      sampled ? 100.0 * outside / sampled : 0.0);

  return detected ? 1 : 0;
}

/* https://github.com/itis911/frida_stalker_detection */
