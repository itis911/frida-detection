/*
 * scan.h - shared helpers for the WD-01 / WD-04 scanners.
 *
 * These detectors are deliberately forensic: they read /proc/self/maps and
 * walk every readable mapping.  WD-00 is the stealthy one and does not use
 * this file at all.
 */

#ifndef BLOG_SCAN_H
#define BLOG_SCAN_H

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static sigjmp_buf g_fault;
static volatile sig_atomic_t g_guarded;

static void
scan_on_fault (int sig)
{
  if (g_guarded)
    siglongjmp (g_fault, 1);

  signal (sig, SIG_DFL);
  raise (sig);
}

static void
scan_install_faults (void)
{
  struct sigaction sa;

  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = scan_on_fault;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = SA_NODEFER;

  sigaction (SIGSEGV, &sa, NULL);
  sigaction (SIGBUS, &sa, NULL);
}

static void
scan_read_exe (char *buf, size_t cap)
{
  ssize_t n;

  if (cap == 0)
    return;

  n = readlink ("/proc/self/exe", buf, cap - 1);
  if (n > 0)
  {
    buf[n] = '\0';
  }
  else
  {
    buf[0] = '\0';
  }
}

static int
scan_skip_path (const char *path, const char *exe)
{
  if (exe[0] != '\0' && strcmp (path, exe) == 0)
    return 1;

  if (strcmp (path, "[stack]") == 0 ||
      strcmp (path, "[vvar]") == 0 ||
      strcmp (path, "[vdso]") == 0)
    return 1;

  return 0;
}

static size_t
scan_count (const uint8_t *base, size_t len,
            const uint8_t *needle, size_t nlen,
            uintptr_t *first)
{
  size_t count = 0;
  const uint8_t *p = base;
  const uint8_t *end;

  if (len < nlen)
    return 0;

  end = base + len - nlen;

  while (p <= end)
  {
    const uint8_t *q = memchr (p, needle[0], (size_t) (end - p) + 1);

    if (q == NULL)
      break;

    if (memcmp (q, needle, nlen) == 0)
    {
      if (count == 0 && first != NULL)
        *first = (uintptr_t) q;
      count++;
    }

    p = q + 1;
  }

  return count;
}

#endif
