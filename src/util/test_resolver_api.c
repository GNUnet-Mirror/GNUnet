/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/
/**
 * @file resolver/test_resolver_api.c
 * @brief testcase for resolver_api.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_resolver_service.h"
#include "resolver.h"

#define VERBOSE GNUNET_NO


static void
check_hostname (void *cls, const struct sockaddr *sa, socklen_t salen)
{
  int *ok = cls;

  if (salen == 0)
    {
      (*ok) &= ~8;
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Got IP address `%s' for our host.\n"),
              GNUNET_a2s (sa, salen));
}


static void
check_localhost_num (void *cls, const char *hostname)
{
  int *ok = cls;
  if (hostname == NULL)
    return;
  if (0 == strcmp (hostname, "127.0.0.1"))
    {
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received correct hostname `%s'.\n", hostname);
#endif
      (*ok) &= ~4;
    }
  else
    {
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received invalid hostname `%s'.\n", hostname);
#endif
      GNUNET_break (0);
    }
}

static void
check_localhost (void *cls, const char *hostname)
{
  int *ok = cls;
  if (hostname == NULL)
    return;
  if (0 == strcmp (hostname, "localhost"))
    {
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received correct hostname `%s'.\n", hostname);
#endif
      (*ok) &= ~2;
    }
  else
    {
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received invalid hostname `%s'.\n", hostname);
#endif
      GNUNET_break (0);
    }
}

static void
check_127 (void *cls, const struct sockaddr *sa, socklen_t salen)
{
  int *ok = cls;
  const struct sockaddr_in *sai = (const struct sockaddr_in *) sa;

  if (sa == NULL)
    return;
  GNUNET_assert (sizeof (struct sockaddr_in) == salen);
  if (sai->sin_addr.s_addr == htonl (INADDR_LOOPBACK))
    {
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received correct address.\n");
#endif
      (*ok) &= ~1;
    }
  else
    {
#if DEBUG_RESOLVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received incorrect address.\n");
#endif
      GNUNET_break (0);
    }
}

static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct sockaddr_in sa;
  struct GNUNET_TIME_Relative timeout =
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                   2500);
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  GNUNET_RESOLVER_ip_get (sched,
                          cfg,
                          "localhost", AF_INET, timeout, &check_127, cls);
  GNUNET_RESOLVER_hostname_get (sched,
                                cfg,
                                (const struct sockaddr *) &sa,
                                sizeof (struct sockaddr),
                                GNUNET_YES, timeout, &check_localhost, cls);
  GNUNET_RESOLVER_hostname_get (sched,
                                cfg,
                                (const struct sockaddr *) &sa,
                                sizeof (struct sockaddr),
                                GNUNET_NO,
                                timeout, &check_localhost_num, cls);
  GNUNET_RESOLVER_hostname_resolve (sched,
                                    cfg,
                                    AF_UNSPEC, timeout, &check_hostname, cls);
}

static int
check ()
{
  int ok = 1 + 2 + 4 + 8;
  pid_t pid;
  char *const argv[] = { "test-resolver-api",
    "-c",
    "test_resolver_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  pid = GNUNET_OS_start_process ("gnunet-service-resolver",
                                 "gnunet-service-resolver",
#if VERBOSE
                                 "-L", "DEBUG",
#endif
                                 "-c", "test_resolver_api_data.conf", NULL);
  GNUNET_assert (OK == GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
					   argv, "test-resolver-api", "nohelp",
					   options, &run, &ok));
  if (0 != PLIBC_KILL (pid, SIGTERM))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      ok = 1;
    }
  GNUNET_OS_process_wait (pid);
  if (ok != 0)
    fprintf (stderr, "Missed some resolutions: %u\n", ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-resolver-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  return ret;
}

/* end of test_resolver_api.c */
