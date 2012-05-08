/*
 This file is part of GNUnet.
 (C) 2009 Christian Grothoff (and other contributing authors)

 GNUnet is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published
 by the Free Software Foundation; either version 3, or (at your
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

/**
 * Using DNS root servers to check gnunet's resolver service
 * a.root-servers.net <-> 198.41.0.4 is a fix 1:1 mapping that should not change over years
 * For more information have a look at IANA's website http://www.root-servers.org/
 */
#define ROOTSERVER_NAME "a.root-servers.net"
#define ROOTSERVER_IP 	"198.41.0.4"

static void
check_hostname (void *cls, const struct sockaddr *sa, socklen_t salen)
{
  int *ok = cls;

  if (salen == 0)
  {
    (*ok) &= ~8;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Got IP address `%s' for our host.\n"),
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received correct hostname `%s'.\n",
                hostname);
    (*ok) &= ~4;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Received invalid hostname `%s'.\n",
                hostname);
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received correct hostname `%s'.\n",
                hostname);
    (*ok) &= ~2;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Received unexpected hostname `%s', expected `localhost' (this could be OK).\n",
                hostname);
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received correct address.\n");
    (*ok) &= ~1;
  }
  else
  {
    char buf[INET_ADDRSTRLEN];

    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Received incorrect address`%s'.\n",
		inet_ntop (AF_INET, &sai->sin_addr, buf, sizeof (buf)));
    GNUNET_break (0);
  }
}

static void
check_local_fqdn (void *cls, const char *gnunet_fqdn)
{
  int result = 0;

  struct hostent *host;
  char hostname[GNUNET_OS_get_hostname_max_length () + 1];

  if (0 != gethostname (hostname, sizeof (hostname) - 1))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                         "gethostname");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Resolving our FQDN `%s'\n"),
              hostname);
  host = gethostbyname (hostname);
  if (NULL == host)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not resolve our FQDN: %s %u\n"), hstrerror (h_errno),
                h_errno);
    return;
  }

  GNUNET_assert (0 != host);

  result = strcmp (host->h_name, gnunet_fqdn);
  if (0 != result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Local resolved and resolver resolved fqdns are not equal\n");
  }
  GNUNET_assert (0 == result);
}



static void
check_rootserver_ip (void *cls, const struct sockaddr *sa, socklen_t salen)
{
  int *ok = cls;
  const struct sockaddr_in *sai = (const struct sockaddr_in *) sa;

  if (sa == NULL)
    return;
  GNUNET_assert (sizeof (struct sockaddr_in) == salen);

  if (0 == strcmp (inet_ntoa (sai->sin_addr), ROOTSERVER_IP))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received correct rootserver ip address.\n");
    (*ok) &= ~1;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received incorrect rootserver ip address.\n");
    GNUNET_break (0);
  }
}

static void
check_rootserver_name (void *cls, const char *hostname)
{
  int *ok = cls;

  if (hostname == NULL)
    return;

  if (0 == strcmp (hostname, ROOTSERVER_NAME))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received correct rootserver hostname `%s'.\n", hostname);
    (*ok) &= ~2;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Received invalid rootserver hostname `%s'.\n", hostname);
    GNUNET_break (0);
  }
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int *ok = cls;
  struct sockaddr_in sa;
  struct GNUNET_TIME_Relative timeout =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30);
  int count_ips = 0;
  char *own_fqdn;

  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = (u_char) sizeof (sa);
#endif
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  /*
   * Looking up our own fqdn
   */
  own_fqdn = GNUNET_RESOLVER_local_fqdn_get ();
  check_local_fqdn (NULL, own_fqdn);
  GNUNET_free_non_null (own_fqdn);

  /*
   * Testing non-local DNS resolution
   * DNS rootserver to test: a.root-servers.net - 198.41.0.4
   */
  const char *rootserver_name = ROOTSERVER_NAME;
  struct hostent *rootserver;

  rootserver = gethostbyname (rootserver_name);
  if (rootserver == NULL)
  {
    /* Error: resolving ip addresses does not work */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("gethostbyname() could not lookup IP address: %s\n"),
                hstrerror (h_errno));
    FPRINTF (stderr,
             "%s", "System seems to be off-line, will not run all DNS tests\n");
    *ok = 0;                    /* mark test as passing anyway */
    return;
  }

  /* Counting returned IP addresses */
  while (rootserver->h_addr_list[count_ips] != NULL)
    count_ips++;
  if (count_ips > 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "IP received range for root name server, but a root name server has only 1 IP\n");
    GNUNET_break (0);
  }

  /* Comparing to resolved address to the address the root name server should have */
  if (strcmp
      (inet_ntoa (*(struct in_addr *) rootserver->h_addr_list[0]),
       ROOTSERVER_IP) != 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "IP received and IP for root name server differ\n");
    GNUNET_break (0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "System's own forward name resolution is working\n");
  /* Resolve the same using GNUNET */
  GNUNET_RESOLVER_ip_get (ROOTSERVER_NAME, AF_INET, timeout,
                          &check_rootserver_ip, cls);

  /*
   * Success: forward lookups work as expected
   * Next step: reverse lookups
   */

  struct in_addr rootserver_addr;

  rootserver->h_name = "";
  if (1 != inet_pton (AF_INET, ROOTSERVER_IP, &rootserver_addr))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Could not transform root name server IP address\n");
    GNUNET_break (0);
  }

  rootserver =
      gethostbyaddr (&rootserver_addr, sizeof (rootserver_addr), AF_INET);
  if (rootserver == NULL)
  {
    /* Error: resolving IP addresses does not work */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("gethostbyaddr() could not lookup hostname: %s\n"),
                hstrerror (h_errno));
    GNUNET_break (0);
  }
  else
  {
    if (0 != strcmp (rootserver->h_name, ROOTSERVER_NAME))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received hostname and hostname for root name server differ\n");
      GNUNET_break (0);
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "System's own reverse name resolution is working\n");
  /* Resolve the same using GNUNET */
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = (u_char) sizeof (sa);
#endif
#ifndef MINGW
  inet_aton (ROOTSERVER_IP, &sa.sin_addr);
#else
  sa.sin_addr.S_un.S_addr = inet_addr (ROOTSERVER_IP);
#endif
  GNUNET_RESOLVER_hostname_get ((const struct sockaddr *) &sa,
                                sizeof (struct sockaddr), GNUNET_YES, timeout,
                                &check_rootserver_name, cls);

  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = (u_char) sizeof (sa);
#endif
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  GNUNET_RESOLVER_ip_get ("localhost", AF_INET, timeout, &check_127, cls);
  GNUNET_RESOLVER_hostname_get ((const struct sockaddr *) &sa,
                                sizeof (struct sockaddr), GNUNET_YES, timeout,
                                &check_localhost, cls);

  GNUNET_RESOLVER_hostname_get ((const struct sockaddr *) &sa,
                                sizeof (struct sockaddr), GNUNET_NO, timeout,
                                &check_localhost_num, cls);
  GNUNET_RESOLVER_hostname_resolve (AF_UNSPEC, timeout, &check_hostname, cls);

}

static int
check ()
{
  int ok = 1 + 2 + 4 + 8;
  char *fn;
  char *pfx;
  struct GNUNET_OS_Process *proc;

  char *const argv[] =
      { "test-resolver-api", "-c", "test_resolver_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] =
      { GNUNET_GETOPT_OPTION_END };
  pfx = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_BINDIR);
  GNUNET_asprintf (&fn, "%s%cgnunet-service-resolver", pfx, DIR_SEPARATOR);
  GNUNET_free (pfx);
  proc = GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, fn, "gnunet-service-resolver",
#if VERBOSE
                                  "-L", "DEBUG",
#endif
                                  "-c", "test_resolver_api_data.conf", NULL);
  GNUNET_assert (NULL != proc);
  GNUNET_free (fn);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                                     argv, "test-resolver-api", "nohelp",
                                     options, &run, &ok));
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    ok = 1;
  }
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_destroy (proc);
  proc = NULL;
  if (ok != 0)
    FPRINTF (stderr, "Missed some resolutions: %u\n", ok);
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
