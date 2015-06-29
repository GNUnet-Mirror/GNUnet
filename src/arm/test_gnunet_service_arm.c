/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2014 Christian Grothoff (and other contributing authors)

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
 * @file arm/test_gnunet_service_arm.c
 * @brief testcase for gnunet-service-arm.c; tests ARM by making it start the resolver
 * @author Safey
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"

/**
 * Timeout for starting services, very short because of the strange way start works
 * (by checking if running before starting, so really this time is always waited on
 * startup (annoying)).
 */
#define START_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 50)

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


static int ret = 1;

static int resolved_ok;

static int asked_for_a_list;

static struct GNUNET_ARM_Handle *arm;


static void
trigger_disconnect (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_ARM_disconnect_and_free (arm);
  arm = NULL;
}


static void
arm_stop_cb (void *cls,
	     enum GNUNET_ARM_RequestStatus status,
	     const char *servicename,
	     enum GNUNET_ARM_Result result)
{
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (result == GNUNET_ARM_RESULT_STOPPED);
  if (result != GNUNET_ARM_RESULT_STOPPED)
  {
    GNUNET_break (0);
    ret = 4;
  }
  GNUNET_SCHEDULER_add_now (&trigger_disconnect, NULL);
}


static void
service_list (void *cls,
	      enum GNUNET_ARM_RequestStatus rs,
	      unsigned int count,
              const char *const*list)
{
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "%u services are are currently running\n",
	      count);
  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
    goto stop_arm;
  for (i=0;i<count;i++)
  {
    if (0 == strcasecmp (list[i],
                         "resolver (gnunet-service-resolver)"))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Got service list, now stopping arm\n");
      ret = 0;
    }
  }

 stop_arm:
  GNUNET_ARM_request_service_stop (arm,
                                   "arm",
                                   TIMEOUT,
                                   &arm_stop_cb, NULL);
}


static void
hostname_resolve_cb (void *cls,
                   const struct sockaddr *addr,
                   socklen_t addrlen)
{
  if ((0 == ret) || (4 == ret) || (1 == resolved_ok))
    return;
  if (NULL == addr)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Name not resolved!\n");
    GNUNET_break (0);
    ret = 3;
    GNUNET_ARM_request_service_stop (arm,
                                     "arm",
                                     TIMEOUT,
                                     &arm_stop_cb, NULL);
    return;
  }
  if (0 == asked_for_a_list)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Resolved hostname, now checking the service list\n");
    GNUNET_ARM_request_service_list (arm,
                                     TIMEOUT,
                                     &service_list,
                                     NULL);
    asked_for_a_list = 1;
    resolved_ok = 1;
  }
}


static void
arm_start_cb (void *cls,
	      enum GNUNET_ARM_RequestStatus status,
	      const char *servicename,
	      enum GNUNET_ARM_Result result)
{
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (result == GNUNET_ARM_RESULT_STARTING);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Trying to resolve our own hostname!\n");
  /* connect to the resolver service */
  if (NULL ==
      GNUNET_RESOLVER_hostname_resolve (AF_UNSPEC, TIMEOUT,
                                        &hostname_resolve_cb,
                                        NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable initiate connection to resolver service\n");
    GNUNET_break (0);
    ret = 2;
    GNUNET_ARM_request_service_stop (arm,
                                     "arm", TIMEOUT,
                                     &arm_stop_cb, NULL);
  }
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  arm = GNUNET_ARM_connect (c, NULL, NULL);
  GNUNET_ARM_request_service_start (arm, "arm",
                                    GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                    START_TIMEOUT,
                                    &arm_start_cb, NULL);
}


int
main (int argc, char *av[])
{
  static char *const argv[] = {
    "test-gnunet-service-arm",
    "-c",
    "test_arm_api_data.conf",
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  char hostname[GNUNET_OS_get_hostname_max_length () + 1];

  if (0 != gethostname (hostname, sizeof (hostname) - 1))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                         "gethostname");
    FPRINTF (stderr,
             "%s",
             "Failed to determine my own hostname, testcase not run.\n");
    return 0;
  }
  if ( (0 == strcmp (hostname,
		     "localhost")) ||
       (0 == strcmp (hostname,
		     "ipv6-localnet")) )
  {
    /* we cannot use 'localhost' as this would not trigger the
       resolver service (see resolver_api.c); so in this case,
       we fall back to (ab)using gnu.org. */
    strcpy (hostname,
	    "www.gnu.org");
  }
  /* trigger DNS lookup */
#if HAVE_GETADDRINFO
  {
    struct addrinfo *ai;
    int ret;

    if (0 != (ret = getaddrinfo (hostname, NULL, NULL, &ai)))
    {
      FPRINTF (stderr,
               "Failed to resolve my hostname `%s', testcase not run.\n",
               hostname);
      return 0;
    }
    freeaddrinfo (ai);
  }
#elif HAVE_GETHOSTBYNAME2
  {
    struct hostent *host;

    host = gethostbyname2 (hostname, AF_INET);
    if (NULL == host)
      host = gethostbyname2 (hostname, AF_INET6);
    if (NULL == host)
      {
        FPRINTF (stderr,
                 "Failed to resolve my hostname `%s', testcase not run.\n",
                 hostname);
        return 0;
      }
  }
#elif HAVE_GETHOSTBYNAME
  {
    struct hostent *host;

    host = gethostbyname (hostname);
    if (NULL == host)
      {
        FPRINTF (stderr,
                 "Failed to resolve my hostname `%s', testcase not run.\n",
                 hostname);
        return 0;
      }
  }
#else
  FPRINTF (stderr,
           "libc fails to have resolver function, testcase not run.\n");
  return 0;
#endif
  GNUNET_log_setup ("test-gnunet-service-arm",
		    "WARNING",
		    NULL);
  GNUNET_break (GNUNET_OK ==
		GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
				    argv, "test-gnunet-service-arm",
				    "nohelp", options,
                                    &run, NULL));
  if (0 != ret)
  {
    fprintf (stderr,
             "Test failed with error code %d\n",
             ret);
  }
  return ret;
}

/* end of test_gnunet_service_arm.c */
