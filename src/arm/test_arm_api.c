/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * @file arm/test_arm_api.c
 * @brief testcase for arm_api.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_resolver_service.h"

#define LOG(...) GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

#define START_ARM GNUNET_YES

#define START_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 1500)

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ARM_Handle *arm;

static int ok = 1;

static int phase = 0;

static void
arm_stop_cb (void *cls,
	     enum GNUNET_ARM_RequestStatus status,
	     const char *servicename,
	     enum GNUNET_ARM_Result result)
{
  /* (6), a stop request should be sent to ARM successfully */
  /* ARM should report that it is stopping */
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (result == GNUNET_ARM_RESULT_STOPPED);
  GNUNET_break (phase == 6);
  phase++;
  LOG ("Sent 'STOP' request for arm to ARM %s\n", (status == GNUNET_ARM_REQUEST_SENT_OK) ? "successfully" : "unsuccessfully");
}


static void
resolver_stop_cb (void *cls,
		  enum GNUNET_ARM_RequestStatus status,
		  const char *servicename, enum GNUNET_ARM_Result result)
{
  /* (5), a stop request should be sent to ARM successfully.
   * ARM should report that resolver is stopped.
   */
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (result == GNUNET_ARM_RESULT_STOPPED);
  GNUNET_break (phase == 5);
  LOG ("Sent 'STOP' request for resolver to ARM %s\n", (status == GNUNET_ARM_REQUEST_SENT_OK) ? "successfully" : "unsuccessfully");
  phase++;
#if START_ARM
  GNUNET_ARM_request_service_stop (arm, "arm", TIMEOUT, arm_stop_cb, NULL);
#else
  arm_stop_cb (NULL, GNUNET_ARM_STATUS_SENT_OK, "arm", GNUNET_ARM_SERVICE_STOPPING);
  arm_conn (NULL, GNUNET_NO);
#endif
}


static void
dns_notify (void *cls, const struct sockaddr *addr, socklen_t addrlen)
{
  if (addr == NULL)
    {
      /* (4), resolver should finish resolving localhost */
      GNUNET_break (phase == 4);
      phase++;
      LOG ("Finished resolving localhost\n");
      if (ok != 0)
        ok = 2;
      GNUNET_ARM_request_service_stop (arm, "resolver", TIMEOUT, resolver_stop_cb, NULL);
      return;
    }
  /* (3), resolver should resolve localhost */
  GNUNET_break (phase == 3);
  LOG ("Resolved localhost\n");
  phase++;
  GNUNET_break (addr != NULL);
  ok = 0;
}


static void
resolver_start_cb (void *cls,
		   enum GNUNET_ARM_RequestStatus status,
		   const char *servicename,
		   enum GNUNET_ARM_Result result)
{
  /* (2), the start request for resolver should be sent successfully
   * ARM should report that resolver service is starting.
   */
  GNUNET_assert (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (phase == 2);
  GNUNET_break (result == GNUNET_ARM_RESULT_STARTING);
  LOG ("Sent 'START' request for resolver to ARM %s\n", (status == GNUNET_ARM_REQUEST_SENT_OK) ? "successfully" : "unsuccessfully");
  phase++;
  GNUNET_RESOLVER_ip_get ("localhost", AF_INET, TIMEOUT, &dns_notify, NULL);
}


static void
trigger_disconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_ARM_disconnect_and_free ((struct GNUNET_ARM_Handle *) cls);
}


static void
arm_conn (void *cls,
	  int connected)
{
  if (GNUNET_SYSERR == connected)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Fatal error initializing ARM API.\n"));
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_assert (0);
    return;
  }
  if (GNUNET_YES == connected)
  {
    /* (1), arm connection should be established */
    LOG ("Connected to ARM\n");
    GNUNET_break (phase == 1);
    phase++;
    GNUNET_ARM_request_service_start (arm, "resolver", GNUNET_OS_INHERIT_STD_OUT_AND_ERR, START_TIMEOUT, resolver_start_cb, NULL);
  }
  else
  {
    /* (7), ARM should stop (we disconnect from it) */
    LOG ("Disconnected from ARM\n");
    GNUNET_break (phase == 7);
    if (phase != 7)
      ok = 3;
    else if (ok == 1)
      ok = 0;
    GNUNET_SCHEDULER_add_now (trigger_disconnect, arm);
  }
}


static void
arm_start_cb (void *cls,
	      enum GNUNET_ARM_RequestStatus status,
	      const char *servicename,
	      enum GNUNET_ARM_Result result)
{
  /* (0) The request should be "sent" successfully
   * ("sent", because it isn't going anywhere, ARM API starts ARM service
   * by itself).
   * ARM API should report that ARM service is starting.
   */
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (phase == 0);
  LOG ("Sent 'START' request for arm to ARM %s\n", (status == GNUNET_ARM_REQUEST_SENT_OK) ? "successfully" : "unsuccessfully");
  GNUNET_break (result == GNUNET_ARM_RESULT_STARTING);
  phase++;
}


static void
task (void *cls, char *const *args, const char *cfgfile,
      const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *armconfig;
  cfg = c;
  if (NULL != cfgfile)
  {
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                 "arm", "CONFIG",
                                                 &armconfig))
    {
      GNUNET_CONFIGURATION_set_value_string ((struct GNUNET_CONFIGURATION_Handle
                                              *) cfg, "arm", "CONFIG",
                                             cfgfile);
    }
    else
      GNUNET_free (armconfig);
  }
  arm = GNUNET_ARM_connect (cfg, &arm_conn, NULL);
  if (NULL == arm)
    return;
#if START_ARM
  GNUNET_ARM_request_service_start (arm, "arm", GNUNET_OS_INHERIT_STD_OUT_AND_ERR, START_TIMEOUT, arm_start_cb, NULL);
#else
  arm_start_cb (NULL, arm, GNUNET_ARM_REQUEST_SENT_OK, "arm", GNUNET_ARM_RESULT_STARTING);
  arm_conn (NULL, arm, GNUNET_YES);
#endif
}


int
main (int argc, char *argvx[])
{
  char *const argv[] = {
    "test-arm-api",
    "-c", "test_arm_api_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_log_setup ("test-arm-api",
		    "WARNING",
		    NULL);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
				     argv, "test-arm-api", "nohelp", options,
				     &task, NULL));
  return ok;
}

/* end of test_arm_api.c */
