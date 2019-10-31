/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2011, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
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

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ARM_Handle *arm;

static struct GNUNET_ARM_Operation *op;

static int ok = 1;

static int phase = 0;


static void
arm_stop_cb (void *cls,
             enum GNUNET_ARM_RequestStatus status,
             enum GNUNET_ARM_Result result)
{
  op = NULL;
  /* (6), a stop request should be sent to ARM successfully */
  /* ARM should report that it is stopping */
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (result == GNUNET_ARM_RESULT_STOPPED);
  GNUNET_break (phase == 6);
  phase++;
  LOG ("Sent 'STOP' request for arm to ARM %s\n",
       (status == GNUNET_ARM_REQUEST_SENT_OK) ? "successfully" :
       "unsuccessfully");
  GNUNET_SCHEDULER_shutdown ();
}


static void
resolver_stop_cb (void *cls,
                  enum GNUNET_ARM_RequestStatus status,
                  enum GNUNET_ARM_Result result)
{
  op = NULL;
  /* (5), a stop request should be sent to ARM successfully.
   * ARM should report that resolver is stopped.
   */
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (result == GNUNET_ARM_RESULT_STOPPED);
  GNUNET_break (phase == 5);
  LOG ("Sent 'STOP' request for resolver to ARM %s\n",
       (status == GNUNET_ARM_REQUEST_SENT_OK) ? "successfully" :
       "unsuccessfully");
  phase++;
  GNUNET_assert (NULL == op);
  op = GNUNET_ARM_request_service_stop (arm,
                                        "arm",
                                        &arm_stop_cb,
                                        NULL);
}


static void
dns_notify (void *cls,
            const struct sockaddr *addr,
            socklen_t addrlen)
{
  if (addr == NULL)
  {
    /* (4), resolver should finish resolving localhost */
    GNUNET_break (phase == 4);
    phase++;
    LOG ("Finished resolving localhost\n");
    if (ok != 0)
      ok = 2;
    GNUNET_assert (NULL == op);
    op = GNUNET_ARM_request_service_stop (arm,
                                          "resolver",
                                          &resolver_stop_cb,
                                          NULL);
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
                   enum GNUNET_ARM_Result result)
{
  op = NULL;
  /* (2), the start request for resolver should be sent successfully
   * ARM should report that resolver service is starting.
   */
  GNUNET_assert (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (phase == 2);
  GNUNET_break (result == GNUNET_ARM_RESULT_STARTING);
  LOG ("Sent 'START' request for resolver to ARM %s\n",
       (status == GNUNET_ARM_REQUEST_SENT_OK) ? "successfully" :
       "unsuccessfully");
  phase++;
  GNUNET_RESOLVER_ip_get ("localhost",
                          AF_INET,
                          TIMEOUT,
                          &dns_notify, NULL);
}


static void
arm_conn (void *cls,
          int connected)
{
  if (GNUNET_SYSERR == connected)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Fatal error initializing ARM API.\n"));
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
    GNUNET_assert (NULL == op);
    op = GNUNET_ARM_request_service_start (arm,
                                           "resolver",
                                           GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                           &resolver_start_cb,
                                           NULL);
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
  }
}


static void
arm_start_cb (void *cls,
              enum GNUNET_ARM_RequestStatus status,
              enum GNUNET_ARM_Result result)
{
  op = NULL;
  /* (0) The request should be "sent" successfully
   * ("sent", because it isn't going anywhere, ARM API starts ARM service
   * by itself).
   * ARM API should report that ARM service is starting.
   */GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (phase == 0);
  LOG ("Sent 'START' request for arm to ARM %s\n",
       (status == GNUNET_ARM_REQUEST_SENT_OK) ? "successfully" :
       "unsuccessfully");
  GNUNET_break (result == GNUNET_ARM_RESULT_STARTING);
  phase++;
}


static void
do_shutdown (void *cls)
{
  if (NULL != op)
  {
    GNUNET_ARM_operation_cancel (op);
    op = NULL;
  }
  if (NULL != arm)
  {
    GNUNET_ARM_disconnect (arm);
    arm = NULL;
  }
}


static void
task (void *cls,
      char *const *args,
      const char *cfgfile,
      const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
  arm = GNUNET_ARM_connect (cfg,
                            &arm_conn,
                            NULL);
  if (NULL == arm)
    return;
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  op = GNUNET_ARM_request_service_start (arm,
                                         "arm",
                                         GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                         &arm_start_cb,
                                         NULL);
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
                 GNUNET_PROGRAM_run ((sizeof(argv) / sizeof(char *)) - 1,
                                     argv, "test-arm-api", "nohelp", options,
                                     &task, NULL));
  return ok;
}


/* end of test_arm_api.c */
