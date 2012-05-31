/*
      This file is part of GNUnet
      (C) 2008, 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file testing/test_testing_new_servicestartup.c
 * @brief test case for testing service startup using new testing API
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_testing_lib-new.h"


#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)

#define TIME_REL_SEC(sec)					\
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, sec)

/**
 * Global test status
 */
static int test_success;

/**
 * The shutdown task. Used to signal that testing is done and service has to be
 * stopped 
 *
 * @param cls NULL
 */
static void
shutdown_task(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  test_success = GNUNET_YES;
  GNUNET_SCHEDULER_shutdown ();  
}


/**
 * The testing callback function
 *
 * @param cls NULL
 * @param cfg the configuration with which the current testing service is run
 */
static void
test_run (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (NULL == cls);
  GNUNET_assert (NULL != cfg);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Service arm started successfully\n");
  GNUNET_SCHEDULER_add_delayed (TIME_REL_SEC (3), &shutdown_task, NULL);
}


/**
 * The main point of execution
 */
int main (int argc, char *argv[])
{
  char *_tmpdir;
  char *tmpdir;
#ifdef MINGW
  char *tmpdir_w;
#endif
  
  GNUNET_log_setup ("test_testing_new_servicestartup", "DEBUG", NULL);  
  _tmpdir = getenv ("TMP");
  if (NULL == _tmpdir)
    _tmpdir = getenv ("TEMP");  
  if (NULL == _tmpdir)
    _tmpdir = getenv ("TMPDIR");
  if (NULL == _tmpdir)
    _tmpdir = "/tmp";
  GNUNET_asprintf (&tmpdir, "%s/%s", _tmpdir, "test-gnunet-testing_new-XXXXXX");  
#ifdef MINGW
  tmpdir_w = GNUNET_malloc (MAX_PATH + 1);
  GNUNET_assert (ERROR_SUCCESS == plibc_conv_to_win_path (tmpdir, tmpdir_w));
  GNUNET_free (tmpdir);
  tmpdir = tmpdir_w;
  //GNUNET_assert (0 == _mktemp_s (tmpdir, strlen (tmpdir) + 1));
#else
  GNUNET_assert (mkdtemp (tmpdir) == tmpdir);
#endif

  test_success = GNUNET_NO;
  GNUNET_assert (0 == GNUNET_TESTING_service_run (tmpdir,
                                                  "arm",
                                                  "test_testing_defaults.conf",
                                                  &test_run,
                                                  NULL));
  GNUNET_free (tmpdir);
  return (GNUNET_YES == test_success) ? 0 : 1;
}
