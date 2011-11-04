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
 * @file util/program.c
 * @brief standard code for GNUnet startup and shutdown
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_directories.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_scheduler_lib.h"
#include <gcrypt.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * Context for the command.
 */
struct CommandContext
{
  /**
   * Argv argument.
   */
  char *const *args;

  /**
   * Name of the configuration file used, can be NULL!
   */
  char *cfgfile;

  /**
   * Main function to run.
   */
  GNUNET_PROGRAM_Main task;

  /**
   * Closure for task.
   */
  void *task_cls;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

};


/**
 * Initial task called by the scheduler for each
 * program.  Runs the program-specific main task.
 */
static void
program_main (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CommandContext *cc = cls;

  GNUNET_RESOLVER_connect (cc->cfg);
  cc->task (cc->task_cls, cc->args, cc->cfgfile, cc->cfg);
}


/**
 * Compare function for 'qsort' to sort command-line arguments by the
 * short option.
 *
 * @param a1 first command line option
 * @param a2 second command line option
 */
static int
cmd_sorter (__const void *a1, __const void *a2)
{
  __const struct GNUNET_GETOPT_CommandLineOption *c1 = a1;
  __const struct GNUNET_GETOPT_CommandLineOption *c2 = a2;

  if (toupper ((unsigned char) c1->shortName) >
      toupper ((unsigned char) c2->shortName))
    return 1;
  if (toupper ((unsigned char) c1->shortName) <
      toupper ((unsigned char) c2->shortName))
    return -1;
  if (c1->shortName > c2->shortName)
    return 1;
  if (c1->shortName < c2->shortName)
    return -1;
  return 0;
}


/**
 * Run a standard GNUnet command startup sequence (initialize loggers
 * and configuration, parse options).
 *
 * @param argc number of command line arguments
 * @param argv command line arguments
 * @param binaryName our expected name
 * @param binaryHelp help text for the program
 * @param options command line options
 * @param task main function to run
 * @param task_cls closure for task
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_PROGRAM_run (int argc, char *const *argv, const char *binaryName,
                    const char *binaryHelp,
                    const struct GNUNET_GETOPT_CommandLineOption *options,
                    GNUNET_PROGRAM_Main task, void *task_cls)
{
  struct CommandContext cc;
  char *path;
  char *loglev;
  char *logfile;
  int ret;
  unsigned int cnt;
  unsigned long long skew_offset;
  unsigned long long skew_variance;
  long long clock_offset;
  struct GNUNET_CONFIGURATION_Handle *cfg;

  struct GNUNET_GETOPT_CommandLineOption defoptions[] = {
    GNUNET_GETOPT_OPTION_CFG_FILE (&cc.cfgfile),
    GNUNET_GETOPT_OPTION_HELP (binaryHelp),
    GNUNET_GETOPT_OPTION_LOGLEVEL (&loglev),
    GNUNET_GETOPT_OPTION_LOGFILE (&logfile),
    GNUNET_GETOPT_OPTION_VERSION (PACKAGE_VERSION)
  };
  struct GNUNET_GETOPT_CommandLineOption *allopts;
  const char *gargs;
  char *lpfx;
  char *spc;

  logfile = NULL;
  gargs = getenv ("GNUNET_ARGS");
  if (gargs != NULL)
  {
    char **gargv;
    unsigned int gargc;
    int i;
    char *tok;
    char *cargs;

    gargv = NULL;
    gargc = 0;
    for (i = 0; i < argc; i++)
      GNUNET_array_append (gargv, gargc, GNUNET_strdup (argv[i]));
    cargs = GNUNET_strdup (gargs);
    tok = strtok (cargs, " ");
    while (NULL != tok)
    {
      GNUNET_array_append (gargv, gargc, GNUNET_strdup (tok));
      tok = strtok (NULL, " ");
    }
    GNUNET_free (cargs);
    GNUNET_array_append (gargv, gargc, NULL);
    argv = (char *const *) gargv;
    argc = gargc - 1;
  }
  memset (&cc, 0, sizeof (cc));
  loglev = NULL;
  cc.task = task;
  cc.task_cls = task_cls;
  cc.cfg = cfg = GNUNET_CONFIGURATION_create ();

  /* prepare */
#if ENABLE_NLS
  setlocale (LC_ALL, "");
  path = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LOCALEDIR);
  if (path != NULL)
  {
    BINDTEXTDOMAIN ("GNUnet", path);
    GNUNET_free (path);
  }
  textdomain ("GNUnet");
#endif
  cnt = 0;
  while (options[cnt].name != NULL)
    cnt++;
  allopts =
      GNUNET_malloc ((cnt +
                      1) * sizeof (struct GNUNET_GETOPT_CommandLineOption) +
                     sizeof (defoptions));
  memcpy (allopts, defoptions, sizeof (defoptions));
  memcpy (&allopts
          [sizeof (defoptions) /
           sizeof (struct GNUNET_GETOPT_CommandLineOption)], options,
          (cnt + 1) * sizeof (struct GNUNET_GETOPT_CommandLineOption));
  cnt += sizeof (defoptions) / sizeof (struct GNUNET_GETOPT_CommandLineOption);
  qsort (allopts, cnt, sizeof (struct GNUNET_GETOPT_CommandLineOption),
         &cmd_sorter);
  loglev = NULL;
  cc.cfgfile = GNUNET_strdup (GNUNET_DEFAULT_USER_CONFIG_FILE);
  lpfx = GNUNET_strdup (binaryName);
  if (NULL != (spc = strstr (lpfx, " ")))
    *spc = '\0';
  if ((-1 ==
       (ret =
        GNUNET_GETOPT_run (binaryName, allopts, (unsigned int) argc, argv))) ||
      (GNUNET_OK != GNUNET_log_setup (lpfx, loglev, logfile)))
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_free_non_null (cc.cfgfile);
    GNUNET_free_non_null (loglev);
    GNUNET_free_non_null (logfile);
    GNUNET_free (allopts);
    GNUNET_free (lpfx);
    return GNUNET_SYSERR;
  }
  (void) GNUNET_CONFIGURATION_load (cfg, cc.cfgfile);
  GNUNET_free (allopts);
  GNUNET_free (lpfx);
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cc.cfg, "testing", "skew_offset",
                                             &skew_offset) &&
      (GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (cc.cfg, "testing",
                                              "skew_variance", &skew_variance)))
  {
    clock_offset = skew_offset - skew_variance;
    GNUNET_TIME_set_offset (clock_offset);
  }
  /* run */
  cc.args = &argv[ret];
  GNUNET_SCHEDULER_run (&program_main, &cc);

  /* clean up */
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_free_non_null (cc.cfgfile);
  GNUNET_free_non_null (loglev);
  GNUNET_free_non_null (logfile);
  return GNUNET_OK;
}


/* end of program.c */
