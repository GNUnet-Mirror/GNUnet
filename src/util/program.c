/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPROSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file util/program.c
 * @brief standard code for GNUnet startup and shutdown
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_constants.h"
#include "speedup.h"
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
   * Closure for @e task.
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

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  GNUNET_SPEEDUP_start_(cc->cfg);
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
cmd_sorter (const void *a1, const void *a2)
{
  const struct GNUNET_GETOPT_CommandLineOption *c1 = a1;
  const struct GNUNET_GETOPT_CommandLineOption *c2 = a2;

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
 * @param argc number of command line arguments in @a argv
 * @param argv command line arguments
 * @param binaryName our expected name
 * @param binaryHelp help text for the program
 * @param options command line options
 * @param task main function to run
 * @param task_cls closure for @a task
 * @param run_without_scheduler #GNUNET_NO start the scheduler, #GNUNET_YES do not
 *        start the scheduler just run the main task
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_PROGRAM_run2 (int argc, char *const *argv, const char *binaryName,
                    const char *binaryHelp,
                    const struct GNUNET_GETOPT_CommandLineOption *options,
                    GNUNET_PROGRAM_Main task, void *task_cls,
                    int run_without_scheduler)
{
  struct CommandContext cc;
#if ENABLE_NLS
  char *path;
#endif
  char *loglev;
  char *logfile;
  char *cfg_fn;
  const char *xdg;
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
    GNUNET_GETOPT_OPTION_VERSION (PACKAGE_VERSION " " VCS_VERSION)
  };
  struct GNUNET_GETOPT_CommandLineOption *allopts;
  const char *gargs;
  char *lpfx;
  char *spc;

  logfile = NULL;
  gargs = getenv ("GNUNET_ARGS");
  if (NULL != gargs)
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
    for (tok = strtok (cargs, " "); NULL != tok; tok = strtok (NULL, " "))
      GNUNET_array_append (gargv, gargc, GNUNET_strdup (tok));
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
  if (NULL != path)
  {
    BINDTEXTDOMAIN ("GNUnet", path);
    GNUNET_free (path);
  }
  textdomain ("GNUnet");
#endif
  cnt = 0;
  while (NULL != options[cnt].name)
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
  xdg = getenv ("XDG_CONFIG_HOME");
  if (NULL != xdg)
    GNUNET_asprintf (&cfg_fn,
                     "%s%s%s",
                     xdg,
                     DIR_SEPARATOR_STR,
                     "gnunet.conf");
  else
    cfg_fn = GNUNET_strdup (GNUNET_DEFAULT_USER_CONFIG_FILE);
  lpfx = GNUNET_strdup (binaryName);
  if (NULL != (spc = strstr (lpfx, " ")))
    *spc = '\0';
  ret = GNUNET_GETOPT_run (binaryName, allopts, (unsigned int) argc, argv);
  if ((GNUNET_OK > ret) ||
      (GNUNET_OK != GNUNET_log_setup (lpfx, loglev, logfile)))
  {
    GNUNET_free (allopts);
    GNUNET_free (lpfx);
    goto cleanup;
  }
  if (NULL == cc.cfgfile)
    cc.cfgfile = GNUNET_strdup (cfg_fn);
  if (GNUNET_YES ==
      GNUNET_DISK_file_test (cc.cfgfile))
  {
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (cfg, cc.cfgfile))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Malformed configuration file `%s', exit ...\n"),
                  cc.cfgfile);
      ret = GNUNET_SYSERR;
      GNUNET_free (allopts);
      GNUNET_free (lpfx);
      goto cleanup;
    }
  }
  else
  {
    if (0 != strcmp (cc.cfgfile, cfg_fn))
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not access configuration file `%s'\n"),
		  cc.cfgfile);
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (cfg, NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Malformed configuration, exit ...\n"));
      ret = GNUNET_SYSERR;
      GNUNET_free (allopts);
      GNUNET_free (lpfx);
      goto cleanup;
    }
  }
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
  /* ARM needs to know which configuration file to use when starting
     services.  If we got a command-line option *and* if nothing is
     specified in the configuration, remember the command-line option
     in "cfg".  This is typically really only having an effect if we
     are running code in src/arm/, as obviously the rest of the code
     has little business with ARM-specific options. */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_have_value (cfg,
                                       "arm",
                                       "CONFIG"))
  {
    GNUNET_CONFIGURATION_set_value_string (cfg,
                                           "arm", "CONFIG",
                                           cc.cfgfile);
  }

  /* run */
  cc.args = &argv[ret];
  if (GNUNET_NO == run_without_scheduler)
  {
    GNUNET_SCHEDULER_run (&program_main, &cc);
  }
  else
  {
    GNUNET_RESOLVER_connect (cc.cfg);
    cc.task (cc.task_cls, cc.args, cc.cfgfile, cc.cfg);
  }
  ret = GNUNET_OK;
 cleanup:
  GNUNET_SPEEDUP_stop_ ();
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_free_non_null (cc.cfgfile);
  GNUNET_free (cfg_fn);
  GNUNET_free_non_null (loglev);
  GNUNET_free_non_null (logfile);
  return ret;
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
 * @param task_cls closure for @a task
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_PROGRAM_run (int argc, char *const *argv,
                    const char *binaryName,
                    const char *binaryHelp,
                    const struct GNUNET_GETOPT_CommandLineOption *options,
                    GNUNET_PROGRAM_Main task,
                    void *task_cls)
{
  return GNUNET_PROGRAM_run2 (argc, argv,
                              binaryName, binaryHelp,
                              options,
                              task, task_cls,
                              GNUNET_NO);
}


/* end of program.c */
