/*
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file regex/gnunet-regex-simulation-profiler.c
 * @brief Regex profiler that dumps all DFAs into a database instead of
 *        using the DHT (with mesh).
 * @author Maximilian Szengel
 *
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_regex_lib.h"
#include "gnunet_mysql_lib.h"

/**
 * Simple struct to keep track of progress, and print a
 * nice little percentage meter for long running tasks.
 */
struct ProgressMeter
{
  unsigned int total;

  unsigned int modnum;

  unsigned int dotnum;

  unsigned int completed;

  int print;

  char *startup_string;
};


/**
 * Handle for the progress meter
 */
static struct ProgressMeter *meter;

/**
 * Abort task identifier.
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Scan task identifier;
 */
static GNUNET_SCHEDULER_TaskIdentifier scan_task;

/**
 * Global testing status.
 */
static int result;

/**
 * MySQL context.
 */
static struct GNUNET_MYSQL_Context *mysql_ctx;

/**
 * MySQL table name.
 */
static char *table_name;

/**
 * Policy dir containing files that contain policies.
 */
static char *policy_dir;

/**
 * Number of policy files.
 */
static unsigned int num_policy_files;

/**
 * Number of policies.
 */
static unsigned int num_policies;

/**
 * Maximal path compression length.
 */
static unsigned int max_path_compression;


/**
 * Create a meter to keep track of the progress of some task.
 *
 * @param total the total number of items to complete
 * @param start_string a string to prefix the meter with (if printing)
 * @param print GNUNET_YES to print the meter, GNUNET_NO to count
 *              internally only
 *
 * @return the progress meter
 */
static struct ProgressMeter *
create_meter (unsigned int total, char *start_string, int print)
{
  struct ProgressMeter *ret;

  ret = GNUNET_malloc (sizeof (struct ProgressMeter));
  ret->print = print;
  ret->total = total;
  ret->modnum = total / 4;
  if (ret->modnum == 0)         /* Divide by zero check */
    ret->modnum = 1;
  ret->dotnum = (total / 50) + 1;
  if (start_string != NULL)
    ret->startup_string = GNUNET_strdup (start_string);
  else
    ret->startup_string = GNUNET_strdup ("");

  return ret;
}


/**
 * Update progress meter (increment by one).
 *
 * @param meter the meter to update and print info for
 *
 * @return GNUNET_YES if called the total requested,
 *         GNUNET_NO if more items expected
 */
static int
update_meter (struct ProgressMeter *meter)
{
  if (meter->print == GNUNET_YES)
  {
    if (meter->completed % meter->modnum == 0)
    {
      if (meter->completed == 0)
      {
        FPRINTF (stdout, "%sProgress: [0%%", meter->startup_string);
      }
      else
        FPRINTF (stdout, "%d%%",
                 (int) (((float) meter->completed / meter->total) * 100));
    }
    else if (meter->completed % meter->dotnum == 0)
      FPRINTF (stdout, "%s",  ".");

    if (meter->completed + 1 == meter->total)
      FPRINTF (stdout, "%d%%]\n", 100);
    fflush (stdout);
  }
  meter->completed++;

  if (meter->completed == meter->total)
    return GNUNET_YES;
  if (meter->completed > meter->total)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Progress meter overflow!!\n");
  return GNUNET_NO;
}


/**
 * Reset progress meter.
 *
 * @param meter the meter to reset
 *
 * @return GNUNET_YES if meter reset,
 *         GNUNET_SYSERR on error
 */
static int
reset_meter (struct ProgressMeter *meter)
{
  if (meter == NULL)
    return GNUNET_SYSERR;

  meter->completed = 0;
  return GNUNET_YES;
}


/**
 * Release resources for meter
 *
 * @param meter the meter to free
 */
static void
free_meter (struct ProgressMeter *meter)
{
  GNUNET_free_non_null (meter->startup_string);
  GNUNET_free (meter);
}


/**
 * Shutdown task.
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != mysql_ctx)
    GNUNET_MYSQL_context_destroy (mysql_ctx);
  if (NULL != meter)
    free_meter (meter);

  GNUNET_SCHEDULER_shutdown ();	/* Stop scheduler to shutdown testbed run */
}


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Aborting\n");
  abort_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SCHEDULER_cancel (scan_task);
  scan_task = GNUNET_SCHEDULER_NO_TASK;
  result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}


/**
 * Iterator over all states that inserts each state into the MySQL db.
 *
 * @param cls closure.
 * @param key hash for current state.
 * @param proof proof for current state.
 * @param accepting GNUNET_YES if this is an accepting state, GNUNET_NO if not.
 * @param num_edges number of edges leaving current state.
 * @param edges edges leaving current state.
 */
static void
regex_iterator (void *cls,
                const struct GNUNET_HashCode *key,
                const char *proof,
                int accepting,
                unsigned int num_edges,
                const struct GNUNET_REGEX_Edge *edges)
{
  char *stmt;
  unsigned int i;

  GNUNET_assert (NULL != mysql_ctx);

  for (i = 0; i < num_edges; i++)
  {
    GNUNET_asprintf (&stmt,
                     "INSERT IGNORE INTO `%s` (`key`, `label`, `to_key`, `accepting`) VALUES ('%s', '%s', '%s', '%d');",
                     table_name, GNUNET_h2s_full (key), edges[i].label,
                     GNUNET_h2s_full (&edges[i].destination), accepting);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Insert statement: %s\n", stmt);

    if (GNUNET_OK != GNUNET_MYSQL_statement_run (mysql_ctx, stmt))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error executing mysql statement: %s\n", stmt);
    }

    GNUNET_free (stmt);
  }
}


/**
 * Announce a regex by creating the DFA and iterating over each state, inserting
 * each state into a MySQL database.
 *
 * @param regex regular expression.
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure.
 */
static int
announce_regex (const char *regex)
{
  struct GNUNET_REGEX_Automaton *dfa;

  dfa = GNUNET_REGEX_construct_dfa (regex, strlen (regex), max_path_compression);

  if (NULL == dfa)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create DFA for regex %s\n", regex);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return GNUNET_SYSERR;
  }

  GNUNET_REGEX_iterate_all_edges (dfa, &regex_iterator, NULL);

  GNUNET_REGEX_automaton_destroy (dfa);

  return GNUNET_OK;
}


/**
 * Function called with a filename.
 *
 * @param cls closure
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK to continue to iterate,
 *  GNUNET_SYSERR to abort iteration with error!
 */
int
policy_filename_cb (void *cls, const char *filename)
{
  char *regex;
  char *data;
  char *buf;
  uint64_t filesize;
  unsigned int offset;

  GNUNET_assert (NULL != filename);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Announcing regexes from file %s\n",
              filename);

  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Could not find policy file %s\n", filename);
    return GNUNET_OK;
  }
  if (GNUNET_OK != GNUNET_DISK_file_size (filename, &filesize, GNUNET_YES, GNUNET_YES))
    filesize = 0;
  if (0 == filesize)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Policy file %s is empty.\n", filename);
    return GNUNET_OK;
  }
  data = GNUNET_malloc (filesize);
  if (filesize != GNUNET_DISK_fn_read (filename, data, filesize))
  {
    GNUNET_free (data);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Could not read policy file %s.\n",
                filename);
    return GNUNET_OK;
  }

  update_meter (meter);

  buf = data;
  offset = 0;
  regex = NULL;
  while (offset < (filesize - 1))
  {
    offset++;
    if (((data[offset] == '\n')) && (buf != &data[offset]))
    {
      data[offset] = '\0';
      regex = buf;
      GNUNET_assert (NULL != regex);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Announcing regex: %s\n",
                  regex);
      num_policies++;

      if (GNUNET_OK != announce_regex (regex))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Could not announce regex %s\n", regex);
      }

      buf = &data[offset + 1];
    }
    else if ((data[offset] == '\n') || (data[offset] == '\0'))
      buf = &data[offset + 1];
  }
  GNUNET_free (data);
  return GNUNET_OK;
}


/**
 * Iterate over files contained in policy_dir.
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_directory_scan (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Absolute start_time;
  struct GNUNET_TIME_Relative duration;

  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);

  meter = create_meter (num_policy_files, "Announcing policy files\n", GNUNET_YES);
  start_time = GNUNET_TIME_absolute_get ();
  GNUNET_DISK_directory_scan (policy_dir,
                              &policy_filename_cb,
                              NULL);
  duration = GNUNET_TIME_absolute_get_duration (start_time);
  reset_meter (meter);
  free_meter (meter);
  meter = NULL;

  printf ("Announced %u files containing %u policies in %s\n",
          num_policy_files, num_policies,
          GNUNET_STRINGS_relative_time_to_string (duration, GNUNET_NO));

  result = GNUNET_OK;
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param config configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  if (NULL == args[0])
  {
    fprintf (stderr, _("No policy directory specified on command line. Exiting.\n"));
    result = GNUNET_SYSERR;
    return;
  }
  if (GNUNET_YES != GNUNET_DISK_directory_test (args[0]))
  {
    fprintf (stderr, _("Specified policies directory does not exist. Exiting.\n"));
    result = GNUNET_SYSERR;
    return;
  }
  policy_dir = args[0];

  num_policy_files = GNUNET_DISK_directory_scan (policy_dir,
                                                 NULL,
                                                 NULL);
  meter = NULL;

  if (NULL == table_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "No table name specified, using default \"NFA\".\n");
    table_name = "NFA";
  }

  mysql_ctx = GNUNET_MYSQL_context_create (config, "regex-mysql");
  if (NULL == mysql_ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to create mysql context\n");
    result = GNUNET_SYSERR;
    return;
  }

  result = GNUNET_OK;

  scan_task = GNUNET_SCHEDULER_add_now (&do_directory_scan, NULL);

  abort_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 10), &do_abort,
                                  NULL);
}


/**
 * Main function.
 *
 * @param argc argument count
 * @param argv argument values
 * @return 0 on success
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'t', "table", "TABLENAME",
     gettext_noop ("name of the table to write DFAs"),
     1, &GNUNET_GETOPT_set_string, &table_name},
    {'p', "max-path-compression", "MAX_PATH_COMPRESSION",
     gettext_noop ("maximum path compression length"),
     1, &GNUNET_GETOPT_set_uint, &max_path_compression},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-regex-simulationprofiler [OPTIONS] policy-dir",
                          _("Profiler for regex library"),
                          options, &run, NULL);
  if (GNUNET_OK != ret)
    return ret;
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
