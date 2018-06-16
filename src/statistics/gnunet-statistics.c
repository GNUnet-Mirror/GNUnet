/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2004-2007, 2009, 2016 GNUnet e.V.

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
*/

/**
 * @file statistics/gnunet-statistics.c
 * @brief tool to obtain statistics
 * @author Christian Grothoff
 * @author Igor Wronsky
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "statistics.h"


/**
 * Final status code.
 */
static int ret;

/**
 * Set to subsystem that we're going to get stats for (or NULL for all).
 */
static char *subsystem;

/**
 * The path of the testbed data.
 */
static char *path_testbed;

/**
 * Set to the specific stat value that we are after (or NULL for all).
 */
static char *name;

/**
 * Make the value that is being set persistent.
 */
static int persistent;

/**
 * Watch value continuously
 */
static int watch;

/**
 * Quiet mode
 */
static int quiet;

/**
 * @brief Separator string for csv.
 */
static char *csv_separator;

/**
 * Remote host
 */
static char *remote_host;

/**
 * Remote host's port
 */
static unsigned long long remote_port;

/**
 * Value to set
 */
static unsigned long long set_val;

/**
 * Set operation
 */
static int set_value;

/**
 * @brief Representation of all (testbed) nodes.
 */
static struct Node {
  /**
   * @brief Index of the node in this array.
   */
  unsigned index_node;

  /**
   * @brief Configuration handle for this node
   */
  struct GNUNET_CONFIGURATION_Handle *conf;

  /**
   * Handle for pending GET operation.
   */
  struct GNUNET_STATISTICS_GetHandle *gh;

  /**
   * @brief Statistics handle nodes.
   */
  struct GNUNET_STATISTICS_Handle *handle;
  /**
   * @brief Identifier for shutdown task for this node.
   */
  struct GNUNET_SCHEDULER_Task *shutdown_task;
} *nodes;

/**
 * @brief Number of configurations of all (testbed) nodes.
 */
static unsigned num_nodes;

/**
 * @brief Set of values for a combination of subsystem and name.
 */
struct ValueSet
{
  /**
   * @brief Subsystem of the valueset.
   */
  char *subsystem;

  /**
   * @brief Name of the valueset.
   */
  char *name;

  /**
   * @brief The values.
   */
  uint64_t *values;

  /**
   * @brief Persistence of the values.
   */
  int is_persistent;
};

/**
 * @brief Collection of all values (represented with #ValueSet).
 */
static struct GNUNET_CONTAINER_MultiHashMap *values;

/**
 * @brief Number of nodes that have their values ready.
 */
static int num_nodes_ready;

/**
 * @brief Create a new #ValueSet
 *
 * @param subsystem Subsystem of the valueset.
 * @param name Name of the valueset.
 * @param num_values Number of values in valueset - number of peers.
 * @param is_persistent Persistence status of values.
 *
 * @return Newly allocated #ValueSet.
 */
static struct ValueSet *
new_value_set (const char *subsystem,
               const char *name,
               unsigned num_values,
               int is_persistent)
{
  struct ValueSet *value_set;

  value_set = GNUNET_new (struct ValueSet);
  value_set->subsystem = GNUNET_strdup (subsystem);
  value_set->name = GNUNET_strdup (name);
  value_set->values = GNUNET_new_array (num_values, uint64_t);
  value_set->is_persistent = persistent;
  return value_set;
}

/**
 * @brief Print the (collected) values.
 *
 * Implements #GNUNET_CONTAINER_HashMapIterator.
 *
 * @param cls Closure - unused
 * @param key #GNUNET_HashCode key of #GNUNET_CONTAINER_MultiHashMap iterator -
 *        unused
 * @param value Values represented as #ValueSet.
 *
 * @return GNUNET_YES - continue iteration.
 */
static int
printer (void *cls,
         const struct GNUNET_HashCode *key,
         void *value)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get();
  const char *now_str;
  struct ValueSet *value_set = value;

  if (quiet == GNUNET_NO)
  {
    if (GNUNET_YES == watch)
    {
      now_str = GNUNET_STRINGS_absolute_time_to_string (now);
      FPRINTF (stdout,
	       "%24s%s %s%s%12s%s %50s%s ",
               now_str,
               csv_separator,
               value_set->is_persistent ? "!" : " ",
               csv_separator,
               value_set->subsystem,
               csv_separator,
	             _(value_set->name),
               (0 == strlen (csv_separator) ? ":": csv_separator));
    }
    else
    {
      FPRINTF (stdout,
	       "%s%s%12s%s %50s%s ",
               value_set->is_persistent ? "!" : " ",
               csv_separator,
               value_set->subsystem,
               csv_separator,
               _(value_set->name),
               (0 == strlen (csv_separator) ? ":": csv_separator));
    }
  }
  for (unsigned i = 0; i < num_nodes; i++)
  {
    FPRINTF (stdout,
            "%16llu%s",
            (unsigned long long) value_set->values[i],
            csv_separator);
  }
  FPRINTF (stdout, "\n");
  GNUNET_free (value_set->subsystem);
  GNUNET_free (value_set->name);
  GNUNET_free (value_set->values);
  GNUNET_free (value_set);
  return GNUNET_YES;
}

/**
 * @brief Called once all statistic values are available.
 *
 * Implements #GNUNET_STATISTICS_Callback
 *
 * @param cls Closure - The index of the node.
 * @param succes Whether statistics were obtained successfully.
 */
static void
continuation_print (void *cls,
                    int success)
{
  const unsigned index_node = *(unsigned *) cls;

  nodes[index_node].gh = NULL;
  if (GNUNET_OK != success)
  {
    if (NULL == remote_host)
      FPRINTF (stderr,
               "%s",
               _("Failed to obtain statistics.\n"));
    else
      FPRINTF (stderr,
               _("Failed to obtain statistics from host `%s:%llu'\n"),
               remote_host,
               remote_port);
    ret = 1;
  }
  num_nodes_ready++;
  if (num_nodes_ready == num_nodes)
  {
    GNUNET_CONTAINER_multihashmap_iterate (values, printer, NULL);
    GNUNET_SCHEDULER_shutdown();
  }
}

/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
printer_watch (void *cls,
               const char *subsystem,
               const char *name,
               uint64_t value,
               int is_persistent)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get();
  const char *now_str;

  if (quiet == GNUNET_NO)
  {
    if (GNUNET_YES == watch)
    {
      now_str = GNUNET_STRINGS_absolute_time_to_string (now);
      FPRINTF (stdout,
               "%24s%s %s%s%12s%s %50s%s %16llu\n",
               now_str,
               csv_separator,
               is_persistent ? "!" : " ",
               csv_separator,
               subsystem,
               csv_separator,
               _(name),
               (0 == strlen (csv_separator) ? ":": csv_separator),
               (unsigned long long) value);
    }
    else
    {
      FPRINTF (stdout,
               "%s%s%12s%s %50s%s %16llu\n",
               is_persistent ? "!" : " ",
               csv_separator,
               subsystem,
               csv_separator,
               _(name),
               (0 == strlen (csv_separator) ? ":": csv_separator),
               (unsigned long long) value);
    }
  }
  else
    FPRINTF (stdout,
	     "%llu\n",
	     (unsigned long long) value);

  return GNUNET_OK;
}

/**
 * Function called last by the statistics code.
 *
 * @param cls closure
 * @param success #GNUNET_OK if statistics were
 *        successfully obtained, #GNUNET_SYSERR if not.
 */
static void
cleanup (void *cls,
         int success)
{
  for (unsigned i = 0; i < num_nodes; i++)
  {
    nodes[i].gh = NULL;
  }
  if (GNUNET_OK != success)
  {
    if (NULL == remote_host)
      FPRINTF (stderr,
               "%s",
               _("Failed to obtain statistics.\n"));
    else
      FPRINTF (stderr,
               _("Failed to obtain statistics from host `%s:%llu'\n"),
               remote_host,
               remote_port);
    ret = 1;
  }
  GNUNET_SCHEDULER_shutdown ();
}

/**
 * @brief Iterate over statistics values and store them in #values.
 * They will be printed once all are available.
 *
 * @param cls Cosure - Node index.
 * @param subsystem Subsystem of the value.
 * @param name Name of the value.
 * @param value Value itself.
 * @param is_persistent Persistence.
 *
 * @return GNUNET_OK - continue.
 */
static int
collector (void *cls,
           const char *subsystem,
           const char *name,
           uint64_t value,
           int is_persistent)
{
  const unsigned index_node = *(unsigned *) cls;
  struct GNUNET_HashCode *key;
  struct GNUNET_HashCode hc;
  char *subsys_name;
  unsigned len_subsys_name;
  struct ValueSet *value_set;

  len_subsys_name = strlen (subsystem) + 3 + strlen (name) + 1;
  subsys_name = GNUNET_malloc (len_subsys_name);
  SPRINTF (subsys_name, "%s---%s", subsystem, name);
  key = &hc;
  GNUNET_CRYPTO_hash (subsys_name, len_subsys_name, key);
  GNUNET_free (subsys_name);
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (values, key))
  {
    // get
    value_set = GNUNET_CONTAINER_multihashmap_get (values, key);
  }
  else
  {
    // new
    value_set = new_value_set (subsystem, name, num_nodes, is_persistent);
  }
  // write
  value_set->values[index_node] = value;
  // put
  GNUNET_CONTAINER_multihashmap_put (values, key, value_set,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  return GNUNET_OK;
}

/**
 * Function run on shutdown to clean up.
 *
 * @param cls the statistics handle
 */
static void
shutdown_task (void *cls)
{
  const unsigned index_node = *(unsigned *) cls;
  struct GNUNET_STATISTICS_Handle *h;
  struct GNUNET_STATISTICS_GetHandle *gh;

  nodes[index_node].shutdown_task = NULL;
  if ( (NULL != path_testbed) &&
       (NULL != nodes[index_node].conf) )
  {
    GNUNET_CONFIGURATION_destroy (nodes[index_node].conf);
    nodes[index_node].conf = NULL;
  }

  h = nodes[index_node].handle;
  gh = nodes[index_node].gh;
  if (NULL == h)
  {
    num_nodes_ready--;
    if (0 == num_nodes_ready)
    {
      GNUNET_array_grow (nodes, num_nodes, 0);
      GNUNET_CONTAINER_multihashmap_destroy (values);
    }
    return;
  }
  if (NULL != gh)
  {
    GNUNET_STATISTICS_get_cancel (gh);
    gh = NULL;
  }
  if ( (GNUNET_YES == watch) &&
       (NULL != subsystem) &&
       (NULL != name) )
    GNUNET_assert (GNUNET_OK ==
       GNUNET_STATISTICS_watch_cancel (h,
                                                   subsystem,
                                                   name,
                                                   &printer_watch,
               &nodes[index_node].index_node));
  GNUNET_STATISTICS_destroy (h,
                             GNUNET_NO);
  h = NULL;

  num_nodes_ready--;
  if (0 == num_nodes_ready)
  {
    GNUNET_array_grow (nodes, num_nodes, 0);
    GNUNET_CONTAINER_multihashmap_destroy (values);
  }
}


/**
 * Main task that does the actual work.
 *
 * @param cls closure with our configuration
 */
static void
main_task (void *cls)
{
  unsigned index_node = *(unsigned *) cls;
  const struct GNUNET_CONFIGURATION_Handle *cfg = nodes[index_node].conf;

  if (set_value)
  {
    if (NULL == subsystem)
    {
      FPRINTF (stderr,
	       "%s",
	       _("Missing argument: subsystem \n"));
      ret = 1;
      return;
    }
    if (NULL == name)
    {
      FPRINTF (stderr,
	       "%s",
	       _("Missing argument: name\n"));
      ret = 1;
      return;
    }
    nodes[index_node].handle = GNUNET_STATISTICS_create (subsystem,
				  cfg);
    if (NULL == nodes[index_node].handle)
    {
      ret = 1;
      return;
    }
    GNUNET_STATISTICS_set (nodes[index_node].handle,
                           name,
                           (uint64_t) set_val,
                           persistent);
    GNUNET_STATISTICS_destroy (nodes[index_node].handle,
                               GNUNET_YES);
    nodes[index_node].handle = NULL;
    return;
  }
  if (NULL == (nodes[index_node].handle = GNUNET_STATISTICS_create ("gnunet-statistics",
                                             cfg)))
  {
    ret = 1;
    return;
  }
  if (GNUNET_NO == watch)
  {
    if (NULL ==
        (nodes[index_node].gh = GNUNET_STATISTICS_get (nodes[index_node].handle,
                                                       subsystem,
                                                       name,
                                                       &continuation_print,
                                                       &collector,
				     &nodes[index_node].index_node)) )
      cleanup (nodes[index_node].handle,
	       GNUNET_SYSERR);
  }
  else
  {
    if ( (NULL == subsystem) ||
	 (NULL == name) )
    {
      printf (_("No subsystem or name given\n"));
      GNUNET_STATISTICS_destroy (nodes[index_node].handle,
				 GNUNET_NO);
      nodes[index_node].handle = NULL;
      ret = 1;
      return;
    }
    if (GNUNET_OK !=
        GNUNET_STATISTICS_watch (nodes[index_node].handle,
                                 subsystem,
                                 name,
                                 &printer_watch,
				 &nodes[index_node].index_node))
    {
      fprintf (stderr,
               _("Failed to initialize watch routine\n"));
      nodes[index_node].shutdown_task =
        GNUNET_SCHEDULER_add_now (&shutdown_task,
                                  &nodes[index_node].index_node);
      return;
    }
  }
  nodes[index_node].shutdown_task =
    GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                   &nodes[index_node].index_node);
}

/**
 * @brief Iter over content of a node's directory to check for existence of a
 * config file.
 *
 * Implements #GNUNET_FileNameCallback
 *
 * @param cls pointer to indicate success
 * @param filename filename inside the directory of the potential node
 *
 * @return to continue iteration or not to
 */
static int
iter_check_config (void *cls,
                   const char *filename)
{
  if (0 == strncmp (GNUNET_STRINGS_get_short_name (filename), "config", 6))
  {
    /* Found the config - stop iteration successfully */
    GNUNET_array_grow (nodes, num_nodes, num_nodes+1);
    nodes[num_nodes-1].conf = GNUNET_CONFIGURATION_create();
    nodes[num_nodes-1].index_node = num_nodes-1;
    if (GNUNET_OK != GNUNET_CONFIGURATION_load (nodes[num_nodes-1].conf, filename))
    {
      FPRINTF (stderr, "Failed loading config `%s'\n", filename);
      return GNUNET_SYSERR;
    }
    return GNUNET_NO;
  }
  else
  {
    /* Continue iteration */
    return GNUNET_OK;
  }
}

/**
 * @brief Iterates over filenames in testbed directory.
 *
 * Implements #GNUNET_FileNameCallback
 *
 * Checks if the file is a directory for a testbed node
 * and counts the nodes.
 *
 * @param cls counter of nodes
 * @param filename full path of the file in testbed
 *
 * @return status whether to continue iteration
 */
static int
iter_testbed_path (void *cls,
                   const char *filename)
{
  unsigned index_node;

  GNUNET_assert (NULL != filename);
  if (1 == SSCANF (GNUNET_STRINGS_get_short_name (filename),
                  "%u",
                  &index_node))
  {
    if (-1 == GNUNET_DISK_directory_scan (filename,
                                          iter_check_config,
                                          NULL))
    {
      /* This is probably no directory for a testbed node
       * Go on with iteration */
      return GNUNET_OK;
    }
    return GNUNET_OK;
  }
  return GNUNET_OK;
}

/**
 * @brief Count the number of nodes running in the testbed
 *
 * @param path_testbed path to the testbed data
 *
 * @return number of running nodes
 */
static int
discover_testbed_nodes (const char *path_testbed)
{
  int num_dir_entries;

  num_dir_entries = GNUNET_DISK_directory_scan (path_testbed,
                                                iter_testbed_path,
                                                NULL);
  if (-1 == num_dir_entries)
  {
    FPRINTF (stderr,
            "Failure during scanning directory `%s'\n",
            path_testbed);
    return -1;
  }
  return 0;
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CONFIGURATION_Handle *c;

  c = (struct GNUNET_CONFIGURATION_Handle *) cfg;
  set_value = GNUNET_NO;
  if (NULL == csv_separator) csv_separator = "";
  if (NULL != args[0])
  {
    if (1 != SSCANF (args[0],
		     "%llu",
		     &set_val))
    {
      FPRINTF (stderr,
	       _("Invalid argument `%s'\n"),
	       args[0]);
      ret = 1;
      return;
    }
    set_value = GNUNET_YES;
  }
  if (NULL != remote_host)
  {
    if (0 == remote_port)
    {
      if (GNUNET_SYSERR ==
	  GNUNET_CONFIGURATION_get_value_number (cfg,
						 "statistics",
						 "PORT",
						 &remote_port))
      {
	FPRINTF (stderr,
		 _("A port is required to connect to host `%s'\n"),
		 remote_host);
	return;
      }
    }
    else if (65535 <= remote_port)
    {
      FPRINTF (stderr,
	       _("A port has to be between 1 and 65535 to connect to host `%s'\n"),
	       remote_host);
      return;
    }

    /* Manipulate configuration */
    GNUNET_CONFIGURATION_set_value_string (c,
					   "statistics",
					   "UNIXPATH",
					   "");
    GNUNET_CONFIGURATION_set_value_string (c,
					   "statistics",
					   "HOSTNAME",
					   remote_host);
    GNUNET_CONFIGURATION_set_value_number (c,
					   "statistics",
					   "PORT",
					   remote_port);
  }
  if (NULL == path_testbed)
  {
    values = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
    GNUNET_array_grow (nodes, num_nodes, 1);
    nodes[0].index_node = 0;
    nodes[0].conf = c;
    GNUNET_SCHEDULER_add_now (&main_task, &nodes[0].index_node);
  }
  else
  {
    if (GNUNET_YES == watch)
    {
      printf (_("Not able to watch testbed nodes (yet - feel free to implement)\n"));
      ret = 1;
      return;
    }
    values = GNUNET_CONTAINER_multihashmap_create (4, GNUNET_NO);
    if (-1 == discover_testbed_nodes (path_testbed))
    {
      return;
    }
    /* For each config/node collect statistics */
    for (unsigned i = 0; i < num_nodes; i++)
    {
      GNUNET_SCHEDULER_add_now (&main_task,
              &nodes[i].index_node);
    }
  }
}


/**
 * The main function to obtain statistics in GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('d',
                                 "csv-separator",
                                 "CSV_SEPARATOR",
                                 gettext_noop ("use as csv separator"),
                                 &csv_separator),

    GNUNET_GETOPT_option_string ('n',
                                 "name",
                                 "NAME",
                                 gettext_noop ("limit output to statistics for the given NAME"),
                                 &name),

    GNUNET_GETOPT_option_flag ('p',
                                  "persistent",
                                  gettext_noop ("make the value being set persistent"),
                                  &persistent),

    GNUNET_GETOPT_option_string ('s',
                                 "subsystem",
                                 "SUBSYSTEM",
                                 gettext_noop ("limit output to the given SUBSYSTEM"),
                                 &subsystem),

    GNUNET_GETOPT_option_filename ('t',
                                  "testbed",
                                  "TESTBED",
                                  gettext_noop ("path to the folder containing the testbed data"),
                                  &path_testbed),

    GNUNET_GETOPT_option_flag ('q',
                                  "quiet",
                                  gettext_noop ("just print the statistics value"),
                                  &quiet),

    GNUNET_GETOPT_option_flag ('w',
                                  "watch",
                                  gettext_noop ("watch value continuously"),
                                  &watch),

    GNUNET_GETOPT_option_string ('r',
                                 "remote",
                                 "REMOTE",
                                 gettext_noop ("connect to remote host"),
                                 &remote_host),

    GNUNET_GETOPT_option_ulong ('o',
                                    "port",
                                    "PORT",
                                    gettext_noop ("port for remote host"),
                                    &remote_port),

    GNUNET_GETOPT_OPTION_END
  };
  remote_port = 0;
  remote_host = NULL;
  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
				    &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc,
			     argv,
			     "gnunet-statistics [options [value]]",
			     gettext_noop
			     ("Print statistics about GNUnet operations."),
			     options,
			     &run,
			     NULL)) ? ret : 1;
  GNUNET_free_non_null (remote_host);
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-statistics.c */
