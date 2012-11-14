/*
     This file is part of GNUnet.
     (C) 2010, 2011, 2012 Christian Grothoff

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
 * @file mesh/gnunet-daemon-regexprofiler.c
 * @brief daemon that uses mesh to announce a regular expression. Used in
 * conjunction with gnunet-regex-profiler to announce regexes on serveral peers
 * without the need to explicitly connect to the mesh service running on the
 * peer from within the profiler.
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "gnunet_mesh_service.h"
#include "gnunet_statistics_service.h"

/**
 * Return value from 'main'.
 */
static int global_ret;

/**
 * Configuration we use.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats_handle;

/**
 * Peer's mesh handle.
 */
struct GNUNET_MESH_Handle *mesh_handle;

/**
 * Peer's mesh tunnel handle.
 */
struct GNUNET_MESH_Tunnel *mesh_tunnel_handle;

/**
 * Maximal path compression length for regex announcing.
 */
static unsigned long long max_path_compression;

/**
 * Name of the file containing policies that this peer should announce. One
 * policy per line.
 */
static char * policy_filename;

/**
 * Prefix to add before every regex we're announcing.
 */
static char * regex_prefix;

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shutting down\n");

  if (NULL != mesh_tunnel_handle)
  {
    GNUNET_MESH_tunnel_destroy (mesh_tunnel_handle);
    mesh_tunnel_handle = NULL;
  }

  if (NULL != mesh_handle)
  {
    GNUNET_MESH_disconnect (mesh_handle);
    mesh_handle = NULL;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shut down\n");
}


/**
 * Announce the given regular expression using Mesh and the path compression
 * length read from config.
 *
 * @param regex regular expression to announce on this peer's mesh.
 */
static void
announce_regex (const char * regex)
{
  if (NULL == regex || 0 == strlen (regex))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot announce empty regex\n");
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Announcing regex: %s\n", regex);
  GNUNET_STATISTICS_update (stats_handle, "# regexes announced", 1, GNUNET_NO);
  GNUNET_MESH_announce_regex (mesh_handle, regex, (unsigned int)max_path_compression);
}


/**
 * Load regular expressions from filename into 'rxes' array. Array needs to be freed.
 *
 * @param filename filename of the file containing the regexes, one per line.
 * @param rx string with the union of all regular expressions.
 * @return number of regular expressions read from filename and in rxes array.
 */
static unsigned int
load_regexes (const char *filename, char **rx)
{
  char *data;
  char *buf;
  uint64_t filesize;
  unsigned int offset;
  unsigned int rx_cnt;

  if (GNUNET_YES != GNUNET_DISK_file_test (policy_filename))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not find policy file %s\n", policy_filename);
    return 0;
  }
  if (GNUNET_OK != GNUNET_DISK_file_size (policy_filename, &filesize, GNUNET_YES, GNUNET_YES))
    filesize = 0;
  if (0 == filesize)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Policy file %s is empty.\n", policy_filename);
    return 0;
  }
  data = GNUNET_malloc (filesize);
  if (filesize != GNUNET_DISK_fn_read (policy_filename, data, filesize))
  {
    GNUNET_free (data);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not read policy file %s.\n",
                policy_filename);
    return 0;
  }
  buf = data;
  offset = 0;
  rx_cnt = 0;
  while (offset < (filesize - 1))
  {
    offset++;
    if (((data[offset] == '\n')) && (buf != &data[offset]))
    {
      data[offset] = '|';
      buf = &data[offset + 1];
      rx_cnt++;
    }
    else if ((data[offset] == '\n') || (data[offset] == '\0'))
      buf = &data[offset + 1];
  }
  data[offset] = '\0';
  *rx = data;

  return rx_cnt;
}


/**
 * @brief Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg_ configuration
 */
static void
run (void *cls, char *const *args GNUNET_UNUSED,
     const char *cfgfile GNUNET_UNUSED,
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  char *regex = NULL;
  char *rx_with_pfx;
  const GNUNET_MESH_ApplicationType app = (GNUNET_MESH_ApplicationType)0;
  static struct GNUNET_MESH_MessageHandler handlers[] = {
    {NULL, 0, 0}
  };

  cfg = cfg_;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "REGEXPROFILER", "MAX_PATH_COMPRESSION",
                                             &max_path_compression))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "regexprofiler", "max_path_compression");
    global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "REGEXPROFILER", "POLICY_FILE",
                                               &policy_filename))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "regexprofiler", "policy_file");
    global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "REGEXPROFILER", "REGEX_PREFIX",
                                             &regex_prefix))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "regexprofiler", "regex_prefix");
    global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  stats_handle = GNUNET_STATISTICS_create ("regexprofiler", cfg);

  mesh_handle =
    GNUNET_MESH_connect (cfg, NULL, NULL, NULL, handlers, &app);

  if (NULL == mesh_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not acquire mesh handle. Exiting.\n");
    global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* Read regexes from policy files */
  if (0 == load_regexes (policy_filename, &regex))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Policy file %s contains no policies. Exiting.\n",
                policy_filename);
    global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* Announcing regexes from policy_filename */
  GNUNET_asprintf (&rx_with_pfx, "%s(%s)", regex_prefix, regex);
  announce_regex (rx_with_pfx);
  GNUNET_free (rx_with_pfx);
  GNUNET_free (regex);

  /* Scheduled the task to clean up when shutdown is called */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * The main function of the regexprofiler service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "regexprofiler",
                              gettext_noop
                              ("Daemon to announce regular expressions for the peer using mesh."),
                              options, &run, NULL)) ? global_ret : 1;
}


#ifdef LINUX
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor)) GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif


/* end of gnunet-daemon-regexprofiler.c */
