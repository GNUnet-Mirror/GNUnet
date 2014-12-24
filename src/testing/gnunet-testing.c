/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/gnunet-testing.c
 * @brief tool to use testing functionality from cmd line
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"


#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "gnunet-testing", __VA_ARGS__)


/**
 * Final status code.
 */
static int ret;

/**
 * Filename of the hostkey file we should write,
 * null if we should not write a hostkey file.
 */
static char *create_hostkey;

/**
 * Non-zero if we should create config files.
 */
static int create_cfg;

/**
 * Number of config files to create.
 */
static unsigned int create_no;

/**
 * Filename of the config template to be written.
 */
static char *create_cfg_template;

/**
 * Service we are supposed to run.
 */
static char *run_service_name;

/**
 * File handle to STDIN, for reading restart/quit commands.
 */
static struct GNUNET_DISK_FileHandle *fh;

/**
 * Temporary filename, used with '-r' to write the configuration to.
 */
static char *tmpfilename;

/**
 * Task identifier of the task that waits for stdin.
 */
static struct GNUNET_SCHEDULER_Task * tid;

/**
 * Peer started for '-r'.
 */
static struct GNUNET_TESTING_Peer *my_peer;



static int
create_unique_cfgs (const char * template, const unsigned int no)
{
  struct GNUNET_TESTING_System *system;
  int fail;
  unsigned int cur;
  char *cur_file;
  struct GNUNET_CONFIGURATION_Handle *cfg_new;
  struct GNUNET_CONFIGURATION_Handle *cfg_tmpl;

  if (GNUNET_NO == GNUNET_DISK_file_test(template))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Configuration template `%s': file not found\n", create_cfg_template);
    return 1;
  }
  cfg_tmpl = GNUNET_CONFIGURATION_create();

  /* load template */
  if ((create_cfg_template != NULL) && (GNUNET_OK != GNUNET_CONFIGURATION_load(cfg_tmpl, create_cfg_template)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not load template `%s'\n", create_cfg_template);
    GNUNET_CONFIGURATION_destroy (cfg_tmpl);

    return 1;
  }
  /* load defaults */
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (cfg_tmpl,  NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not load template `%s'\n", create_cfg_template);
    GNUNET_CONFIGURATION_destroy (cfg_tmpl);
    return 1;
  }

  fail = GNUNET_NO;
  system = GNUNET_TESTING_system_create ("testing", NULL /* controller */,
                                         NULL, NULL);
  for (cur = 0; cur < no; cur++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating configuration no. %u \n", cur);
    if (create_cfg_template != NULL)
      GNUNET_asprintf (&cur_file,"%04u-%s",cur, create_cfg_template);
    else
      GNUNET_asprintf (&cur_file,"%04u%s",cur, ".conf");

    cfg_new = GNUNET_CONFIGURATION_dup (cfg_tmpl);
    if (GNUNET_OK !=
	GNUNET_TESTING_configuration_create (system, cfg_new))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not create another configuration\n");
      GNUNET_CONFIGURATION_destroy (cfg_new);
      fail = GNUNET_YES;
      break;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Writing configuration no. %u to file `%s' \n", cur, cur_file);
    if (GNUNET_OK != GNUNET_CONFIGURATION_write(cfg_new, cur_file))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to write configuration no. %u \n", cur);
      fail = GNUNET_YES;
    }
    GNUNET_CONFIGURATION_destroy (cfg_new);
    GNUNET_free (cur_file);
    if (GNUNET_YES == fail)
      break;
  }
  GNUNET_CONFIGURATION_destroy(cfg_tmpl);
  GNUNET_TESTING_system_destroy (system, GNUNET_NO);
  if (GNUNET_YES == fail)
    return 1;
  return 0;
}


static int
create_hostkeys (const unsigned int no)
{
  struct GNUNET_TESTING_System *system;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_DISK_FileHandle *fd;
  struct GNUNET_CRYPTO_EddsaPrivateKey *pk;

  system = GNUNET_TESTING_system_create ("testing", NULL, NULL, NULL);
  pk = GNUNET_TESTING_hostkey_get (system, create_no, &id);
  if (NULL == pk)
  {
    fprintf (stderr, _("Could not extract hostkey %u (offset too large?)\n"), create_no);
    GNUNET_TESTING_system_destroy (system, GNUNET_YES);
    return 1;
  }
  (void) GNUNET_DISK_directory_create_for_file (create_hostkey);
  fd = GNUNET_DISK_file_open (create_hostkey,
			      GNUNET_DISK_OPEN_READWRITE |
			      GNUNET_DISK_OPEN_CREATE,
			      GNUNET_DISK_PERM_USER_READ |
			      GNUNET_DISK_PERM_USER_WRITE);
  GNUNET_assert (fd != NULL);
  ret = GNUNET_DISK_file_write (fd, pk,
				sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey));
  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fd));
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
		   "Wrote hostkey to file: `%s'\n", create_hostkey);
  GNUNET_free (pk);
  GNUNET_TESTING_system_destroy (system, GNUNET_YES);
  return 0;
}


/**
 * Cleanup called by signal handlers and when stdin is closed.
 * Removes the temporary file.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
cleanup (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != tmpfilename)
  {
    if (0 != UNLINK (tmpfilename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", tmpfilename);
  }
  if (NULL != tid)
  {
    GNUNET_SCHEDULER_cancel (tid);
    tid = NULL;
  }
  if (NULL != fh)
  {
    GNUNET_DISK_file_close (fh);
    fh = NULL;
  }
}


/**
 * Called whenever we can read stdin non-blocking
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
stdin_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c;

  tid = NULL;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  GNUNET_assert (0 != (GNUNET_SCHEDULER_REASON_READ_READY & tc->reason));
  c = getchar ();
  switch (c)
  {
  case EOF:
  case 'q':
    GNUNET_SCHEDULER_shutdown ();
    return;
  case 'r':
    if (GNUNET_OK != GNUNET_TESTING_peer_stop (my_peer))
      LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to stop the peer\n");
    if (GNUNET_OK != GNUNET_TESTING_peer_start (my_peer))
      LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to start the peer\n");
    printf ("restarted\n");
    fflush (stdout);
    break;
  case '\n':
  case '\r':
    /* ignore whitespace */
    break;
  default:
    fprintf (stderr, _("Unknown command, use 'q' to quit or 'r' to restart peer\n"));
    break;
  }
  tid = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, fh,
                                        &stdin_cb, NULL);
}


/**
 * Main function called by the testing library.
 * Executed inside a running scheduler.
 *
 * @param cls unused
 * @param cfg configuration of the peer that was started
 * @param peer handle to the peer
 */
static void
testing_main (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
              struct GNUNET_TESTING_Peer *peer)
{
  my_peer = peer;
  if (NULL == (tmpfilename = GNUNET_DISK_mktemp ("gnunet-testing")))
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_write ((struct GNUNET_CONFIGURATION_Handle *) cfg,
                                  tmpfilename))
  {
    GNUNET_break (0);
    return;
  }
  printf("ok\n%s\n", tmpfilename);
  fflush(stdout);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, NULL);
  fh = GNUNET_DISK_get_handle_from_native (stdin);
  tid = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, fh,
                                        &stdin_cb, NULL);
}



/**
 * Main function that will be running without scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run_no_scheduler (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (NULL != run_service_name)
  {
    ret = GNUNET_TESTING_service_run ("gnunet_service_test", run_service_name,
                                      cfgfile, &testing_main, NULL);
    return;
  }

  if (GNUNET_YES == create_cfg)
  {
    if (create_no > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Creating %u configuration files based on template `%s'\n", create_no, create_cfg_template);
      ret = create_unique_cfgs (create_cfg_template, create_no);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Missing arguments! \n");
      ret = 1;
    }
  }
  if (NULL != create_hostkey)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Extracting hostkey %u\n", create_no);
    ret = create_hostkeys (create_no);
  }
  GNUNET_free_non_null (create_cfg_template);
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'C', "cfg", NULL, gettext_noop ("create unique configuration files"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &create_cfg},
    {'k', "key", "FILENAME", gettext_noop ("extract hostkey file from pre-computed hostkey list"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &create_hostkey},
    {'n', "number", "NUMBER", gettext_noop ("number of unique configuration files to create, or number of the hostkey to extract"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &create_no},
    {'t', "template", "FILENAME", gettext_noop ("configuration template"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &create_cfg_template},
    {'r', "run", "SERVICE", gettext_noop ("run the given service, wait on stdin for 'r' (restart) or 'q' (quit)"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &run_service_name},
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  /* Run without scheduler, because we may want to call
   * GNUNET_TESTING_service_run, which starts the scheduler on its own.
   * Furthermore, the other functionality currently does not require the scheduler, too,
   * but beware when extending gnunet-testing. */
  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run2 (argc, argv, "gnunet-testing",
			     gettext_noop ("Command line tool to access the testing library"), options, &run_no_scheduler,
			     NULL, GNUNET_YES)) ? ret : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-testing.c */
