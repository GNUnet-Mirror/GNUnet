/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file identity/gnunet-identity.c
 * @brief IDENTITY management command line tool
 * @author Christian Grothoff
 *
 * Todo:
 * - add options to get default egos
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"

/**
 * Handle to IDENTITY service.
 */
static struct GNUNET_IDENTITY_Handle *sh;

/**
 * Was "list" specified?
 */
static int list;

/**
 * Was "monitor" specified?
 */
static int monitor;

/**
 * -C option
 */
static char *create_ego;

/**
 * -D option
 */
static char *delete_ego;

/**
 * -s option.
 */
static char *set_ego;

/**
 * -S option.
 */
static char *set_subsystem;

/**
 * Operation handle for set operation.
 */
static struct GNUNET_IDENTITY_Operation *set_op;

/**
 * Handle for create operation.
 */
static struct GNUNET_IDENTITY_Operation *create_op;

/**
 * Handle for delete operation.
 */
static struct GNUNET_IDENTITY_Operation *delete_op;


/**
 * Task run on shutdown.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != set_op)
  {
    GNUNET_IDENTITY_cancel (set_op);
    set_op = NULL;
  }
  if (NULL != create_op)
  {
    GNUNET_IDENTITY_cancel (create_op);
    create_op = NULL;
  }
  if (NULL != delete_op)
  {
    GNUNET_IDENTITY_cancel (delete_op);
    delete_op = NULL;
  }
  GNUNET_IDENTITY_disconnect (sh);
  sh = NULL;
}


/**
 * Test if we are finished yet.
 */
static void
test_finished ()
{
  if ( (NULL == create_op) &&
       (NULL == delete_op) &&
       (NULL == set_op) &&
       (NULL == set_ego) &&
       (! list) &&
       (! monitor) )
    GNUNET_SCHEDULER_shutdown ();
}


/**
 * Deletion operation finished.
 *
 * @param cls pointer to operation handle
 * @param emsg NULL on success, otherwise an error message
 */
static void
delete_finished (void *cls,
		 const char *emsg)
{
  struct GNUNET_IDENTITY_Operation **op = cls;

  *op = NULL;
  if (NULL != emsg)
    fprintf (stderr,
	     "%s\n",
	     gettext (emsg));
  test_finished ();
}


/**
 * Creation operation finished.
 *
 * @param cls pointer to operation handle
 * @param emsg error message, NULL on success
 */
static void
create_finished (void *cls,
		 const char *emsg)
{
  struct GNUNET_IDENTITY_Operation **op = cls;

  *op = NULL;
  if (NULL != emsg)
    fprintf (stderr,
	     _("Failed to create ego: %s\n"),
	     emsg);
  test_finished ();
}


/**
 * Function called by #GNUNET_IDENTITY_set up on completion.
 *
 * @param cls NULL
 * @param emsg error message (NULL on success)
 */
static void
set_done (void *cls,
	  const char *emsg)
{
  set_op = NULL;
  if (NULL != emsg)
    fprintf (stderr,
	     _("Failed to set default ego: %s\n"),
	     emsg);
  test_finished ();
}


/**
 * If listing is enabled, prints information about the egos.
 *
 * This function is initially called for all egos and then again
 * whenever a ego's identifier changes or if it is deleted.  At the
 * end of the initial pass over all egos, the function is once called
 * with 'NULL' for 'ego'. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with 'GNUNET_IDENTITY_create' or 'GNUNET_IDENTITY_get',
 * this function is only called ONCE, and 'NULL' being passed in
 * 'ego' does indicate an error (i.e. name is taken or no default
 * value is known).  If 'ego' is non-NULL and if '*ctx'
 * is set in those callbacks, the value WILL be passed to a subsequent
 * call to the identity callback of 'GNUNET_IDENTITY_connect' (if
 * that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) ego but the NEW identifier.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the 'identifier'.  In this case,
 * the 'ego' is henceforth invalid (and the 'ctx' should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param identifier identifier assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
*/
static void
print_ego (void *cls,
	   struct GNUNET_IDENTITY_Ego *ego,
	   void **ctx,
	   const char *identifier)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pk;
  char *s;

  if ( (NULL != set_ego) &&
       (NULL != ego) &&
       (NULL != identifier) &&
       (0 == strcmp (identifier,
		     set_ego)) )
    {
      set_op = GNUNET_IDENTITY_set (sh,
				    set_subsystem,
				    ego,
				    &set_done,
				    NULL);
      GNUNET_free (set_subsystem);
      set_subsystem = NULL;
      GNUNET_free (set_ego);
      set_ego = NULL;
    }
  if ( (NULL == ego) &&
       (NULL != set_ego) )
  {
    fprintf (stderr,
	     "Could not set ego to `%s' for subsystem `%s', ego not known\n",
	     set_ego,
	     set_subsystem);
    GNUNET_free (set_subsystem);
    set_subsystem = NULL;
    GNUNET_free (set_ego);
    set_ego = NULL;
  }
  if ( (NULL == ego) && (! monitor) )
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (! (list | monitor))
    return;
  if (NULL == ego)
    return;
  GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
  s = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
  if ( (monitor) || (NULL != identifier) )
    fprintf (stdout, "%s - %s\n", identifier, s);
  GNUNET_free (s);
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
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if ( (NULL == set_subsystem) ^
       (NULL == set_ego) )
  {
    fprintf (stderr,
	     "Options -e and -s must always be specified together\n");
    return;
  }
  sh = GNUNET_IDENTITY_connect (cfg, &print_ego, NULL);
  if (NULL != delete_ego)
    delete_op = GNUNET_IDENTITY_delete (sh,
					delete_ego,
					&delete_finished,
					&delete_op);
  if (NULL != create_ego)
    create_op = GNUNET_IDENTITY_create (sh,
					create_ego,
					&create_finished,
					&create_op);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task, NULL);
  test_finished ();
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
  int res;

  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'C', "create", "NAME",
     gettext_noop ("create ego NAME"),
     1, &GNUNET_GETOPT_set_string, &create_ego},
    {'D', "delete", "NAME",
     gettext_noop ("delete ego NAME "),
     1, &GNUNET_GETOPT_set_string, &delete_ego},
    {'d', "display", NULL,
     gettext_noop ("display all egos"),
     0, &GNUNET_GETOPT_set_one, &list},
    {'e', "ego", "NAME",
     gettext_noop ("set default identity to EGO for a subsystem SUBSYSTEM (use together with -s)"),
     1, &GNUNET_GETOPT_set_string, &set_ego},
    {'m', "monitor", NULL,
     gettext_noop ("run in monitor mode egos"),
     0, &GNUNET_GETOPT_set_one, &monitor},
    {'s', "set", "SUBSYSYSTEM",
     gettext_noop ("set default identity to EGO for a subsystem SUBSYSTEM (use together with -e)"),
     1, &GNUNET_GETOPT_set_string, &set_subsystem},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-identity",
			    gettext_noop ("Maintain egos"),
			    options, &run,
			    NULL);
  GNUNET_free ((void *) argv);

  if (GNUNET_OK != res)
    return 1;
  return 0;
}

/* end of gnunet-identity.c */
