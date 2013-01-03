/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/gnunet-consensus.c
 * @brief 
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_consensus_service.h"



/**
 * Handle to the consensus service
 */
static struct GNUNET_CONSENSUS_Handle *consensus;
/**
 * Session id
 */
static char *session_id_str;

/**
 * File handle to STDIN
 */
static struct GNUNET_DISK_FileHandle *stdin_fh;

/**
 * Task for reading from stdin
 */
static GNUNET_SCHEDULER_TaskIdentifier stdin_tid = GNUNET_SCHEDULER_NO_TASK;


static void
stdin_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Called when a conclusion was successful.
 *
 * @param cls
 * @param num_peers_in_consensus
 * @param peers_in_consensus
 */
static void
conclude_cb (void *cls, 
             unsigned int consensus_group_count,
             const struct GNUNET_CONSENSUS_Group *groups)
{
  printf("reached conclusion\n");
  GNUNET_SCHEDULER_shutdown ();
}


static void
insert_done_cb (void *cls,
                int success)
{
  struct GNUNET_CONSENSUS_Element *element = cls;

  GNUNET_free (element);
  if (GNUNET_YES != success)
  {
    printf ("insert failed\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == stdin_tid);
  stdin_tid = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, stdin_fh,
					      &stdin_cb, NULL);    
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
  char buf[1024];
  char *ret;
  struct GNUNET_CONSENSUS_Element *element;

  stdin_tid = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return; /* we're done here */
  ret = fgets (buf, 1024, stdin);
  if (NULL == ret)
  {
    if (feof (stdin))
    {
      printf ("concluding ...\n");
      GNUNET_CONSENSUS_conclude (consensus, GNUNET_TIME_UNIT_FOREVER_REL, 0, conclude_cb, NULL);
    }
    return;
  }

  printf("read: %s", buf);

  element = GNUNET_malloc (sizeof (struct GNUNET_CONSENSUS_Element) + strlen(buf) + 1);
  element->type = 0;
  element->size = strlen(buf) + 1;
  element->data = &element[1];
  strcpy ((char *) &element[1], buf);
  GNUNET_CONSENSUS_insert (consensus, element, &insert_done_cb, element); 
}


/**
 * Called when a new element was received from another peer, or an error occured.
 *
 * May deliver duplicate values.
 *
 * Elements given to a consensus operation by the local peer are NOT given
 * to this callback.
 *
 * @param cls closure
 * @param element new element, NULL on error
 * @return GNUNET_OK if the valid is well-formed and should be added to the consensus,
 *         GNUNET_SYSERR if the element should be ignored and not be propagated
 */
static int
cb (void *cls,
    struct GNUNET_CONSENSUS_Element *element)
{
  if (NULL == element)
  {
    printf("error receiving from consensus\n");
    GNUNET_SCHEDULER_shutdown ();
    return GNUNET_NO;
  }
  printf("got element\n");
  return GNUNET_YES;
}


/**
 * Function run on shutdown to clean up.
 *
 * @param cls the statistics handle
 * @param tc scheduler context
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "shutting down\n");
  if (NULL != consensus)
  {
    GNUNET_CONSENSUS_destroy (consensus);
    consensus = NULL;
  }
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_HashCode sid;
  struct GNUNET_PeerIdentity *pids;
  int count;
  int i;

  if (NULL == session_id_str)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "no session id given (missing -s/--session-id)\n");
    return;
  }

  GNUNET_CRYPTO_hash (session_id_str, strlen (session_id_str), &sid);

  for (count = 0; NULL != args[count]; count++);
 
  if (0 != count)
  { 
    pids = GNUNET_malloc (count * sizeof (struct GNUNET_PeerIdentity));
  }
  else
  {
    pids = NULL;
  }

  for (i = 0; i < count; i++)
  {
    int ret;
    ret = GNUNET_CRYPTO_hash_from_string (args[i], &pids[i].hashPubKey);
    if (GNUNET_OK != ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "peer identity '%s' is malformed\n", args[i]);
      return;
    }
  }

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task, NULL);
  
  consensus = 
      GNUNET_CONSENSUS_create (cfg,
                               count, pids,
                               &sid,
                               &cb, NULL);

  stdin_fh = GNUNET_DISK_get_handle_from_native (stdin);
  stdin_tid = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, stdin_fh,
                                        &stdin_cb, NULL);
}


int
main (int argc, char **argv)
{
   static const struct GNUNET_GETOPT_CommandLineOption options[] = {
      { 's', "session-id", "ID",
        gettext_noop ("session identifier"),
        GNUNET_YES, &GNUNET_GETOPT_set_string, &session_id_str },
        GNUNET_GETOPT_OPTION_END
   };
  GNUNET_PROGRAM_run (argc, argv, "gnunet-consensus",
		      "help",
		      options, &run, NULL);
  return 0;
}
