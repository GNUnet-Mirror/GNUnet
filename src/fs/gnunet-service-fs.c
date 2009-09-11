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
 * @file statistics/gnunet-service-fs.c
 * @brief program that provides the file-sharing service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_core_service.h"
#include "gnunet_datastore_service.h"
#include "gnunet_util_lib.h"
#include "fs.h"

static struct GNUNET_DATASTORE_Handle *dsh;

/**
 * Handle INDEX_START-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_index_start (void *cls,
		    struct GNUNET_SERVER_Client *client,
		    const struct GNUNET_MessageHeader *message)
{
  const struct IndexStartMessage *ism;
  const char *fn;
  uint16_t msize;

  msize = ntohs(message->size);
  if ( (msize <= sizeof (struct IndexStartMessage)) ||
       ( ((const char *)message)[msize-1] != '\0') )
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client,
				  GNUNET_SYSERR);
      return;
    }
  ism = (const struct IndexStartMessage*) message;
  fn = (const char*) &ism[1];
  // FIXME: store fn, hash, check, respond to client, etc.
}


/**
 * Handle INDEX_LIST_GET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_index_list_get (void *cls,
		       struct GNUNET_SERVER_Client *client,
		       const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVER_TransmitContext *tc;
  struct IndexInfoMessage *iim;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE];
  size_t slen;
  char *fn;
  struct GNUNET_MessageHeader *msg;

  tc = GNUNET_SERVER_transmit_context_create (client);
  iim = (struct IndexInfoMessage*) buf;
  msg = &iim->header;
  while (0)
    {
      iim->reserved = 0;
      // FIXME: read actual list of indexed files...
      // iim->file_id = id;
      fn = "FIXME";
      slen = strlen (fn) + 1;
      if (slen + sizeof (struct IndexInfoMessage) > 
	  GNUNET_SERVER_MAX_MESSAGE_SIZE)
	{
	  GNUNET_break (0);
	  break;
	}
      memcpy (&iim[1], fn, slen);
      GNUNET_SERVER_transmit_context_append
	(tc,
	 &msg[1],
	 sizeof (struct IndexInfoMessage) 
	 - sizeof (struct GNUNET_MessageHeader) + slen,
	 GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_ENTRY);
    }
  GNUNET_SERVER_transmit_context_append (tc,
					 NULL, 0,
					 GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_END);
  GNUNET_SERVER_transmit_context_run (tc,
				      GNUNET_TIME_UNIT_MINUTES);
}


/**
 * Handle UNINDEX-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_unindex (void *cls,
		struct GNUNET_SERVER_Client *client,
		const struct GNUNET_MessageHeader *message)
{
  const struct UnindexMessage *um;
  struct GNUNET_SERVER_TransmitContext *tc;
  
  um = (const struct UnindexMessage*) message;
  // fixme: process!
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_SERVER_transmit_context_append (tc,
					 NULL, 0,
					 GNUNET_MESSAGE_TYPE_FS_UNINDEX_OK);
  GNUNET_SERVER_transmit_context_run (tc,
				      GNUNET_TIME_UNIT_MINUTES);
}


/**
 * FIXME
 *
 * @param cls closure
 * @param ok GNUNET_OK if DS is ready, GNUNET_SYSERR on timeout
 */
typedef void (*RequestFunction)(void *cls,
				int ok);


/**
 * Run the next DS request in our
 * queue, we're done with the current one.
 */
static void
next_ds_request ()
{
}


/**
 * FIXME.
 */
static void
queue_ds_request (struct GNUNET_TIME_Relative deadline,
		  RequestFunction fun,
		  void *fun_cls)
{
}



/**
 * Closure for processing START_SEARCH
 * messages from a client.
 */
struct LocalGetContext
{
  /**
   * Client that initiated the search.
   */
  struct GNUNET_SERVER_Client *client;
  
};


/**
 * Handle START_SEARCH-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_start_search (void *cls,
		     struct GNUNET_SERVER_Client *client,
		     const struct GNUNET_MessageHeader *message)
{
  const struct SearchMessage *sm;
  struct LocalGetContext *lgc;

  sm = (const struct SearchMessage*) message;
  GNUNET_SERVER_client_keep (client);
  lgc = GNUNET_malloc (sizeof (struct LocalGetContext));
  lgc->client = client;
  lgc->x = y;
  queue_ds_request (&transmit_local_get,
		    lgc);
}


static void 
transmit_local_get (void *cls,
		    int ok)
{
  struct LocalGetContext *lgc = cls;
  // FIXME: search locally

  GNUNET_assert (GNUNET_OK == ok);
  GNUNET_SERVER_receive_done (lgc->client,
			      GNUNET_OK);
  
  // FIXME: if not found, initiate P2P search  

  // FIXME: once done with "client" handle:
  GNUNET_SERVER_client_drop (lgc->client); 
}


/**
 * List of handlers for the messages understood by this
 * service.
 */
static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&handle_index_start, NULL, 
   GNUNET_MESSAGE_TYPE_FS_INDEX_START, 0},
  {&handle_index_list_get, NULL, 
   GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_GET, sizeof(struct GNUNET_MessageHeader) },
  {&handle_unindex, NULL, GNUNET_MESSAGE_TYPE_FS_UNINDEX, 
   sizeof (struct UnindexMessage) },
  {&handle_start_search, NULL, GNUNET_MESSAGE_TYPE_FS_START_SEARCH, 
   sizeof (struct SearchMessage) },
  {NULL, NULL, 0, 0}
};


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_DATASTORE_disconnect (dsh,
			       GNUNET_NO);
  dsh = NULL;
}


/**
 * Process fs requests.
 *
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  dsh = GNUNET_DATASTORE_connect (cfg,
				  sched);
  if (NULL == dsh)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to datastore service.\n"));
      return;
    }
  GNUNET_SERVER_add_handlers (server, handlers);
  // FIXME: also handle P2P messages!

  GNUNET_SCHEDULER_add_delayed (sched,
				GNUNET_YES,
				GNUNET_SCHEDULER_PRIORITY_IDLE,
				GNUNET_SCHEDULER_NO_TASK,
				GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task,
				NULL);
}


/**
 * The main function for the fs service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "fs", &run, NULL, NULL, NULL)) ? 0 : 1;
}

/* end of gnunet-service-fs.c */
