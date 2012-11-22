/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs_stream.c
 * @brief non-anonymous file-transfer
 * @author Christian Grothoff
 *
 * TODO:
 * - add statistics
 * - limit # concurrent clients, timeout for read
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_stream_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_indexing.h"
#include "gnunet-service-fs_stream.h"

/**
 * Information we keep around for each active streaming client.
 */
struct StreamClient
{
  /**
   * DLL
   */ 
  struct StreamClient *next;

  /**
   * DLL
   */ 
  struct StreamClient *prev;

  /**
   * Socket for communication.
   */ 
  struct GNUNET_STREAM_Socket *socket;

  /**
   * Handle for active read operation, or NULL.
   */ 
  struct GNUNET_STREAM_IOReadHandle *rh;

  /**
   * Handle for active write operation, or NULL.
   */ 
  struct GNUNET_STREAM_IOWriteHandle *wh;
  
  /**
   * Tokenizer for requests.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;
  
  /**
   * Current active request to the datastore, if we have one pending.
   */
  struct GNUNET_DATASTORE_QueueEntry *qe;

  /**
   * Size of the last write that was initiated.
   */ 
  size_t reply_size;

};


/**
 * Query from one peer, asking the other for CHK-data.
 */
struct StreamQueryMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_FS_STREAM_QUERY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Block type must be DBLOCK or IBLOCK.
   */
  uint32_t type;

  /**
   * Query hash from CHK (hash of encrypted block).
   */
  struct GNUNET_HashCode query;

};


/**
 * Reply to a StreamQueryMessage.
 */
struct StreamReplyMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_FS_STREAM_REPLY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Block type must be DBLOCK or IBLOCK.
   */
  uint32_t type;

  /**
   * Expiration time for the block.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /* followed by the encrypted block */

};


/**
 * Listen socket for incoming requests.
 */
static struct GNUNET_STREAM_ListenSocket *listen_socket;

/**
 * Head of DLL of stream clients.
 */ 
static struct StreamClient *sc_head;

/**
 * Tail of DLL of stream clients.
 */ 
static struct StreamClient *sc_tail;


/**
 * We're done with a particular client, clean up.
 *
 * @param sc client to clean up
 */
static void
terminate_stream (struct StreamClient *sc)
{
  if (NULL != sc->rh)
    GNUNET_STREAM_io_read_cancel (sc->rh);
  if (NULL != sc->wh)
    GNUNET_STREAM_io_write_cancel (sc->wh);
  if (NULL != sc->qe)
    GNUNET_DATASTORE_cancel (sc->qe);
  GNUNET_SERVER_mst_destroy (sc->mst);
  GNUNET_STREAM_close (sc->socket);
  GNUNET_CONTAINER_DLL_remove (sc_head,
			       sc_tail,
			       sc);
  GNUNET_free (sc);
}


/**
 * Functions of this signature are called whenever data is available from the
 * stream.
 *
 * @param cls the closure from GNUNET_STREAM_read
 * @param status the status of the stream at the time this function is called
 * @param data traffic from the other side
 * @param size the number of bytes available in data read; will be 0 on timeout 
 * @return number of bytes of processed from 'data' (any data remaining should be
 *         given to the next time the read processor is called).
 */
static size_t 
process_request (void *cls,
		 enum GNUNET_STREAM_Status status,
		 const void *data,
		 size_t size);


/**
 * We're done handling a request from a client, read the next one.
 *
 * @param sc client to continue reading requests from
 */
static void
continue_reading (struct StreamClient *sc)
{
  int ret;

  ret = 
    GNUNET_SERVER_mst_receive (sc->mst,
			       NULL,
			       NULL, 0,
			       GNUNET_NO, GNUNET_YES);
  if (GNUNET_NO == ret)
    return; 
  sc->rh = GNUNET_STREAM_read (sc->socket,
			       GNUNET_TIME_UNIT_FOREVER_REL,
			       &process_request,
			       sc);      
}


/**
 * Functions of this signature are called whenever data is available from the
 * stream.
 *
 * @param cls the closure from GNUNET_STREAM_read
 * @param status the status of the stream at the time this function is called
 * @param data traffic from the other side
 * @param size the number of bytes available in data read; will be 0 on timeout 
 * @return number of bytes of processed from 'data' (any data remaining should be
 *         given to the next time the read processor is called).
 */
static size_t 
process_request (void *cls,
		 enum GNUNET_STREAM_Status status,
		 const void *data,
		 size_t size)
{
  struct StreamClient *sc = cls;
  int ret;

  sc->rh = NULL;
  switch (status)
  {
  case GNUNET_STREAM_OK:
    ret = 
      GNUNET_SERVER_mst_receive (sc->mst,
				 NULL,
				 data, size,
				 GNUNET_NO, GNUNET_YES);
    if (GNUNET_NO == ret)
      return size; /* more messages in MST */
    if (GNUNET_SYSERR == ret)
    {
      GNUNET_break_op (0);
      terminate_stream (sc);
      return size;
    }
    break;
  case GNUNET_STREAM_TIMEOUT:
  case GNUNET_STREAM_SHUTDOWN:
  case GNUNET_STREAM_SYSERR:
  case GNUNET_STREAM_BROKEN:
    terminate_stream (sc);
    return size;
  default:
    GNUNET_break (0);
    return size;
  }
  continue_reading (sc);
  return size;
}


/**
 * Sending a reply was completed, continue processing.
 *
 * @param cls closure with the struct StreamClient which sent the query
 */
static void
write_continuation (void *cls,
		    enum GNUNET_STREAM_Status status,
		    size_t size)
{
  struct StreamClient *sc = cls;
  
  sc->wh = NULL;
  if ( (GNUNET_STREAM_OK == status) &&
       (size == sc->reply_size) )
    continue_reading (sc);
  else
    terminate_stream (sc);    
}


/**
 * Process a datum that was stored in the datastore.
 *
 * @param cls closure with the struct StreamClient which sent the query
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void 
handle_datastore_reply (void *cls,
			const struct GNUNET_HashCode * key,
			size_t size, const void *data,
			enum GNUNET_BLOCK_Type type,
			uint32_t priority,
			uint32_t anonymity,
			struct GNUNET_TIME_Absolute
			expiration, uint64_t uid)
{
  struct StreamClient *sc = cls;
  size_t msize = size + sizeof (struct StreamReplyMessage);
  char buf[msize] GNUNET_ALIGN;
  struct StreamReplyMessage *srm = (struct StreamReplyMessage *) buf;

  sc->qe = NULL;
  if (GNUNET_BLOCK_TYPE_FS_ONDEMAND == type)
  {
    if (GNUNET_OK !=
	GNUNET_FS_handle_on_demand_block (key,
					  size, data, type,
					  priority, anonymity,
					  expiration, uid,
					  &handle_datastore_reply,
					  sc))
    {
      continue_reading (sc);
    }
    return;
  }
  if (msize > GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    continue_reading (sc);
    return;
  }
  srm->header.size = htons ((uint16_t) msize);
  srm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_STREAM_REPLY);
  srm->type = htonl (type);
  srm->expiration = GNUNET_TIME_absolute_hton (expiration);
  memcpy (&srm[1], data, size);
  sc->reply_size = msize;
  sc->wh = GNUNET_STREAM_write (sc->socket,
				buf, msize,
				GNUNET_TIME_UNIT_FOREVER_REL,
				&write_continuation,
				sc);
  if (NULL == sc->wh)
  {
    terminate_stream (sc);
    return;
  }
}


/**
 * Functions with this signature are called whenever a
 * complete message is received.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure with the 'struct StreamClient'
 * @param client identification of the client, NULL
 * @param message the actual message
 * @return GNUNET_OK on success, GNUNET_SYSERR to stop further processing
 */
static int
request_cb (void *cls,
	    void *client,
	    const struct GNUNET_MessageHeader *message)
{
  struct StreamClient *sc = cls;
  const struct StreamQueryMessage *sqm;

  switch (ntohs (message->type))
  {
  case GNUNET_MESSAGE_TYPE_FS_STREAM_QUERY:
    if (sizeof (struct StreamQueryMessage) != 
	ntohs (message->size))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    sqm = (const struct StreamQueryMessage *) message;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Received query for `%s' via stream\n",
		GNUNET_h2s (&sqm->query));
    sc->qe = GNUNET_DATASTORE_get_key (GSF_dsh,
				       0,
				       &sqm->query,
				       ntohl (sqm->type),
				       0 /* FIXME: priority */, 
				       GSF_datastore_queue_size,
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       &handle_datastore_reply, sc);
    if (NULL == sc->qe)
      continue_reading (sc);
    return GNUNET_OK;
  default:
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Functions of this type are called upon new stream connection from other peers
 * or upon binding error which happen when the app_port given in
 * GNUNET_STREAM_listen() is already taken.
 *
 * @param cls the closure from GNUNET_STREAM_listen
 * @param socket the socket representing the stream; NULL on binding error
 * @param initiator the identity of the peer who wants to establish a stream
 *            with us; NULL on binding error
 * @return GNUNET_OK to keep the socket open, GNUNET_SYSERR to close the
 *             stream (the socket will be invalid after the call)
 */
static int 
accept_cb (void *cls,
	   struct GNUNET_STREAM_Socket *socket,
	   const struct GNUNET_PeerIdentity *initiator)
{
  struct StreamClient *sc;

  if (NULL == socket)
    return GNUNET_SYSERR;
  sc = GNUNET_malloc (sizeof (struct StreamClient));
  sc->socket = socket;
  sc->mst = GNUNET_SERVER_mst_create (&request_cb,
				      sc);
  sc->rh = GNUNET_STREAM_read (sc->socket,
			       GNUNET_TIME_UNIT_FOREVER_REL,
			       &process_request,
			       sc);
  GNUNET_CONTAINER_DLL_insert (sc_head,
			       sc_tail,
			       sc);
  return GNUNET_OK;
}


/**
 * Initialize subsystem for non-anonymous file-sharing.
 */
void
GSF_stream_start ()
{
  listen_socket = GNUNET_STREAM_listen (GSF_cfg,
					GNUNET_APPLICATION_TYPE_FS_BLOCK_TRANSFER,
					&accept_cb, NULL,
					GNUNET_STREAM_OPTION_END);
}


/**
 * Shutdown subsystem for non-anonymous file-sharing.
 */
void
GSF_stream_stop ()
{
  struct StreamClient *sc;

  while (NULL != (sc = sc_head))
    terminate_stream (sc);
  if (NULL != listen_socket)
  {
    GNUNET_STREAM_listen_close (listen_socket);
    listen_socket = NULL;
  }
}

/* end of gnunet-service-fs_stream.c */
