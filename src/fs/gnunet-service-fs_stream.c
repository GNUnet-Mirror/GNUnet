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
 * - limit # concurrent clients, timeout for read
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_stream_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet-service-fs.h"
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
   * Size of the last write that was initiated.
   */ 
  size_t reply_size;

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
		 size_t size)
{
  struct StreamClient *sc = cls;

  sc->rh = NULL;
  switch (status)
  {
  case GNUNET_STREAM_OK:
    // fixme: handle request...
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
  sc->rh = GNUNET_STREAM_read (sc->socket,
			       GNUNET_TIME_UNIT_FOREVER_REL,
			       &process_request,
			       sc);
  return size;
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
