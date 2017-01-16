
/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file cadet/gnunet-service-cadet-new_connection.c
 * @brief
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-cadet-new_channel.h"
#include "gnunet-service-cadet-new_paths.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_connection.h"


/**
 * Low-level connection to a destination.
 */
struct CadetConnection
{
  /**
   * To which peer does this connection go?
   */
  struct CadetPeer *destination;

  /**
   * Path we are using to our destination.
   */
  struct CadetPeerPath *path;

  /**
   * Function to call once we are ready to transmit.
   */
  GNUNET_SCHEDULER_TaskCallback ready_cb;

  /**
   * Closure for @e ready_cb.
   */
  void *ready_cb_cls;

  /**
   * Offset of our @e destination in @e path.
   */
  unsigned int off;

};


/**
 * Is the given connection currently ready for transmission?
 *
 * @param cc connection to transmit on
 * @return #GNUNET_YES if we could transmit
 */
int
GCC_is_ready (struct CadetConnection *cc)
{
  GNUNET_break (0);
  return GNUNET_NO;
}


/**
 * Destroy a connection.
 *
 * @param cc connection to destroy
 */
void
GCC_destroy (struct CadetConnection *cc)
{
  GCPP_del_connection (cc->path,
                       cc->off,
                       cc);
  GNUNET_assert (0); // FIXME: incomplete implementation!
  GNUNET_free (cc);
}


/**
 * Create a connection to @a destination via @a path and
 * notify @a cb whenever we are ready for more data.
 *
 * @param destination where to go
 * @param path which path to take (may not be the full path)
 * @param ready_cb function to call when ready to transmit
 * @param ready_cb_cls closure for @a cb
 */
struct CadetConnection *
GCC_create (struct CadetPeer *destination,
            struct CadetPeerPath *path,
            GNUNET_SCHEDULER_TaskCallback ready_cb,
            void *ready_cb_cls)
{
  struct CadetConnection *cc;
  unsigned int off;

  off = GCPP_find_peer (path,
                        destination);
  GNUNET_assert (UINT_MAX > off);

  GNUNET_assert (0); // fIXME: unfinished

  cc = GNUNET_new (struct CadetConnection);
  cc->path = path;
  cc->off = off;
  GCPP_add_connection (path,
                       off,
                       cc);
  for (unsigned int i=0;i<off;i++)
  {
    // FIXME: remember existence of this connection with
    // ALL peers on the path!
    // (and remove on destruction of connection!)
  }
  return cc;
}


/**
 * Transmit message @a msg via connection @a cc.  Must only be called
 * (once) after the connection has signalled that it is ready via the
 * `ready_cb`.  Clients can also use #GCC_is_ready() to check if the
 * connection is right now ready for transmission.
 *
 * @param cc connection identification
 * @param msg message to transmit
 */
void
GCC_transmit (struct CadetConnection *cc,
              const struct GNUNET_MessageHeader *msg)
{
  GNUNET_assert (0); // FIXME
}


/**
 * Obtain the path used by this connection.
 *
 * @param cc connection
 * @return path to @a cc
 */
struct CadetPeerPath *
GCC_get_path (struct CadetConnection *cc)
{
  return cc->path;
}


/**
 * Obtain unique ID for the connection.
 *
 * @param cc connection.
 * @return unique number of the connection
 */
const struct GNUNET_CADET_ConnectionTunnelIdentifier *
GCC_get_id (struct CadetConnection *cc)
{
  GNUNET_assert (0); // FIXME
  return NULL;
}


/**
 * Log connection info.
 *
 * @param cc connection
 * @param level Debug level to use.
 */
void
GCC_debug (struct CadetConnection *cc,
           enum GNUNET_ErrorType level)
{
}
