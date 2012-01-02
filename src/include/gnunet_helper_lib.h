/*
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff

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
 * @file include/gnunet_helper_lib.h
 * @brief API for dealing with (SUID) helper processes that communicate via GNUNET_MessageHeaders on stdin/stdout
 * @author Philipp Toelke
 * @author Christian Grothoff
 */
#ifndef GNUNET_HELPER_LIB_H
#define GNUNET_HELPER_LIB_H

#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"

/**
 * The handle to a helper process.
 */
struct GNUNET_HELPER_Handle;


/**
 * @brief Starts a helper and begins reading from it
 *
 * @param binary_name name of the binary to run
 * @param binary_argv NULL-terminated list of arguments to give when starting the binary (this
 *                    argument must not be modified by the client for
 *                     the lifetime of the helper handle)
 * @param cb function to call if we get messages from the helper
 * @param cb_cls Closure for the callback
 * @return the new Handle, NULL on error
 */
struct GNUNET_HELPER_Handle *
GNUNET_HELPER_start (const char *binary_name,
		     char *const binary_argv[],
		     GNUNET_SERVER_MessageTokenizerCallback cb, void *cb_cls);


/**
 * @brief Kills the helper, closes the pipe and frees the handle
 *
 * @param h handle to helper to stop
 */
void
GNUNET_HELPER_stop (struct GNUNET_HELPER_Handle *h);


/**
 * Continuation function.
 * 
 * @param cls closure
 * @param result GNUNET_OK on success,
 *               GNUNET_NO if helper process died
 *               GNUNET_SYSERR during GNUNET_HELPER_stop
 */
typedef void (*GNUNET_HELPER_Continuation)(void *cls,
					   int result);


/**
 * Send an message to the helper.
 *
 * @param h helper to send message to
 * @param msg message to send
 * @param can_drop can the message be dropped if there is already one in the queue?
 * @param cont continuation to run once the message is out
 * @param cont_cls closure for 'cont'
 * @return GNUNET_YES if the message will be sent
 *         GNUNET_NO if the message was dropped
 */
int
GNUNET_HELPER_send (struct GNUNET_HELPER_Handle *h, 
		    const struct GNUNET_MessageHeader *msg,
		    int can_drop,
		    GNUNET_HELPER_Continuation cont,
		    void *cont_cls);


#endif /* end of include guard: GNUNET_HELPER_LIB_H */
