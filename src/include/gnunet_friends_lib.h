/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff

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
 * @file include/gnunet_friends_lib.h
 * @brief library to read and write the FRIENDS file
 * @author Christian Grothoff
 */
#ifndef GNUNET_FRIENDS_LIB_H
#define GNUNET_FRIENDS_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"


/**
 * Signature of a function called on each friend found.
 *
 * @param cls closure
 * @param friend_id peer identity of the friend
 */
typedef void (*GNUNET_FRIENDS_Callback)(void *cls,
                                        const struct GNUNET_PeerIdentity *friend_id);


/**
 * Parse the FRIENDS file.
 *
 * @param cfg our configuration
 * @param cb function to call on each friend found
 * @param cb_cls closure for @a cb
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on parsing errors
 */
int
GNUNET_FRIENDS_parse (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      GNUNET_FRIENDS_Callback cb,
                      void *cb_cls);


/**
 * Handle for writing a friends file.
 */
struct GNUNET_FRIENDS_Writer;


/**
 * Start writing a fresh FRIENDS file.  Will make a backup of the
 * old one.
 *
 * @param cfg configuration to use.
 * @return NULL on error
 */
struct GNUNET_FRIENDS_Writer *
GNUNET_FRIENDS_write_start (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Finish writing out the friends file.
 *
 * @param w write handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_FRIENDS_write_stop (struct GNUNET_FRIENDS_Writer *w);


/**
 * Add a friend to the friends file.
 *
 * @param w write handle
 * @param friend_id friend to add
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_FRIENDS_write (struct GNUNET_FRIENDS_Writer *w,
                      const struct GNUNET_PeerIdentity *friend_id);


					  #if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
