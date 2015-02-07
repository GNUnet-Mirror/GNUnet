/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_regex_service.h
 * @brief access regex service to advertise capabilities via regex and discover
 *        respective peers using matching strings
 * @author Maximilian Szengel
 * @author Christian Grothoff
 */
#ifndef GNUNET_REGEX_SERVICE_H
#define GNUNET_REGEX_SERVICE_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Constant for how many bytes the initial string regex should have.
 */
#define GNUNET_REGEX_INITIAL_BYTES 24


/**
 * Handle to store cached data about a regex announce.
 */
struct GNUNET_REGEX_Announcement;

/**
 * Handle to store data about a regex search.
 */
struct GNUNET_REGEX_Search;


/**
 * Announce this peer under the given regular expression.  Does
 * not free resources, must call #GNUNET_REGEX_announce_cancel for
 * that.
 *
 * @param cfg configuration to use
 * @param regex Regular expression to announce.
 * @param refresh_delay after what delay should the announcement be repeated?
 * @param compression How many characters per edge can we squeeze?
 * @return Handle to reuse o free cached resources.
 *         Must be freed by calling #GNUNET_REGEX_announce_cancel.
 */
struct GNUNET_REGEX_Announcement *
GNUNET_REGEX_announce (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const char *regex,
		       struct GNUNET_TIME_Relative refresh_delay,
                       uint16_t compression);


/**
 * Stop announcing the regex specified by the given handle.
 *
 * @param a handle returned by a previous #GNUNET_REGEX_announce call.
 */
void
GNUNET_REGEX_announce_cancel (struct GNUNET_REGEX_Announcement *a);


/**
 * Search callback function, invoked for every result that was found.
 *
 * @param cls Closure provided in #GNUNET_REGEX_search.
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of @a get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the @a put_path.
 */
typedef void (*GNUNET_REGEX_Found)(void *cls,
                                   const struct GNUNET_PeerIdentity *id,
                                   const struct GNUNET_PeerIdentity *get_path,
                                   unsigned int get_path_length,
                                   const struct GNUNET_PeerIdentity *put_path,
                                   unsigned int put_path_length);


/**
 * Search for a peer offering a regex matching certain string in the DHT.
 * The search runs until #GNUNET_REGEX_search_cancel is called, even if results
 * are returned.
 *
 * @param cfg configuration to use
 * @param string String to match against the regexes in the DHT.
 * @param callback Callback for found peers.
 * @param callback_cls Closure for @c callback.
 * @return Handle to stop search and free resources.
 *         Must be freed by calling #GNUNET_REGEX_search_cancel.
 */
struct GNUNET_REGEX_Search *
GNUNET_REGEX_search (const struct GNUNET_CONFIGURATION_Handle *cfg,
		     const char *string,
                     GNUNET_REGEX_Found callback,
                     void *callback_cls);


/**
 * Stop search and free all data used by a #GNUNET_REGEX_search call.
 *
 * @param s Handle returned by a previous #GNUNET_REGEX_search call.
 */
void
GNUNET_REGEX_search_cancel (struct GNUNET_REGEX_Search *s);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_regex_service.h */
#endif
