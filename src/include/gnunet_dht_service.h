/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_dht_service.h
 * @brief API to the DHT service
 * @author Christian Grothoff
 */

#ifndef GNUNET_DHT_SERVICE_H
#define GNUNET_DHT_SERVICE_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

struct GNUNET_DHT_GetHandle;

  /**
   * Perform an asynchronous GET operation on the DHT identified.
   *
   * @param type expected type of the response object
   * @param key the key to look up
   * @param callback function to call on each result
   * @param closure extra argument to callback
   * @return handle to stop the async get
   */
  struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start) (struct GNUNET_DHT_Handle *h,
		unsigned int type,
                                             const GNUNET_HashCode * key,
                                             GNUNET_DHT_ResultProcessor callback,
                                             void *callback_cls);

  /**
   * Stop async DHT-get.  Frees associated resources.
   */
  int GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle * record);

  /**
   * Perform a PUT operation on the DHT identified by 'table' storing
   * a binding of 'key' to 'value'.  The peer does not have to be part
   * of the table (if so, we will attempt to locate a peer that is!)
   *
   * @param key the key to store under
   */
  int GNUNET_DHT_put (struct GNUNET_DHT_Handle *h, 
const GNUNET_HashCode * key,
              unsigned int type, unsigned int size, const char *data);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif /* DHT_SERVICE_API_H */
