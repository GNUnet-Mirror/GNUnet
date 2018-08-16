/*
     This file is part of GNUnet.
     Copyright (C) 2001-2018 GNUnet e.V.

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
 * @file include/gnunet_zklaim_lib.h
 * @brief ZKlaim functions for GNUnet
 *
 * @author Martin Schanzenbach
 *
 * @defgroup zklaim ZKlaim library: Zero-Knowledge Credentials
 *
 */
#ifndef GNUNET_ZKLAIM_LIB_H
#define GNUNET_ZKLAIM_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"

/**
 * @brief type for ZKlaim context
 */
struct GNUNET_ZKLAIM_Context;

/**
 * @brief type for ZKlaim payload
 */
struct GNUNET_ZKLAIM_Payload;


/**
 * @ingroup zklaim
 * Create a new ZKlaim context. Caller must free return value.
 * TODO: parameters: keys etc.
 *
 * @return fresh context; free using #GNUNET_free
 */
struct GNUNET_ZKLAIM_Context *
GNUNET_ZKLAIM_context_create (void);

/**
 * @ingroup zklaim
 * Create a payload.
 * TODO: parameters, attributes etc.
 *
 * @return fresh payload; free using #GNUNET_free
 */
void
GNUNET_ZKLAIM_payload_create (void);

/**
 * @ingroup zklaim
 * Create a payload.
 * TODO: parameters, attributes etc.
 *
 * @return GNUNET_OK is successful
 */
int
GNUNET_ZKLAIM_context_add_payload (struct GNUNET_ZKLAIM_Context *ctx,
                                   struct GNUNET_ZKLAIM_Payload* pl);


/**
 * @ingroup zklaim
 * Create a payload.
 * TODO: parameters, attributes etc.
 *
 * @return size needed for serialized context, -1 on error
 */
ssize_t
GNUNET_ZKLAIM_context_serialize_get_size (struct GNUNET_ZKLAIM_Context *ctx);


/**
 * @ingroup zklaim
 * Create a payload.
 * TODO: parameters, attributes etc.
 *
 */
void
GNUNET_ZKLAIM_context_serialize (struct GNUNET_ZKLAIM_Context *ctx,
                                 char* buf);


/**
 * @ingroup zklaim
 * Create a payload.
 * TODO: parameters, attributes etc.
 *
 * @return fresh payload; free using #GNUNET_free
 */
char *
GNUNET_ZKLAIM_context_to_string (struct GNUNET_ZKLAIM_Context *ctx);




#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_ZKLAIM_LIB_H */
#endif
/* end of gnunet_zklaim_lib.h */
