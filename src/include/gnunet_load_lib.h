/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_load_lib.h
 * @brief functions related to load calculations
 * @author Christian Grothoff
 */

#ifndef GNUNET_LOAD_LIB_H
#define GNUNET_LOAD_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_time_lib.h"

/**
 * Opaque load handle.
 */
struct GNUNET_LOAD_Value;

/**
 * Create a new load value.
 *
 * @return the new load value
 */
struct GNUNET_LOAD_Value *
GNUNET_LOAD_value_init (void);


/**
 * Free a load value.
 *
 * @param lv value to free
 */
#define GNUNET_LOAD_value_free(lv) GNUNET_free (lv)


/**
 * Get the current load.
 *
 * @param load load handle
 * @return zero for below-average load, otherwise
 *         number of std. devs we are above average;
 *         100 if the latest updates were so large
 *         that we could not do proper calculations
 */
double
GNUNET_LOAD_get_load (const struct GNUNET_LOAD_Value *load);


/**
 * Get the average value given to update so far.
 *
 * @param load load handle
 * @return zero if update was never called
 */
double
GNUNET_LOAD_get_average (const struct GNUNET_LOAD_Value *load);


/**
 * Update the current load.
 *
 * @param load to update
 * @param data latest measurement value (for example, delay)
 */
void
GNUNET_LOAD_update (struct GNUNET_LOAD_Value *load,
		    uint64_t data);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_LOAD_LIB_H */
#endif
/* end of gnunet_load_lib.h */
