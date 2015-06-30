/*
     This file is part of GNUnet.
     Copyright (C) 2009 -- 2013 Christian Grothoff (and other contributing authors)

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
 * @file util/speedup.c
 * @brief Interface for speedup routinues
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#ifndef SPEEDUP_H_
#define SPEEDUP_H_

/**
 * Start task that may speed up our system clock artificially
 *
 * @param cfg configuration to use
 * @return GNUNET_OK on success, GNUNET_SYSERR if the speedup was not configured
 */
int
GNUNET_SPEEDUP_start_ (const struct GNUNET_CONFIGURATION_Handle *cfg);

/**
 * Stop tasks that modify clock behavior.
 */
void
GNUNET_SPEEDUP_stop_ (void);

#endif  /* SPEEDUP_H_ */
