/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_sd.h
 * @brief functions to calculate standard deviation
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#ifndef TESTBED_API_SD_H
#define TESTBED_API_SD_H


/**
 * Opaque handle for calculating SD
 */
struct SDHandle;


/**
 * Initialize standard deviation calculation handle
 *
 * @param max_cnt the maximum number of readings to keep
 * @return the initialized handle
 */
struct SDHandle *
GNUNET_TESTBED_SD_init_ (unsigned int max_cnt);


/**
 * Frees the memory allocated to the SD handle
 *
 * @param h the SD handle
 */
void
GNUNET_TESTBED_SD_destroy_ (struct SDHandle *h);


/**
 * Add a reading to SD
 *
 * @param h the SD handle
 * @param amount the reading value
 */
void
GNUNET_TESTBED_SD_add_data_ (struct SDHandle *h, unsigned int amount);


/**
 * Returns the factor by which the given amount differs from the standard deviation
 *
 * @param h the SDhandle
 * @param amount the value for which the deviation is returned
 * @param factor the factor by which the given amont differs
 * @return the deviation from the average; GNUNET_SYSERR if the deviation cannot
 *           be calculated OR 0 if the deviation is less than the average; a
 *           maximum of 4 is returned for deviations equal to or larger than 4
 */
int
GNUNET_TESTBED_SD_deviation_factor_ (struct SDHandle *h, unsigned int amount,
                                     int *factor);

#endif
/* end of testbed_api.h */
