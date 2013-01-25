/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_topology.h
 * @brief header for intra library exported functions
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#ifndef TESTBED_API_TOPOLOGY_H
#define TESTBED_API_TOPOLOGY_H

/**
 * Returns the number of links that are required to generate a 2d torus for the
 * given number of peers. Also returns the arrangment (number of rows and the
 * length of each row)
 *
 * @param num_peers number of peers
 * @param rows number of rows in the 2d torus. Can be NULL.
 * @param rows_len the length of each row. This array will be allocated
 *          fresh. The caller should free it. Can be NULL.
 */
unsigned int
GNUNET_TESTBED_2dtorus_calc_links (unsigned int num_peers, unsigned int *rows,
                                   unsigned int **rows_len);


/**
 * Get a topology from a string input.
 *
 * @param topology where to write the retrieved topology
 * @param topology_string The string to attempt to
 *        get a configuration value from
 * @return GNUNET_YES if topology string matched a
 *         known topology, GNUNET_NO if not
 */
int
GNUNET_TESTBED_topology_get_ (enum GNUNET_TESTBED_TopologyOption *topology,
                              const char *topology_string);


/**
 * Returns the string corresponding to the given topology
 *
 * @param topology the topology
 * @return the string (freshly allocated) of given topology; NULL if topology cannot be
 *           expressed as a string
 */
char *
GNUNET_TESTBED_topology_to_str_ (enum GNUNET_TESTBED_TopologyOption topology);

#endif
/* end of  testbed_api_topology.h */
