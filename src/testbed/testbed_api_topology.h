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


/**
 * Functions of this type are called to process underlay link
 *
 * @param cls closure
 * @param A offset of first peer
 * @param B offset of second peer
 * @param bandwidth the bandwidth of the link in bytes per second
 * @param latency the latency of link in milliseconds
 * @param loss the percentage of messages dropped on the link
 * @return GNUNET_OK to continue processing; GNUNET_SYSERR to abort
 */
typedef int (*underlay_link_processor) (void *cls,
                                        unsigned int A,
                                        unsigned int B,
                                        unsigned int bandwidth,
                                        unsigned int latency,
                                        unsigned int loss);


/**
 * Function to construct an underlay topology
 *
 * @param num_peers the number of peers for which the topology should be
 *          generated
 * @param proc the underlay link processor callback.  Will be called for each
 *          underlay link generated unless a previous call to this callback
 *          returned GNUNET_SYSERR.  Cannot be NULL.
 * @param cls closure for proc
 * @param ... variable arguments denoting the topology and its parameters.  They
 *          should start with the type of topology to generate followed by their
 *          options.  These arguments should *always* end with
 *          GNUNET_TESTBED_TOPOLOGY_OPTION_END option
 * @return GNUNET_OK if underlay link generation is successful; GNUNET_SYSERR
 *          upon error in generating the underlay or if any calls to the
 *          underlay link processor returned GNUNET_SYSERR
 */
int
GNUNET_TESTBED_underlay_construct_ (int num_peers,
                                    underlay_link_processor proc,
                                    void *cls,
                                    ...);

#endif
/* end of  testbed_api_topology.h */
