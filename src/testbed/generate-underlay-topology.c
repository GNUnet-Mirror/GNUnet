/*
      This file is part of GNUnet
      (C) 2008--2014 Christian Grothoff (and other contributing authors)

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
 * @file testbed/generate-underlay-topology.c
 * @brief Program to generate a database file containing given underlay topology
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "testbed_api_topology.h"

#define LOG(type, ...)                          \
  GNUNET_log (type, __VA_ARGS__)


#define LOG_ERROR(...)                          \
  LOG (GNUNET_ERROR_TYPE_ERROR, __VA_ARGS__)


/**
 * The topology to generate
 */
enum GNUNET_TESTBED_TopologyOption topology;

/**
 * The number of peers to include in the topology
 */
static int num_peers;

/**
 * program result
 */
static int exit_result;


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
static int
link_processor (void *cls,
                unsigned int A,
                unsigned int B,
                unsigned int bandwidth,
                unsigned int latency,
                unsigned int loss)
{
  GNUNET_break (0);
  return GNUNET_OK;
}


/**
 * Main run function.
 *
 * @param cls NULL
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param cfg the configuration file handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  const char *dbfile;
  const char *topology_string;
  unsigned int arg_uint1;
  unsigned int arg_uint2;
  const char *arg_str1;
  const char *value;
  unsigned int argc;

  argc = 0;
  if (NULL == args)
  {
    LOG_ERROR (_("Need atleast 2 arguments\n"));
    return;
  }
  if (NULL == (dbfile = args[argc++]))
  {
    LOG_ERROR (_("Database filename missing\n"));
    return;
  }
  if (NULL == (topology_string = args[argc++]))
  {
    LOG_ERROR (_("Topology string missing\n"));
    return;
  }
  if (GNUNET_YES != GNUNET_TESTBED_topology_get_ (&topology, topology_string))
  {
    LOG_ERROR (_("Invalid topology: %s\n"), topology_string);
    return;
  }
  /* parse for first TOPOOPT.  This can either be arg_uint1 or arg_str1 */
  switch (topology)
  {
  case GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI:
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING:
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD:
  case GNUNET_TESTBED_TOPOLOGY_SCALE_FREE:
    if (NULL == (value = args[argc++]))
    {
      LOG_ERROR (_("An argument is missing for given topology `%s'\n"),
                 topology_string);
      return;
    }
    if (-1 == SSCANF (value, "%u", &arg_uint1))
    {
      LOG_ERROR (_("Invalid argument `%s' given as topology argument\n"),
                 value);
      return;
    }
    break;
  case GNUNET_TESTBED_TOPOLOGY_FROM_FILE:
    if (NULL == (arg_str1 = args[argc++]))
    {
      LOG_ERROR (_("Filename argument missing for topology `%s'\n"),
                 topology_string);
      return;
    }
    break;
  default:
    GNUNET_assert (0);
  }
  /* parse for second TOPOOPT.  Only required for SCALE_FREE topology */
  switch (topology)
  {
  case GNUNET_TESTBED_TOPOLOGY_SCALE_FREE:
    if (NULL == (value = args[argc++]))
    {
      LOG_ERROR (_("Second argument for topology `%s' is missing\n"),
                 topology_string);
      return;
    }
    if (-1 == SSCANF (value, "%u", &arg_uint2))
    {
      LOG_ERROR (_("Invalid argument `%s'; expecting unsigned int\n"), value);
      return;
    }
    break;
  default:
    GNUNET_assert (0);
  }
  /* contruct topologies */
  switch (topology)
  {
  case GNUNET_TESTBED_TOPOLOGY_LINE:
  case GNUNET_TESTBED_TOPOLOGY_RING:
  case GNUNET_TESTBED_TOPOLOGY_CLIQUE:
  case GNUNET_TESTBED_TOPOLOGY_2D_TORUS:
    GNUNET_TESTBED_underlay_construct_ (num_peers, link_processor, NULL,
                                        topology);
    break;
  case GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI:
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING:
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD:
    GNUNET_TESTBED_underlay_construct_ (num_peers, link_processor, NULL,
                                        topology,
                                        arg_uint1);
    break;
  case GNUNET_TESTBED_TOPOLOGY_FROM_FILE:
    GNUNET_TESTBED_underlay_construct_ (num_peers, link_processor, NULL,
                                        topology,
                                        arg_str1);
    break;
  case GNUNET_TESTBED_TOPOLOGY_SCALE_FREE:
    GNUNET_TESTBED_underlay_construct_ (num_peers, link_processor, NULL,
                                        topology,
                                        arg_uint1,
                                        arg_uint2);
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Main
 */
int
main (int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption option[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;
  
  exit_result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-underlay-topology",
                          _("Generates SQLite3 database representing a given underlay topology.\n"
                            "Usage: gnunet-underlay-topology [OPTIONS] db-filename TOPO [TOPOOPTS]\n"
                            "The following options are available for TOPO followed by TOPOOPTS if applicable:\n"
                            "\t LINE\n"
                            "\t RING\n"
                            "\t RANDOM <num_rnd_links>\n"
                            "\t SMALL_WORLD <num_rnd_links>\n"
                            "\t SMALL_WORLD_RING <num_rnd_links>\n"
                            "\t CLIQUE\n"
                            "\t 2D_TORUS\n"
                            "\t SCALE_FREE <cap> <m>\n"
                            "\t FROM_FILE <filename>\n"
                            "TOPOOPTS:\n"
                            "\t num_rnd_links: The number of random links\n"
                            "\t cap: the maximum number of links a node can have\n"
                            "\t m: the number of links a node should have while joining the network\n"
                            "\t filename: the path of the file which contains topology information\n"
                            "NOTE: the format of the above file is descibed here: https://www.gnunet.org/content/topology-file-format\n"),
                          option, &run, NULL);
  if ((GNUNET_OK != ret) || (GNUNET_OK != exit_result))
    return 1;
  return 0;
}
