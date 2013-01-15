/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file sysmon/test_glibtop_process.c
 * @brief a brief test for glibtop
 * @author Matthias Wachs
 */

#include "platform.h"

#include <glibtop.h>
#include <glibtop/netlist.h>
#include <glibtop/netload.h>

static int ret;


static void
print_netlist ()
{
  glibtop_netlist netlist;
  glibtop_netload netload;
  int i;
  char ** tmp;
  uint8_t *address;
  uint8_t *netmask;

  tmp = glibtop_get_netlist (&netlist);

  printf ("Network information: %u devices\n", netlist.number);
  for (i = 0; i < netlist.number; ++i)
  {
    printf ("Device %i: %s\n", i, tmp[i]);
    glibtop_get_netload (&netload, tmp[i]);
    address = (uint8_t *) &netload.address;
    netmask = (uint8_t *) &netload.subnet;
    printf ("\t%-50s: %u.%u.%u.%u\n", "IPv4 subnet", netmask[0], netmask[1], netmask[2],netmask[3]);
    printf ("\t%-50s: %u.%u.%u.%u\n", "IPv4 address", address[0], address[1], address[2],address[3]);

    printf ("\t%-50s: %llu\n", "bytes in", (long long unsigned int) netload.bytes_in);
    printf ("\t%-50s: %llu\n", "bytes out", (long long unsigned int) netload.bytes_out);
    printf ("\t%-50s: %llu\n", "packets total", (long long unsigned int) netload.packets_total);
  }
}

/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  if (NULL == glibtop_init())
  {
    fprintf (stderr, "Could not init gliptop!\n");
    return 1;
  }

  /* Network information */
  print_netlist ();

  glibtop_close();
  return ret;
}

/* end of ttest_glibtop_process.c */

