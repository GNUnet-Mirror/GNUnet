/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/gnunet-consensus.c
 * @brief 
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_consensus_service.h"




/**
 * Called when a new element was received from another peer, or an error occured.
 *
 * May deliver duplicate values.
 *
 * Elements given to a consensus operation by the local peer are NOT given
 * to this callback.
 *
 * @param cls closure
 * @param element new element, NULL on error
 * @return GNUNET_OK if the valid is well-formed and should be added to the consensus,
 *         GNUNET_SYSERR if the element should be ignored and not be propagated
 */
static int
cb (void *cls,
    struct GNUNET_CONSENSUS_Element *element)
{
  return 0;
}



static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static struct GNUNET_PeerIdentity pid;
  static struct GNUNET_HashCode sid;
  
  GNUNET_CONSENSUS_create (cfg,
			   1, &pid,
			   &sid,
			   &cb, NULL);
  
}


int
main (int argc, char **argv)
{
   static const struct GNUNET_GETOPT_CommandLineOption options[] = {
        GNUNET_GETOPT_OPTION_END
   };
  GNUNET_PROGRAM_run (argc, argv, "gnunet-consensus",
		      "help",
		      options, &run, NULL);
  return 0;
}
