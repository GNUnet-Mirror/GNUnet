/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-core-list-connections.c
 * @brief Print information about other known _connected_ peers.
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_core_service.h"
#include "gnunet_program_lib.h"

#define VERBOSE 0
static int no_resolve;

#if VERBOSE
static unsigned int peer_count;
#endif

static const struct GNUNET_CONFIGURATION_Handle *cfg;

struct AddressStringList
{
  /**
   * Pointer to previous element.
   */
  struct AddressStringList *prev;

  /**
   * Pointer to next element.
   */
  struct AddressStringList *next;

  /**
   * Address as string.
   */
  char *address_string;
};

struct PrintContext
{
  struct GNUNET_PeerIdentity peer;
  struct AddressStringList *address_list_head;
  struct AddressStringList *address_list_tail;
};


static void
dump_pc (struct PrintContext *pc)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  struct AddressStringList *address;

  GNUNET_CRYPTO_hash_to_enc (&pc->peer.hashPubKey, &enc);
  printf (_("Peer `%s'\n"), (const char *) &enc);
  while (NULL != (address = pc->address_list_head))
  {
    printf ("\t%s\n", address->address_string);
    GNUNET_free (address->address_string);
    GNUNET_CONTAINER_DLL_remove (pc->address_list_head, pc->address_list_tail,
                                 address);
    GNUNET_free (address);
  }

  printf ("\n");

  GNUNET_free (pc);
}


/**
 * Function to call with a human-readable format of an address
 *
 * @param cls closure
 * @param peer peer this update is about
 * @param address NULL on error, otherwise 0-terminated printable UTF-8 string
 */
static void
process_resolved_address (void *cls, const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_HELLO_Address *address)
{
  struct PrintContext *pc = cls;

//  struct AddressStringList *new_address;

  if (address == NULL)
  {
    dump_pc (pc);
    return;
  }

  /* This does exactly the same as gnunet-transport -i ! */
  /*
   * new_address = GNUNET_malloc (sizeof (struct AddressStringList));
   * #if VERBOSE
   * FPRINTF (stderr, "Received address %s\n", address);
   * #endif
   *
   * new_address->address_string = GNUNET_strdup ("FIXME");
   * GNUNET_CONTAINER_DLL_insert (pc->address_list_head, pc->address_list_tail,
   * new_address);
   */
}


/**
 * Callback for retrieving a list of connected peers.
 */
static void
connected_peer_callback (void *cls, const struct GNUNET_PeerIdentity *peer,
                         const struct GNUNET_ATS_Information *atsi,
                         unsigned int atsi_count)
{
  struct PrintContext *pc;

  if (peer != NULL)             /* Not yet finished */
  {
#if VERBOSE
    FPRINTF (stderr, "Learned about peer %s\n", GNUNET_i2s (peer));
    peer_count++;
#endif
    pc = GNUNET_malloc (sizeof (struct PrintContext));
    pc->peer = *peer;
    GNUNET_TRANSPORT_peer_get_active_addresses (cfg, peer, GNUNET_YES,
                                                GNUNET_TIME_UNIT_MINUTES,
                                                &process_resolved_address, pc);
  }
#if VERBOSE
  else
  {
    FPRINTF (stderr, "Counted %u total connected peers.\n", peer_count);
  }
#endif
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{

  cfg = c;
  if (args[0] != NULL)
  {
    FPRINTF (stderr, _("Invalid command line argument `%s'\n"), args[0]);
    return;
  }

  GNUNET_CORE_iterate_peers (cfg, &connected_peer_callback, NULL);

}


/**
 * The main function to obtain peer information.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'n', "numeric", NULL,
     gettext_noop ("don't resolve host names"),
     0, &GNUNET_GETOPT_set_one, &no_resolve},
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-list-connections",
                              gettext_noop
                              ("Print information about connected peers."),
                              options, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-core-list-connections.c */
