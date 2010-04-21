/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo-tool/gnunet-peerinfo.c
 * @brief Print information about other known peers.
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_program_lib.h"

static int no_resolve;

static int be_quiet;

static int get_self;

static struct GNUNET_SCHEDULER_Handle *sched;

static struct GNUNET_PEERINFO_Handle *peerinfo;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

struct PrintContext
{
  struct GNUNET_PeerIdentity peer;
  char **address_list;
  unsigned int num_addresses;
  uint32_t off;
  uint32_t trust;
};


static void
dump_pc (struct PrintContext *pc)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  unsigned int i;

  GNUNET_CRYPTO_hash_to_enc (&pc->peer.hashPubKey, &enc);
  printf (_("Peer `%s' with trust %8u\n"), 
	  (const char *) &enc,
	  pc->trust);
  for (i=0;i<pc->num_addresses;i++)
    {
      printf ("\t%s\n",
	      pc->address_list[i]);
      GNUNET_free (pc->address_list[i]);
    }
  printf ("\n");
  GNUNET_array_grow (pc->address_list,
		     pc->num_addresses,
		     0);
  GNUNET_free (pc);
}


/**
 * Function to call with a human-readable format of an address
 *
 * @param cls closure
 * @param address NULL on error, otherwise 0-terminated printable UTF-8 string
 */
static void
process_resolved_address (void *cls,
			  const char *address)
{
  struct PrintContext *pc = cls;

  if (address == NULL)
    {
      pc->off--;
      if (pc->off == 0)
	dump_pc (pc);
      return;
    }
  GNUNET_array_append (pc->address_list,
		       pc->num_addresses,
		       GNUNET_strdup (address));
}


/**
 * Iterator callback to go over all addresses.
 *
 * @param cls closure
 * @param tname name of the transport
 * @param expiration expiration time
 * @param addr the address
 * @param addrlen length of the address
 * @return GNUNET_OK to keep the address and continue
 */
static int
count_address (void *cls,
	       const char *tname,
	       struct GNUNET_TIME_Absolute expiration,
	       const void *addr, size_t addrlen)
{
  struct PrintContext *pc = cls;
  pc->off++;
  return GNUNET_OK;
}


/**
 * Iterator callback to go over all addresses.
 *
 * @param cls closure
 * @param tname name of the transport
 * @param expiration expiration time
 * @param addr the address
 * @param addrlen length of the address
 * @return GNUNET_OK to keep the address and continue
 */
static int
print_address (void *cls,
	       const char *tname,
	       struct GNUNET_TIME_Absolute expiration,
	       const void *addr, size_t addrlen)
{
  struct PrintContext *pc = cls;
  GNUNET_TRANSPORT_address_lookup (sched,
				   cfg,
				   addr,
				   addrlen,
				   no_resolve,
				   tname,
				   GNUNET_TIME_UNIT_SECONDS,
				   &process_resolved_address,
				   pc);
  return GNUNET_OK;
}


/**
 * Print information about the peer.
 * Currently prints the GNUNET_PeerIdentity, trust and the IP.
 * Could of course do more (e.g. resolve via DNS).
 */
static void
print_peer_info (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_HELLO_Message *hello, uint32_t trust)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  struct PrintContext *pc;

  if (peer == NULL)    
    {
      GNUNET_PEERINFO_disconnect (peerinfo);
      return;    
    }
  if (be_quiet)
    {
      GNUNET_CRYPTO_hash_to_enc (&peer->hashPubKey, &enc);
      printf ("%s\n", (const char *) &enc);
      return;
    }
  pc = GNUNET_malloc (sizeof (struct PrintContext));
  pc->peer = *peer;  
  pc->trust = trust;
  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &count_address, pc);
  if (0 == pc->off)
    {
      dump_pc (pc);
      return;
    }
  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &print_address, pc);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param s the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, 
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *priv;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  char *fn;

  sched = s;
  cfg = c;
  if (get_self != GNUNET_YES)
    {
      peerinfo = GNUNET_PEERINFO_connect (sched, cfg);
      if (peerinfo == NULL)
	{
	  fprintf (stderr,
		   _("Could not access PEERINFO service.  Exiting.\n"));
	  return;
	}
      (void) GNUNET_PEERINFO_iterate (peerinfo,
				      NULL,
				      0,
				      GNUNET_TIME_relative_multiply
				      (GNUNET_TIME_UNIT_SECONDS, 2),
				      &print_peer_info, NULL);
    }
  else
    {
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                   "GNUNETD",
                                                   "HOSTKEY", &fn))
	{
          fprintf (stderr, 
		   _("Could not find option `%s:%s' in configuration.\n"), 
		   "GNUNETD",
		   "HOSTKEYFILE");
	  return;
	}
      priv = GNUNET_CRYPTO_rsa_key_create_from_file (fn);
      if (priv == NULL)
        {
          fprintf (stderr, _("Loading hostkey from `%s' failed.\n"), fn);
          GNUNET_free (fn);
          return;
        }
      GNUNET_free (fn);
      GNUNET_CRYPTO_rsa_key_get_public (priv, &pub);
      GNUNET_CRYPTO_rsa_key_free (priv);
      GNUNET_CRYPTO_hash (&pub, sizeof (pub), &pid.hashPubKey);
      GNUNET_CRYPTO_hash_to_enc (&pid.hashPubKey, &enc);
      if (be_quiet)
        printf ("%s\n", (char *) &enc);
      else
        printf (_("I am peer `%s'.\n"), (const char *) &enc);
    }
}


/**
 * gnunet-peerinfo command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'n', "numeric", NULL,
   gettext_noop ("don't resolve host names"),
   0, &GNUNET_GETOPT_set_one, &no_resolve},
  {'q', "quiet", NULL,
   gettext_noop ("output only the identity strings"),
   0, &GNUNET_GETOPT_set_one, &be_quiet},
  {'s', "self", NULL,
   gettext_noop ("output our own identity only"),
   0, &GNUNET_GETOPT_set_one, &get_self},
  GNUNET_GETOPT_OPTION_END
};

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
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-peerinfo",
                              gettext_noop ("Print information about peers."),
                              options, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-peerinfo.c */
