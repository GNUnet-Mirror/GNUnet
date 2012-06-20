/*
     This file is part of GNUnet.
     (C) 2004, 2009 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo/test_peerinfo_api.c
 * @brief testcase for peerinfo_api.c
 * @author Christian Grothoff
 *
 * TODO:
 * - test merging of HELLOs (add same peer twice...)
 */
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_testing_lib-new.h"
#include "peerinfo.h"

static struct GNUNET_PEERINFO_IteratorContext *ic;

static struct GNUNET_PEERINFO_Handle *h;

static unsigned int retries;

static int global_ret;


static int
check_it (void *cls, const struct GNUNET_HELLO_Address *address,
          struct GNUNET_TIME_Absolute expiration)
{
  unsigned int *agc = cls;

  if (address != NULL)
  {
    GNUNET_assert (0 == strcmp ("peerinfotest", address->transport_name));
    GNUNET_assert (0 ==
                   strncmp ("Address", address->address,
                            address->address_length));
    (*agc) -= (1 << (address->address_length - 1));
  }
  return GNUNET_OK;
}


static size_t
address_generator (void *cls, size_t max, void *buf)
{
  size_t *agc = cls;
  size_t ret;
  struct GNUNET_HELLO_Address address;

  if (0 == *agc)
    return 0;
  memset (&address.peer, 0, sizeof (struct GNUNET_PeerIdentity));
  address.address = "Address";
  address.transport_name = "peerinfotest";
  address.address_length = *agc;
  ret =
      GNUNET_HELLO_add_address (&address,
                                GNUNET_TIME_relative_to_absolute
                                (GNUNET_TIME_UNIT_HOURS), buf, max);
  (*agc)--;
  return ret;
}


static void
add_peer ()
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_HELLO_Message *h2;
  size_t agc;

  agc = 2;
  memset (&pkey, 32, sizeof (pkey));
  GNUNET_CRYPTO_hash (&pkey, sizeof (pkey), &pid.hashPubKey);
  h2 = GNUNET_HELLO_create (&pkey, &address_generator, &agc);
  GNUNET_PEERINFO_add_peer (h, h2, NULL, NULL);
  GNUNET_free (h2);

}


static void
process (void *cls, const struct GNUNET_PeerIdentity *peer,
         const struct GNUNET_HELLO_Message *hello, const char *err_msg)
{
  unsigned int agc;

  if (err_msg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Error in communication with PEERINFO service\n"));
  }

  if (peer == NULL)
  {
    ic = NULL;
    if ((3 == global_ret) && (retries < 50))
    {
      /* try again */
      retries++;
      add_peer ();
      ic = GNUNET_PEERINFO_iterate (h, NULL,
                                    GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 15), &process,
                                    cls);
      return;
    }
    GNUNET_assert (peer == NULL);
    GNUNET_assert (2 == global_ret);
    GNUNET_PEERINFO_disconnect (h);
    h = NULL;
    global_ret = 0;
    return;
  }
  if (hello != NULL)
  {
    GNUNET_assert (3 == global_ret);
    agc = 3;
    GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &check_it, &agc);
    GNUNET_assert (agc == 0);
    global_ret = 2;
  }
}


static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  h = GNUNET_PEERINFO_connect (cfg);
  GNUNET_assert (NULL != h);
  add_peer ();
  ic = GNUNET_PEERINFO_iterate (h, NULL,
                                GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_SECONDS, 15), &process, cls);
}


int
main (int argc, char *argv[])
{
  global_ret = 3;
  if (0 != GNUNET_TESTING_service_run ("test-gnunet-peerinfo",
				       "peerinfo",
				       "test_peerinfo_api_data.conf",
				       &run, NULL))
    return 1;
  return global_ret;
}

/* end of test_peerinfo_api.c */
