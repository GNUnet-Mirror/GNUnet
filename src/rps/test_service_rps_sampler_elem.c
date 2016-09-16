/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file rps/test_service_rps_sampler_elem.c
 * @brief testcase for gnunet-service-rps_sampler_elem.c
 */
#include <platform.h>
#include "gnunet_util_lib.h"
#include "gnunet-service-rps_sampler_elem.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }
#define CHECK(c) { if (! (c)) ABORT(); }


static int
check ()
{
  struct GNUNET_PeerIdentity pid0;
  struct GNUNET_PeerIdentity pid1;
  struct RPS_SamplerElement *s_elem;
  struct GNUNET_CRYPTO_AuthKey auth_key;
  struct GNUNET_CRYPTO_AuthKey auth_key2;
  struct GNUNET_HashCode hash_code;
  struct GNUNET_HashCode hash_code2;

  memset (&pid0, 1, sizeof (pid0));
  memset (&pid1, 0, sizeof (pid1));

  /* Check if creation and destruction of an
   * (empty) sampler element works */
  s_elem = RPS_sampler_elem_create ();
  CHECK (NULL != s_elem);
  CHECK (EMPTY == s_elem->is_empty);
  CHECK (NULL != &s_elem->auth_key);
  auth_key = s_elem->auth_key;
  RPS_sampler_elem_destroy (s_elem);


  /* Check creation of another sampler element
   * yields another (random) key */
  s_elem = RPS_sampler_elem_create ();
  CHECK (NULL != s_elem);
  CHECK (EMPTY == s_elem->is_empty);
  CHECK (NULL != &s_elem->auth_key);
  CHECK (auth_key.key != s_elem->auth_key.key);
  CHECK (0 != memcmp (auth_key.key, s_elem->auth_key.key, GNUNET_CRYPTO_HASH_LENGTH));
  auth_key = s_elem->auth_key;

  /* Check that reinitialisation
   * yields another (random) key */
  RPS_sampler_elem_reinit (s_elem);
  CHECK (NULL != s_elem);
  CHECK (EMPTY == s_elem->is_empty);
  CHECK (NULL != &s_elem->auth_key);
  CHECK (auth_key.key != s_elem->auth_key.key);
  CHECK (0 != memcmp (auth_key.key, s_elem->auth_key.key, GNUNET_CRYPTO_HASH_LENGTH));
  RPS_sampler_elem_destroy (s_elem);


  /* Check that input of single peer id
   * sets valid values */
  s_elem = RPS_sampler_elem_create ();
  CHECK (EMPTY == s_elem->is_empty);
  CHECK (NULL != &s_elem->auth_key);
  CHECK (auth_key.key != s_elem->auth_key.key);
  /* This fails only with minimal chance */
  CHECK (0 != memcmp (auth_key.key, s_elem->auth_key.key, GNUNET_CRYPTO_HASH_LENGTH));
  auth_key = s_elem->auth_key;

  /* Check also that the hash of the peer id changed
   * Also fails with minimal probability */
  hash_code = s_elem->peer_id_hash;
  RPS_sampler_elem_next (s_elem, &pid0);
  CHECK (0 == memcmp (&pid0,
                      &s_elem->peer_id,
                      sizeof (struct GNUNET_PeerIdentity)));
  CHECK (0 != memcmp (&hash_code,
                      &s_elem->peer_id_hash,
                      sizeof (struct GNUNET_HashCode)));
  hash_code = s_elem->peer_id_hash;

  /* We can only check that the peer id is one of both inputs */
  RPS_sampler_elem_next (s_elem, &pid1);
  CHECK ( (0 == memcmp (&pid0,
                        &s_elem->peer_id,
                        sizeof (struct GNUNET_PeerIdentity))) ||
          (0 == memcmp (&pid1,
                        &s_elem->peer_id,
                        sizeof (struct GNUNET_PeerIdentity))) );

  /* Check that hash stayed the same when peer id did not change */
  if (0 == memcmp (&pid0,
                   &s_elem->peer_id,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    CHECK (0 == memcmp (&hash_code,
                        &s_elem->peer_id_hash,
                        sizeof (struct GNUNET_HashCode)));
  }
  else /* Check that hash changed */
  {
    CHECK (0 != memcmp (&hash_code,
                        &s_elem->peer_id_hash,
                        sizeof (struct GNUNET_HashCode)));
  }

  /* Check multiple inputs of same id
   * hash should not change anymore */
  hash_code2 = s_elem->peer_id_hash;
  RPS_sampler_elem_next (s_elem, &pid0);
  CHECK (0 == memcmp (&hash_code2,
                      &s_elem->peer_id_hash,
                      sizeof (struct GNUNET_HashCode)));
  RPS_sampler_elem_next (s_elem, &pid1);
  CHECK (0 == memcmp (&hash_code2,
                      &s_elem->peer_id_hash,
                      sizeof (struct GNUNET_HashCode)));
  RPS_sampler_elem_next (s_elem, &pid0);
  CHECK (0 == memcmp (&hash_code2,
                      &s_elem->peer_id_hash,
                      sizeof (struct GNUNET_HashCode)));
  RPS_sampler_elem_next (s_elem, &pid0);
  CHECK (0 == memcmp (&hash_code2,
                      &s_elem->peer_id_hash,
                      sizeof (struct GNUNET_HashCode)));
  RPS_sampler_elem_next (s_elem, &pid0);
  CHECK (0 == memcmp (&hash_code2,
                      &s_elem->peer_id_hash,
                      sizeof (struct GNUNET_HashCode)));
  RPS_sampler_elem_next (s_elem, &pid1);
  CHECK (0 == memcmp (&hash_code2,
                      &s_elem->peer_id_hash,
                      sizeof (struct GNUNET_HashCode)));
  RPS_sampler_elem_next (s_elem, &pid1);
  CHECK (0 == memcmp (&hash_code2,
                      &s_elem->peer_id_hash,
                      sizeof (struct GNUNET_HashCode)));
  RPS_sampler_elem_next (s_elem, &pid1);
  CHECK (0 == memcmp (&hash_code2,
                      &s_elem->peer_id_hash,
                      sizeof (struct GNUNET_HashCode)));

  /* Check whether pid stayed the same all the time */
  if (0 == memcmp (&hash_code,
                   &hash_code2,
                   sizeof (struct GNUNET_HashCode)))
  {
    CHECK (0 == memcmp (&pid0,
                        &s_elem->peer_id,
                        sizeof (struct GNUNET_PeerIdentity)));
  }
  else
  {
    CHECK (0 == memcmp (&pid1,
                        &s_elem->peer_id,
                        sizeof (struct GNUNET_PeerIdentity)));
  }
  RPS_sampler_elem_destroy (s_elem);

  /* Check _set() */
  s_elem = RPS_sampler_elem_create ();
  CHECK (NULL != s_elem);
  CHECK (EMPTY == s_elem->is_empty);
  CHECK (NULL != &s_elem->auth_key);
  auth_key = s_elem->auth_key;
  memset (&auth_key2, 0, sizeof (auth_key2));
  RPS_sampler_elem_set (s_elem, auth_key2);
  CHECK (0 == memcmp (auth_key2.key,
                      s_elem->auth_key.key,
                      GNUNET_CRYPTO_HASH_LENGTH));
  RPS_sampler_elem_destroy (s_elem);


  /* TODO: deterministic tests (use _set() to set auth_key) */
  return 0;
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test_service_rps_peers", 
		    "WARNING",
		    NULL);
  return check ();
}

/* end of test_service_rps_peers.c */
