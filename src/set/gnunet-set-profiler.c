/*
      This file is part of GNUnet
      (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file set/gnunet-set-profiler.c
 * @brief profiling tool for set
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_set_service.h"
#include "gnunet_testbed_service.h"


static int ret;

static unsigned int num_a = 5;
static unsigned int num_b = 5;
static unsigned int num_c = 20;

static unsigned int salt = 42;

static char* op_str = "union";

const static struct GNUNET_CONFIGURATION_Handle *config;

struct GNUNET_CONTAINER_MultiHashMap *map_a;
struct GNUNET_CONTAINER_MultiHashMap *map_b;
struct GNUNET_CONTAINER_MultiHashMap *map_c;


/**
 * Elements that set a received, should match map_c
 * in the end.
 */
struct GNUNET_CONTAINER_MultiHashMap *map_a_received;

/**
 * Elements that set b received, should match map_c
 * in the end.
 */
struct GNUNET_CONTAINER_MultiHashMap *map_b_received;

struct GNUNET_SET_Handle *set_a;
struct GNUNET_SET_Handle *set_b;

struct GNUNET_HashCode app_id;

struct GNUNET_PeerIdentity local_peer;

struct GNUNET_SET_ListenHandle *set_listener;

struct GNUNET_SET_OperationHandle *set_oh1;
struct GNUNET_SET_OperationHandle *set_oh2;


int a_done;
int b_done;



static int
map_remove_iterator (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  struct GNUNET_CONTAINER_MultiHashMap *m = cls;
  int ret;

  ret = GNUNET_CONTAINER_multihashmap_remove (m, key, NULL);
  GNUNET_assert (GNUNET_OK == ret);
  return GNUNET_YES;

}


static void
set_result_cb_1 (void *cls,
                 const struct GNUNET_SET_Element *element,
                 enum GNUNET_SET_Status status)
{
  GNUNET_assert (GNUNET_NO == a_done);
  GNUNET_assert (element->size == sizeof (struct GNUNET_HashCode));
  switch (status)
  {
    case GNUNET_SET_STATUS_DONE:
    case GNUNET_SET_STATUS_HALF_DONE:
      a_done = GNUNET_YES;
      GNUNET_CONTAINER_multihashmap_iterate (map_c, map_remove_iterator, map_a_received);
      GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (map_a_received));
      return;
    case GNUNET_SET_STATUS_FAILURE:
      GNUNET_assert (0);
      return;
    case GNUNET_SET_STATUS_OK:
      break;
    default:
      GNUNET_assert (0);
  }
  GNUNET_CONTAINER_multihashmap_put (map_a_received,
                                     element->data, NULL,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
}


static void
set_result_cb_2 (void *cls,
                 const struct GNUNET_SET_Element *element,
                 enum GNUNET_SET_Status status)
{
  GNUNET_assert (GNUNET_NO == b_done);
  GNUNET_assert (element->size == sizeof (struct GNUNET_HashCode));
  switch (status)
  {
    case GNUNET_SET_STATUS_DONE:
    case GNUNET_SET_STATUS_HALF_DONE:
      b_done = GNUNET_YES;
      GNUNET_CONTAINER_multihashmap_iterate (map_c, map_remove_iterator, map_b_received);
      GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (map_b_received));
      return;
    case GNUNET_SET_STATUS_FAILURE:
      GNUNET_assert (0);
      return;
    case GNUNET_SET_STATUS_OK:
      break;
    default:
      GNUNET_assert (0);
  }
  GNUNET_CONTAINER_multihashmap_put (map_b_received,
                                     element->data, NULL,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
}


static void
set_listen_cb (void *cls,
               const struct GNUNET_PeerIdentity *other_peer,
               const struct GNUNET_MessageHeader *context_msg,
               struct GNUNET_SET_Request *request)
{
  GNUNET_assert (NULL == set_oh2);
  set_oh2 = GNUNET_SET_accept (request, GNUNET_SET_RESULT_ADDED,
                               set_result_cb_2, NULL);
  GNUNET_SET_commit (set_oh2, set_b);
}



static int
set_insert_iterator (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  struct GNUNET_SET_Handle *set = cls;
  struct GNUNET_SET_Element *el;

  el = GNUNET_malloc (sizeof *el + sizeof *key);
  el->type = 0;
  memcpy (&el[1], key, sizeof *key);
  el->data = &el[1];
  el->size = sizeof *key;
  GNUNET_SET_add_element (set, el, NULL, NULL);
  GNUNET_free (el);
  return GNUNET_YES;
}


/**
 * Signature of the 'main' function for a (single-peer) testcase that
 * is run using 'GNUNET_TESTING_peer_run'.
 * 
 * @param cls closure
 * @param cfg configuration of the peer that was started
 * @param peer identity of the peer that was created
 */
static void
test_main (void *cls,
          const struct GNUNET_CONFIGURATION_Handle *cfg,
          struct GNUNET_TESTING_Peer *peer)
{
  unsigned int i;
  struct GNUNET_HashCode hash;

  config = cfg;

  if (GNUNET_OK != GNUNET_CRYPTO_get_host_identity (cfg, &local_peer))
  {
    GNUNET_assert (0);
    return;
  }
  
  map_a = GNUNET_CONTAINER_multihashmap_create (num_a, GNUNET_NO);
  map_b = GNUNET_CONTAINER_multihashmap_create (num_b, GNUNET_NO);
  map_c = GNUNET_CONTAINER_multihashmap_create (num_c, GNUNET_NO);

  for (i = 0; i < num_a; i++)
  {
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_STRONG, &hash);
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (map_a, &hash))
    {
      i--;
      continue;
    }
    GNUNET_CONTAINER_multihashmap_put (map_a, &hash, &hash,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }

  for (i = 0; i < num_b; i++)
  {
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_STRONG, &hash);
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (map_a, &hash))
    {
      i--;
      continue;
    }
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (map_b, &hash))
    {
      i--;
      continue;
    }
    GNUNET_CONTAINER_multihashmap_put (map_b, &hash, NULL,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }

  for (i = 0; i < num_c; i++)
  {
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_STRONG, &hash);
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (map_a, &hash))
    {
      i--;
      continue;
    }
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (map_b, &hash))
    {
      i--;
      continue;
    }
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (map_c, &hash))
    {
      i--;
      continue;
    }
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_STRONG, &hash);
    GNUNET_CONTAINER_multihashmap_put (map_c, &hash, NULL,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }

  /* use last hash for app id */
  app_id = hash;

  /* FIXME: also implement intersection etc. */
  set_a = GNUNET_SET_create (config, GNUNET_SET_OPERATION_UNION);
  set_b = GNUNET_SET_create (config, GNUNET_SET_OPERATION_UNION);

  GNUNET_CONTAINER_multihashmap_iterate (map_a, set_insert_iterator, set_a);
  GNUNET_CONTAINER_multihashmap_iterate (map_b, set_insert_iterator, set_b);
  GNUNET_CONTAINER_multihashmap_iterate (map_c, set_insert_iterator, set_a);
  GNUNET_CONTAINER_multihashmap_iterate (map_c, set_insert_iterator, set_b);

  set_listener = GNUNET_SET_listen (config, GNUNET_SET_OPERATION_UNION,
                                    &app_id, set_listen_cb, NULL);

  set_oh1 = GNUNET_SET_prepare (&local_peer, &app_id, NULL, salt, GNUNET_SET_RESULT_ADDED,
                       set_result_cb_1, NULL);
  GNUNET_SET_commit (set_oh1, set_a);
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{

  ret = GNUNET_TESTING_peer_run ("test_set_api",
                                 "test_set.conf",
                                 &test_main, NULL);
}


int
main (int argc, char **argv)
{
   static const struct GNUNET_GETOPT_CommandLineOption options[] = {
      { 'A', "num-first", NULL,
        gettext_noop ("number of values"),
        GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_a },
      { 'B', "num-second", NULL,
        gettext_noop ("number of values"),
        GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_b },
      { 'B', "num-common", NULL,
        gettext_noop ("number of values"),
        GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_c },
      { 'x', "operation", NULL,
        gettext_noop ("oeration to execute"),
        GNUNET_YES, &GNUNET_GETOPT_set_string, &op_str },
      GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run2 (argc, argv, "gnunet-consensus",
		      "help",
		      options, &run, NULL, GNUNET_YES);
  return ret;
}

