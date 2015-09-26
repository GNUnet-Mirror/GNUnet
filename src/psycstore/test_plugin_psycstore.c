/*
 * This file is part of GNUnet
 * Copyright (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/*
 * @file psycstore/test_plugin_psycstore.c
 * @brief Test for the PSYCstore plugins.
 * @author Gabor X Toth
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_psycstore_plugin.h"
#include "gnunet_psycstore_service.h"
#include "gnunet_multicast_service.h"

#define DEBUG_PSYCSTORE GNUNET_EXTRA_LOGGING
#if DEBUG_PSYCSTORE
# define LOG_LEVEL "DEBUG"
#else
# define LOG_LEVEL "WARNING"
#endif

#define C2ARG(str) str, (sizeof (str) - 1)

#define LOG(kind,...)                                                          \
  GNUNET_log_from (kind, "test-plugin-psycstore", __VA_ARGS__)

static int ok;

/**
 * Name of plugin under test.
 */
static const char *plugin_name;

static struct GNUNET_CRYPTO_EddsaPrivateKey *channel_key;
static struct GNUNET_CRYPTO_EcdsaPrivateKey *slave_key;

static struct GNUNET_CRYPTO_EddsaPublicKey channel_pub_key;
static struct GNUNET_CRYPTO_EcdsaPublicKey slave_pub_key;

/**
 * Function called when the service shuts down.  Unloads our psycstore
 * plugin.
 *
 * @param api api to unload
 */
static void
unload_plugin (struct GNUNET_PSYCSTORE_PluginFunctions *api)
{
  char *libname;

  GNUNET_asprintf (&libname, "libgnunet_plugin_psycstore_%s", plugin_name);
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (libname, api));
  GNUNET_free (libname);
}


/**
 * Load the psycstore plugin.
 *
 * @param cfg configuration to pass
 * @return NULL on error
 */
static struct GNUNET_PSYCSTORE_PluginFunctions *
load_plugin (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_PSYCSTORE_PluginFunctions *ret;
  char *libname;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Loading `%s' psycstore plugin\n"),
              plugin_name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_psycstore_%s", plugin_name);
  if (NULL == (ret = GNUNET_PLUGIN_load (libname, (void*) cfg)))
  {
    FPRINTF (stderr, "Failed to load plugin `%s'!\n", plugin_name);
    return NULL;
  }
  GNUNET_free (libname);
  return ret;
}


struct FragmentClosure
{
  uint8_t n;
  uint64_t flags[16];
  struct GNUNET_MULTICAST_MessageHeader *msg[16];
};

static int
fragment_cb (void *cls, struct GNUNET_MULTICAST_MessageHeader *msg2,
             enum GNUNET_PSYCSTORE_MessageFlags flags)
{
  struct FragmentClosure *fcls = cls;
  struct GNUNET_MULTICAST_MessageHeader *msg1 = fcls->msg[fcls->n];
  uint64_t flags1 = fcls->flags[fcls->n++];
  int ret;

  if (flags1 == flags && msg1->header.size == msg2->header.size
      && 0 == memcmp (msg1, msg2, ntohs (msg1->header.size)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Fragment %llu matches\n",
         GNUNET_ntohll (msg1->fragment_id));
    ret = GNUNET_YES;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Fragment %llu differs\n",
         GNUNET_ntohll (msg1->fragment_id));
    ret = GNUNET_SYSERR;
  }

  GNUNET_free (msg2);
  return ret;
}


struct StateClosure {
  size_t n;
  char *name[16];
  void *value[16];
  size_t value_size[16];
};

static int
state_cb (void *cls, const char *name, const void *value, uint32_t value_size)
{
  struct StateClosure *scls = cls;
  const void *val = scls->value[scls->n];
  size_t val_size = scls->value_size[scls->n++];

  /* FIXME: check name */

  return value_size == val_size && 0 == memcmp (value, val, val_size)
    ? GNUNET_YES
    : GNUNET_SYSERR;
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_PSYCSTORE_PluginFunctions *db;

  ok = 1;
  db = load_plugin (cfg);
  if (NULL == db)
  {
    FPRINTF (stderr,
             "%s",
	     "Failed to initialize PSYCstore.  "
             "Database likely not setup, skipping test.\n");
    return;
  }

  /* Store & test membership */

  channel_key = GNUNET_CRYPTO_eddsa_key_create ();
  slave_key = GNUNET_CRYPTO_ecdsa_key_create ();

  GNUNET_CRYPTO_eddsa_key_get_public (channel_key,
                                                  &channel_pub_key);
  GNUNET_CRYPTO_ecdsa_key_get_public (slave_key, &slave_pub_key);

  GNUNET_assert (GNUNET_OK == db->membership_store (db->cls, &channel_pub_key,
                                                    &slave_pub_key, GNUNET_YES,
                                                    4, 2, 1));

  GNUNET_assert (GNUNET_YES == db->membership_test (db->cls, &channel_pub_key,
                                                    &slave_pub_key, 4));

  GNUNET_assert (GNUNET_YES == db->membership_test (db->cls, &channel_pub_key,
                                                    &slave_pub_key, 2));

  GNUNET_assert (GNUNET_NO == db->membership_test (db->cls, &channel_pub_key,
                                                   &slave_pub_key, 1));


  /* Store & get messages */

  struct GNUNET_MULTICAST_MessageHeader *msg
    = GNUNET_malloc (sizeof (*msg) + sizeof (channel_pub_key));
  GNUNET_assert (msg != NULL);

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE);
  msg->header.size = htons (sizeof (*msg) + sizeof (channel_pub_key));

  uint64_t fragment_id = INT64_MAX - 1;
  msg->fragment_id = GNUNET_htonll (fragment_id);

  uint64_t message_id = INT64_MAX - 10;
  msg->message_id = GNUNET_htonll (message_id);

  uint64_t group_generation = INT64_MAX - 3;
  msg->group_generation = GNUNET_htonll (group_generation);

  msg->hop_counter = htonl (9);
  msg->fragment_offset = GNUNET_htonll (0);
  msg->flags = htonl (GNUNET_MULTICAST_MESSAGE_LAST_FRAGMENT);

  memcpy (&msg[1], &channel_pub_key, sizeof (channel_pub_key));

  msg->purpose.size = htonl (ntohs (msg->header.size)
                             - sizeof (msg->header)
                             - sizeof (msg->hop_counter)
                             - sizeof (msg->signature));
  msg->purpose.purpose = htonl (234);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_eddsa_sign (channel_key, &msg->purpose, &msg->signature));

  struct FragmentClosure fcls = { 0 };
  fcls.n = 0;
  fcls.msg[0] = msg;
  fcls.flags[0] = GNUNET_PSYCSTORE_MESSAGE_STATE;

  GNUNET_assert (
    GNUNET_OK == db->fragment_store (db->cls, &channel_pub_key, msg,
                                     fcls.flags[0]));

  uint64_t ret_frags = 0;
  GNUNET_assert (
    GNUNET_OK == db->fragment_get (db->cls, &channel_pub_key,
                                   fragment_id, fragment_id,
                                   &ret_frags, fragment_cb, &fcls));
  GNUNET_assert (fcls.n == 1);

  // FIXME: test fragment_get_latest and message_get_latest

  fcls.n = 0;

  GNUNET_assert (
    GNUNET_OK == db->message_get_fragment (db->cls, &channel_pub_key,
                                           GNUNET_ntohll (msg->message_id),
                                           GNUNET_ntohll (msg->fragment_offset),
                                           fragment_cb, &fcls));
  GNUNET_assert (fcls.n == 1);

  GNUNET_assert (
    GNUNET_OK == db->message_add_flags (db->cls, &channel_pub_key,
                                        GNUNET_ntohll (msg->message_id),
                                        GNUNET_PSYCSTORE_MESSAGE_STATE_APPLIED));

  fcls.n = 0;
  fcls.flags[0] |= GNUNET_PSYCSTORE_MESSAGE_STATE_APPLIED;

  GNUNET_assert (
    GNUNET_OK == db->fragment_get (db->cls, &channel_pub_key,
                                   fragment_id, fragment_id,
                                   &ret_frags, fragment_cb, &fcls));
  GNUNET_assert (fcls.n == 1);

  struct GNUNET_MULTICAST_MessageHeader *msg1
    = GNUNET_malloc (sizeof (*msg1) + sizeof (channel_pub_key));

  memcpy (msg1, msg, sizeof (*msg1) + sizeof (channel_pub_key));

  msg1->fragment_id = GNUNET_htonll (INT64_MAX);
  msg1->fragment_offset = GNUNET_htonll (32768);

  fcls.n = 0;
  fcls.msg[1] = msg1;
  fcls.flags[1] = GNUNET_PSYCSTORE_MESSAGE_STATE_HASH;

  GNUNET_assert (GNUNET_OK == db->fragment_store (db->cls, &channel_pub_key, msg1,
                                                  fcls.flags[1]));

  GNUNET_assert (
    GNUNET_OK == db->message_get (db->cls, &channel_pub_key,
                                  message_id, message_id, 0,
                                  &ret_frags, fragment_cb, &fcls));
  GNUNET_assert (fcls.n == 2 && ret_frags == 2);

  /* Message counters */

  fragment_id = 0;
  message_id = 0;
  group_generation = 0;
  GNUNET_assert (
    GNUNET_OK == db->counters_message_get (db->cls, &channel_pub_key,
                                           &fragment_id, &message_id,
                                           &group_generation)
    && fragment_id == GNUNET_ntohll (msg1->fragment_id)
    && message_id == GNUNET_ntohll (msg1->message_id)
    && group_generation == GNUNET_ntohll (msg1->group_generation));

  /* Modify state */

  message_id = GNUNET_ntohll (fcls.msg[0]->message_id) + 1;
  GNUNET_assert (GNUNET_OK == db->state_modify_begin (db->cls, &channel_pub_key,
                                                      message_id, 0));

  GNUNET_assert (GNUNET_OK == db->state_modify_op (db->cls, &channel_pub_key,
                                                   GNUNET_ENV_OP_ASSIGN,
                                                   "_foo",
                                                   C2ARG("one two three")));

  GNUNET_assert (GNUNET_OK == db->state_modify_op (db->cls, &channel_pub_key,
                                                   GNUNET_ENV_OP_ASSIGN,
                                                   "_foo_bar", slave_key,
                                                   sizeof (*slave_key)));

  GNUNET_assert (GNUNET_OK == db->state_modify_end (db->cls, &channel_pub_key,
                                                    message_id));

  struct StateClosure scls = { 0 };
  scls.n = 0;
  scls.value[0] = "one two three";
  scls.value_size[0] = strlen ("one two three");

  GNUNET_assert (GNUNET_OK == db->state_get (db->cls, &channel_pub_key, "_foo",
                                             state_cb, &scls));
  GNUNET_assert (scls.n == 1);

  scls.n = 0;
  scls.value[1] = slave_key;
  scls.value_size[1] = sizeof (*slave_key);

  GNUNET_assert (GNUNET_OK == db->state_get_prefix (db->cls, &channel_pub_key,
                                                    "_foo", state_cb, &scls));
  GNUNET_assert (scls.n == 2);

  scls.n = 0;
  GNUNET_assert (GNUNET_NO == db->state_get_signed (db->cls, &channel_pub_key,
                                                    state_cb, &scls));
  GNUNET_assert (scls.n == 0);

  GNUNET_assert (GNUNET_OK == db->state_update_signed (db->cls,
                                                       &channel_pub_key));

  scls.n = 0;
  GNUNET_assert (GNUNET_YES == db->state_get_signed (db->cls, &channel_pub_key,
                                                     state_cb, &scls));
  GNUNET_assert (scls.n == 2);

  /* State counters */

  uint64_t max_state_msg_id = 0;
  GNUNET_assert (GNUNET_OK == db->counters_state_get (db->cls, &channel_pub_key,
                                                      &max_state_msg_id)
                 && max_state_msg_id == message_id);

  /* State sync */

  scls.n = 0;
  scls.value[0] = channel_key;
  scls.value_size[0] = sizeof (*channel_key);
  scls.value[1] = "three two one";
  scls.value_size[1] = strlen ("three two one");

  GNUNET_assert (GNUNET_OK == db->state_sync_begin (db->cls, &channel_pub_key));

  GNUNET_assert (GNUNET_OK == db->state_sync_assign (db->cls, &channel_pub_key,
                                                     "_sync_bar", scls.value[0],
                                                     scls.value_size[0]));

  GNUNET_assert (GNUNET_OK == db->state_sync_assign (db->cls, &channel_pub_key,
                                                     "_sync_foo", scls.value[1],
                                                     scls.value_size[1]));

  GNUNET_assert (GNUNET_OK == db->state_sync_end (db->cls, &channel_pub_key,
                                                  max_state_msg_id,
                                                  INT64_MAX - 5));

  GNUNET_assert (GNUNET_NO == db->state_get_prefix (db->cls, &channel_pub_key,
                                                    "_foo", state_cb, &scls));
  GNUNET_assert (scls.n == 0);

  GNUNET_assert (GNUNET_OK == db->state_get_prefix (db->cls, &channel_pub_key,
                                                    "_sync", state_cb, &scls));
  GNUNET_assert (scls.n == 2);

  scls.n = 0;
  GNUNET_assert (GNUNET_OK == db->state_get_signed (db->cls, &channel_pub_key,
                                                    state_cb, &scls));
  GNUNET_assert (scls.n == 2);

  /* Modify state after sync */

  message_id = GNUNET_ntohll (fcls.msg[0]->message_id) + 6;
  GNUNET_assert (GNUNET_OK == db->state_modify_begin (db->cls, &channel_pub_key,
                                                      message_id,
                                                      message_id - max_state_msg_id));

  GNUNET_assert (GNUNET_OK == db->state_modify_op (db->cls, &channel_pub_key,
                                                   GNUNET_ENV_OP_ASSIGN,
                                                   "_sync_foo",
                                                   C2ARG("five six seven")));

  GNUNET_assert (GNUNET_OK == db->state_modify_end (db->cls, &channel_pub_key,
                                                    message_id));

  /* Reset state */

  scls.n = 0;
  GNUNET_assert (GNUNET_OK == db->state_reset (db->cls, &channel_pub_key));
  GNUNET_assert (scls.n == 0);

  ok = 0;

  if (NULL != channel_key)
  {
    GNUNET_free (channel_key);
    channel_key = NULL;
  }
  if (NULL != slave_key)
  {
    GNUNET_free (slave_key);
    slave_key = NULL;
  }

  unload_plugin (db);
}


int
main (int argc, char *argv[])
{
  char cfg_name[128];
  char *const xargv[] = {
    "test-plugin-psycstore",
    "-c", cfg_name,
    "-L", LOG_LEVEL,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-plugin-psycstore-sqlite");
  GNUNET_log_setup ("test-plugin-psycstore", LOG_LEVEL, NULL);
  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_snprintf (cfg_name, sizeof (cfg_name), "test_plugin_psycstore_%s.conf",
                   plugin_name);
  GNUNET_PROGRAM_run ((sizeof (xargv) / sizeof (char *)) - 1, xargv,
                      "test-plugin-psycstore", "nohelp", options, &run, NULL);

  if (ok != 0)
    FPRINTF (stderr, "Missed some testcases: %d\n", ok);

#if ! DEBUG_PSYCSTORE
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-plugin-psycstore-sqlite");
#endif

  return ok;
}

/* end of test_plugin_psycstore.c */
