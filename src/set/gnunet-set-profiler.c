/*
      This file is part of GNUnet
      Copyright (C) 2013 GNUnet e.V.

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
 * @file set/gnunet-set-profiler.c
 * @brief profiling tool for set
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_set_service.h"
#include "gnunet_testbed_service.h"


static int ret;

static unsigned int num_a = 5;
static unsigned int num_b = 5;
static unsigned int num_c = 20;

static char *op_str = "union";

const static struct GNUNET_CONFIGURATION_Handle *config;

struct SetInfo
{
  char *id;
  struct GNUNET_SET_Handle *set;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_CONTAINER_MultiHashMap *sent;
  struct GNUNET_CONTAINER_MultiHashMap *received;
  int done;
} info1, info2;

static struct GNUNET_CONTAINER_MultiHashMap *common_sent;

static struct GNUNET_HashCode app_id;

static struct GNUNET_PeerIdentity local_peer;

static struct GNUNET_SET_ListenHandle *set_listener;

static int byzantine;
static unsigned int force_delta;
static unsigned int force_full;
static unsigned int element_size = 32;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *statistics;

/**
 * The profiler will write statistics
 * for all peers to the file with this name.
 */
static char *statistics_filename;

/**
 * The profiler will write statistics
 * for all peers to this file.
 */
static FILE *statistics_file;


static int
map_remove_iterator (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  struct GNUNET_CONTAINER_MultiHashMap *m = cls;
  int ret;

  GNUNET_assert (NULL != key);

  ret = GNUNET_CONTAINER_multihashmap_remove_all (m, key);
  if (GNUNET_OK != ret)
    printf ("spurious element\n");
  return GNUNET_YES;

}


/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
statistics_result (void *cls,
                   const char *subsystem,
                   const char *name,
                   uint64_t value,
                   int is_persistent)
{
  if (NULL != statistics_file)
  {
    fprintf (statistics_file, "%s\t%s\t%lu\n", subsystem, name, (unsigned long) value);
  }
  return GNUNET_OK;
}


static void
statistics_done (void *cls,
                 int success)
{
  GNUNET_assert (GNUNET_YES == success);
  if (NULL != statistics_file)
    fclose (statistics_file);
  GNUNET_SCHEDULER_shutdown ();
}


static void
check_all_done (void)
{
  if (info1.done == GNUNET_NO || info2.done == GNUNET_NO)
    return;

  GNUNET_CONTAINER_multihashmap_iterate (info1.received, map_remove_iterator, info2.sent);
  GNUNET_CONTAINER_multihashmap_iterate (info2.received, map_remove_iterator, info1.sent);

  printf ("set a: %d missing elements\n", GNUNET_CONTAINER_multihashmap_size (info1.sent));
  printf ("set b: %d missing elements\n", GNUNET_CONTAINER_multihashmap_size (info2.sent));

  if (NULL == statistics_filename)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  statistics_file = fopen (statistics_filename, "w");
  GNUNET_STATISTICS_get (statistics, NULL, NULL,
                         &statistics_done,
                         &statistics_result, NULL);
}


static void
set_result_cb (void *cls,
               const struct GNUNET_SET_Element *element,
               uint64_t current_size,
               enum GNUNET_SET_Status status)
{
  struct SetInfo *info = cls;
  struct GNUNET_HashCode hash;

  GNUNET_assert (GNUNET_NO == info->done);
  switch (status)
  {
    case GNUNET_SET_STATUS_DONE:
    case GNUNET_SET_STATUS_HALF_DONE:
      info->done = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "set %s done\n", info->id);
      check_all_done ();
      info->oh = NULL;
      return;
    case GNUNET_SET_STATUS_FAILURE:
      info->oh = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "failure\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    case GNUNET_SET_STATUS_ADD_LOCAL:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "set %s: local element\n", info->id);
      break;
    case GNUNET_SET_STATUS_ADD_REMOTE:
      GNUNET_CRYPTO_hash (element->data, element->size, &hash);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "set %s: remote element %s\n", info->id,
                  GNUNET_h2s (&hash));
      // XXX: record and check
      return;
    default:
      GNUNET_assert (0);
  }

  if (element->size != element_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "wrong element size: %u, expected %u\n",
                element->size,
                (unsigned int) sizeof (struct GNUNET_HashCode));
    GNUNET_assert (0);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "set %s: got element (%s)\n",
              info->id, GNUNET_h2s (element->data));
  GNUNET_assert (NULL != element->data);
  struct GNUNET_HashCode data_hash;
  GNUNET_CRYPTO_hash (element->data, element_size, &data_hash);
  GNUNET_CONTAINER_multihashmap_put (info->received,
                                     &data_hash, NULL,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
}


static void
set_listen_cb (void *cls,
               const struct GNUNET_PeerIdentity *other_peer,
               const struct GNUNET_MessageHeader *context_msg,
               struct GNUNET_SET_Request *request)
{
  /* max. 2 options plus terminator */
  struct GNUNET_SET_Option opts[3] = {{0}};
  unsigned int n_opts = 0;

  if (NULL == request)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "listener failed\n");
    return;
  }
  GNUNET_assert (NULL == info2.oh);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "set listen cb called\n");
  if (byzantine)
  {
    opts[n_opts++] = (struct GNUNET_SET_Option) { .type = GNUNET_SET_OPTION_BYZANTINE };
  }
  GNUNET_assert (!(force_full && force_delta));
  if (force_full)
  {
    opts[n_opts++] = (struct GNUNET_SET_Option) { .type = GNUNET_SET_OPTION_FORCE_FULL };
  }
  if (force_delta)
  {
    opts[n_opts++] = (struct GNUNET_SET_Option) { .type = GNUNET_SET_OPTION_FORCE_DELTA };
  }

  opts[n_opts].type = 0;
  info2.oh = GNUNET_SET_accept (request, GNUNET_SET_RESULT_SYMMETRIC,
                                opts,
                                set_result_cb, &info2);
  GNUNET_SET_commit (info2.oh, info2.set);
}


static int
set_insert_iterator (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  struct GNUNET_SET_Handle *set = cls;
  struct GNUNET_SET_Element el;

  el.element_type = 0;
  el.data = value;
  el.size = element_size;
  GNUNET_SET_add_element (set, &el, NULL, NULL);
  return GNUNET_YES;
}


static void
handle_shutdown (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Shutting down set profiler\n");
  if (NULL != set_listener)
  {
    GNUNET_SET_listen_cancel (set_listener);
    set_listener = NULL;
  }
  if (NULL != info1.oh)
  {
    GNUNET_SET_operation_cancel (info1.oh);
    info1.oh = NULL;
  }
  if (NULL != info2.oh)
  {
    GNUNET_SET_operation_cancel (info2.oh);
    info2.oh = NULL;
  }
  if (NULL != info1.set)
  {
    GNUNET_SET_destroy (info1.set);
    info1.set = NULL;
  }
  if (NULL != info2.set)
  {
    GNUNET_SET_destroy (info2.set);
    info2.set = NULL;
  }
  GNUNET_STATISTICS_destroy (statistics, GNUNET_NO);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  unsigned int i;
  struct GNUNET_HashCode hash;
  /* max. 2 options plus terminator */
  struct GNUNET_SET_Option opts[3] = {{0}};
  unsigned int n_opts = 0;

  config = cfg;

  GNUNET_assert (element_size > 0);

  if (GNUNET_OK != GNUNET_CRYPTO_get_peer_identity (cfg, &local_peer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "could not retrieve host identity\n");
    ret = 0;
    return;
  }

  statistics = GNUNET_STATISTICS_create ("set-profiler", cfg);

  GNUNET_SCHEDULER_add_shutdown (&handle_shutdown, NULL);

  info1.id = "a";
  info2.id = "b";

  info1.sent = GNUNET_CONTAINER_multihashmap_create (num_a+1, GNUNET_NO);
  info2.sent = GNUNET_CONTAINER_multihashmap_create (num_b+1, GNUNET_NO);
  common_sent = GNUNET_CONTAINER_multihashmap_create (num_c+1, GNUNET_NO);

  info1.received = GNUNET_CONTAINER_multihashmap_create (num_a+1, GNUNET_NO);
  info2.received = GNUNET_CONTAINER_multihashmap_create (num_b+1, GNUNET_NO);

  for (i = 0; i < num_a; i++)
  {
    char *data = GNUNET_malloc (element_size);
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK, data, element_size);
    GNUNET_CRYPTO_hash (data, element_size, &hash);
    GNUNET_CONTAINER_multihashmap_put (info1.sent, &hash, data,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }

  for (i = 0; i < num_b; i++)
  {
    char *data = GNUNET_malloc (element_size);
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK, data, element_size);
    GNUNET_CRYPTO_hash (data, element_size, &hash);
    GNUNET_CONTAINER_multihashmap_put (info2.sent, &hash, data,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }

  for (i = 0; i < num_c; i++)
  {
    char *data = GNUNET_malloc (element_size);
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK, data, element_size);
    GNUNET_CRYPTO_hash (data, element_size, &hash);
    GNUNET_CONTAINER_multihashmap_put (common_sent, &hash, data,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_STRONG, &app_id);

  /* FIXME: also implement intersection etc. */
  info1.set = GNUNET_SET_create (config, GNUNET_SET_OPERATION_UNION);
  info2.set = GNUNET_SET_create (config, GNUNET_SET_OPERATION_UNION);

  GNUNET_CONTAINER_multihashmap_iterate (info1.sent, set_insert_iterator, info1.set);
  GNUNET_CONTAINER_multihashmap_iterate (info2.sent, set_insert_iterator, info2.set);
  GNUNET_CONTAINER_multihashmap_iterate (common_sent, set_insert_iterator, info1.set);
  GNUNET_CONTAINER_multihashmap_iterate (common_sent, set_insert_iterator, info2.set);

  set_listener = GNUNET_SET_listen (config, GNUNET_SET_OPERATION_UNION,
                                    &app_id, set_listen_cb, NULL);


  if (byzantine)
  {
    opts[n_opts++] = (struct GNUNET_SET_Option) { .type = GNUNET_SET_OPTION_BYZANTINE };
  }
  GNUNET_assert (!(force_full && force_delta));
  if (force_full)
  {
    opts[n_opts++] = (struct GNUNET_SET_Option) { .type = GNUNET_SET_OPTION_FORCE_FULL };
  }
  if (force_delta)
  {
    opts[n_opts++] = (struct GNUNET_SET_Option) { .type = GNUNET_SET_OPTION_FORCE_DELTA };
  }

  opts[n_opts].type = 0;

  info1.oh = GNUNET_SET_prepare (&local_peer, &app_id, NULL,
                                 GNUNET_SET_RESULT_SYMMETRIC,
                                 opts,
                                 set_result_cb, &info1);
  GNUNET_SET_commit (info1.oh, info1.set);
  GNUNET_SET_destroy (info1.set);
  info1.set = NULL;
}


static void
pre_run (void *cls, char *const *args, const char *cfgfile,
         const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (0 != GNUNET_TESTING_peer_run ("set-profiler",
                                    cfgfile,
                                    &run, NULL))
    ret = 2;
}


int
main (int argc, char **argv)
{
   struct GNUNET_GETOPT_CommandLineOption options[] = {
      GNUNET_GETOPT_OPTION_SET_UINT ('A',
                                     "num-first",
                                     NULL,
                                     gettext_noop ("number of values"),
                                     &num_a),

      GNUNET_GETOPT_OPTION_SET_UINT ('B',
                                     "num-second",
                                     NULL,
                                     gettext_noop ("number of values"),
                                     &num_b),

      GNUNET_GETOPT_OPTION_SET_ONE ('b',
                                    "byzantine",
                                    gettext_noop ("use byzantine mode"),
                                    &byzantine),

      GNUNET_GETOPT_OPTION_SET_UINT ('f',
                                     "force-full",
                                     NULL,
                                     gettext_noop ("force sending full set"),
                                     &force_full),

      GNUNET_GETOPT_OPTION_SET_UINT ('d',
                                     "force-delta",
                                     NULL,
                                     gettext_noop ("number delta operation"),
                                     &force_delta),

      GNUNET_GETOPT_OPTION_SET_UINT ('C',
                                     "num-common",
                                     NULL,
                                     gettext_noop ("number of values"),
                                     &num_c),

      GNUNET_GETOPT_OPTION_STRING ('x',
                                   "operation",
                                   NULL,
                                   gettext_noop ("operation to execute"),
                                   &op_str),

      GNUNET_GETOPT_OPTION_SET_UINT ('w',
                                     "element-size",
                                     NULL,
                                     gettext_noop ("element size"),
                                     &element_size),

      GNUNET_GETOPT_OPTION_FILENAME ('s',
                                     "statistics",
                                     "FILENAME",
                                     gettext_noop ("write statistics to file"),
                                     &statistics_filename),

      GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run2 (argc, argv, "gnunet-set-profiler",
		      "help",
		      options, &pre_run, NULL, GNUNET_YES);
  return ret;
}
