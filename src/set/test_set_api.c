/*
     This file is part of GNUnet.
     Copyright (C) 2012 GNUnet e.V.

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
 * @file set/test_set_api.c
 * @brief testcase for set_api.c
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_set_service.h"


static struct GNUNET_PeerIdentity local_id;

static struct GNUNET_HashCode app_id;

static struct GNUNET_SET_Handle *set1;

static struct GNUNET_SET_Handle *set2;

static struct GNUNET_SET_ListenHandle *listen_handle;

static struct GNUNET_SET_OperationHandle *oh1;

static struct GNUNET_SET_OperationHandle *oh2;

static const struct GNUNET_CONFIGURATION_Handle *config;

static unsigned int iter_count;

static int ret;

static struct GNUNET_SCHEDULER_Task *tt;


static void
result_cb_set1 (void *cls,
                const struct GNUNET_SET_Element *element,
                enum GNUNET_SET_Status status)
{
  switch (status)
  {
  case GNUNET_SET_STATUS_OK:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "set 1: got element\n");
    break;
  case GNUNET_SET_STATUS_FAILURE:
    GNUNET_break (0);
    oh1 = NULL;
    fprintf (stderr,
             "set 1: received failure status!\n");
    ret = 1;
    if (NULL != tt)
    {
      GNUNET_SCHEDULER_cancel (tt);
      tt = NULL;
    }
    GNUNET_SCHEDULER_shutdown ();
    break;
  case GNUNET_SET_STATUS_DONE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "set 1: done\n");
    oh1 = NULL;
    if (NULL != set1)
    {
      GNUNET_SET_destroy (set1);
      set1 = NULL;
    }
    if (NULL == set2)
    {
      GNUNET_SCHEDULER_cancel (tt);
      tt = NULL;
      GNUNET_SCHEDULER_shutdown ();
    }
    break;
  default:
    GNUNET_assert (0);
  }
}


static void
result_cb_set2 (void *cls,
                const struct GNUNET_SET_Element *element,
                enum GNUNET_SET_Status status)
{
  switch (status)
  {
  case GNUNET_SET_STATUS_OK:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "set 2: got element\n");
    break;
  case GNUNET_SET_STATUS_FAILURE:
    GNUNET_break (0);
    oh2 = NULL;
    fprintf (stderr,
             "set 2: received failure status\n");
    ret = 1;
    break;
  case GNUNET_SET_STATUS_DONE:
    oh2 = NULL;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "set 2: done\n");
    GNUNET_SET_destroy (set2);
    set2 = NULL;
    if (NULL == set1)
    {
      GNUNET_SCHEDULER_cancel (tt);
      tt = NULL;
      GNUNET_SCHEDULER_shutdown ();
    }
    break;
  default:
    GNUNET_assert (0);
  }
}


static void
listen_cb (void *cls,
           const struct GNUNET_PeerIdentity *other_peer,
           const struct GNUNET_MessageHeader *context_msg,
           struct GNUNET_SET_Request *request)
{
  GNUNET_assert (NULL != context_msg);
  GNUNET_assert (ntohs (context_msg->type) == GNUNET_MESSAGE_TYPE_TEST);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "listen cb called\n");
  GNUNET_SET_listen_cancel (listen_handle);
  listen_handle = NULL;
  oh2 = GNUNET_SET_accept (request,
                           GNUNET_SET_RESULT_ADDED,
                           &result_cb_set2,
                           NULL);
  GNUNET_SET_commit (oh2,
                     set2);
}


/**
 * Start the set operation.
 *
 * @param cls closure, unused
 */
static void
start (void *cls)
{
  struct GNUNET_MessageHeader context_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting reconciliation\n");
  context_msg.size = htons (sizeof context_msg);
  context_msg.type = htons (GNUNET_MESSAGE_TYPE_TEST);
  listen_handle = GNUNET_SET_listen (config,
                                     GNUNET_SET_OPERATION_UNION,
                                     &app_id,
                                     &listen_cb,
                                     NULL);
  oh1 = GNUNET_SET_prepare (&local_id,
                            &app_id,
                            &context_msg,
                            GNUNET_SET_RESULT_ADDED,
                            &result_cb_set1,
                            NULL);
  GNUNET_SET_commit (oh1,
                     set1);
}


/**
 * Initialize the second set, continue
 *
 * @param cls closure, unused
 */
static void
init_set2 (void *cls)
{
  struct GNUNET_SET_Element element;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "initializing set 2\n");

  element.element_type = 0;

  element.data = "hello";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (set2, &element, NULL, NULL);
  element.data = "quux";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (set2, &element, NULL, NULL);
  element.data = "baz";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (set2, &element, &start, NULL);
}


/**
 * Initialize the first set, continue.
 */
static void
init_set1 (void)
{
  struct GNUNET_SET_Element element;

  element.element_type = 0;

  element.data = "hello";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (set1, &element, NULL, NULL);
  element.data = "bar";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (set1, &element, init_set2, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "initialized set 1\n");
}


static int
iter_cb (void *cls,
         const struct GNUNET_SET_Element *element)
{
  if (NULL == element)
  {
    GNUNET_assert (3 == iter_count);
    GNUNET_SET_destroy (cls);
    return GNUNET_YES;
  }
  iter_count++;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "iter: got element %u\n",
              iter_count);
  return GNUNET_YES;
}


static void
test_iter ()
{
  struct GNUNET_SET_Element element;
  struct GNUNET_SET_Handle *iter_set;

  iter_set = GNUNET_SET_create (config, GNUNET_SET_OPERATION_UNION);

  element.element_type = 0;

  element.data = "hello";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (iter_set, &element, NULL, NULL);
  element.data = "bar";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (iter_set, &element, NULL, NULL);
  element.data = "quux";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (iter_set, &element, NULL, NULL);

  GNUNET_SET_iterate (iter_set, iter_cb, iter_set);
}


/**
 * Function run on timeout.
 *
 * @param cls closure
 */
static void
timeout_fail (void *cls)
{
  tt = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
              "Testcase failed with timeout\n");
  GNUNET_SCHEDULER_shutdown ();
  ret = 1;
}


/**
 * Function run on shutdown.
 *
 * @param cls closure
 */
static void
do_shutdown (void *cls)
{
  if (NULL != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = NULL;
  }
  if (NULL != oh1)
  {
    GNUNET_SET_operation_cancel (oh1);
    oh1 = NULL;
  }
  if (NULL != oh2)
  {
    GNUNET_SET_operation_cancel (oh2);
    oh2 = NULL;
  }
  if (NULL != set1)
  {
    GNUNET_SET_destroy (set1);
    set1 = NULL;
  }
  if (NULL != set2)
  {
    GNUNET_SET_destroy (set2);
    set2 = NULL;
  }
  if (NULL != listen_handle)
  {
    GNUNET_SET_listen_cancel (listen_handle);
    listen_handle = NULL;
  }
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
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{

  struct GNUNET_SET_OperationHandle *my_oh;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running preparatory tests\n");
  tt = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
				     &timeout_fail,
                                     NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);

  config = cfg;
  GNUNET_CRYPTO_get_peer_identity (cfg, &local_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "my id (from CRYPTO): %s\n",
              GNUNET_i2s (&local_id));
  GNUNET_TESTING_peer_get_identity (peer, &local_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "my id (from TESTING): %s\n",
              GNUNET_i2s (&local_id));
  test_iter ();

  set1 = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
  set2 = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
                                    &app_id);

  ///* test if canceling an uncommited request works! */
  my_oh = GNUNET_SET_prepare (&local_id,
                              &app_id,
                              NULL,
                              GNUNET_SET_RESULT_ADDED,
                              NULL,
                              NULL);

  GNUNET_SET_operation_cancel (my_oh);

  /* test the real set reconciliation */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running real set-reconciliation\n");
  init_set1 ();
}


int
main (int argc, char **argv)
{
  GNUNET_log_setup ("test_set_api",
                    "WARNING",
                    NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Launching peer\n");
  if (0 != GNUNET_TESTING_peer_run ("test_set_api",
                                    "test_set.conf",
                                    &run, NULL))
  {
    return 1;
  }
  return ret;
}
