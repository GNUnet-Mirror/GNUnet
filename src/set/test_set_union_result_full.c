/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file set/test_set_union_result_full.c
 * @brief testcase for full result mode of the union set operation
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_set_service.h"


/**
 * Value to return from #main().
 */
static int ret;

static struct GNUNET_PeerIdentity local_id;

static struct GNUNET_HashCode app_id;
static struct GNUNET_SET_Handle *set1;

static struct GNUNET_SET_Handle *set2;

static struct GNUNET_SET_ListenHandle *listen_handle;

static const struct GNUNET_CONFIGURATION_Handle *config;

static int iter_count;

/**
 * Are we testing correctness for the empty set union?
 */
static int empty;

/**
 * Number of elements found in set 1
 */
static unsigned int count_set1;

/**
 * Number of elements found in set 2
 */
static unsigned int count_set2;


static void
result_cb_set1 (void *cls,
                const struct GNUNET_SET_Element *element,
                enum GNUNET_SET_Status status)
{
  switch (status)
  {
    case GNUNET_SET_STATUS_OK:
      count_set1++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 1: got element\n");
      break;
    case GNUNET_SET_STATUS_FAILURE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 1: failure\n");
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      break;
    case GNUNET_SET_STATUS_DONE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 1: done\n");
      GNUNET_SET_destroy (set1);
      set1 = NULL;
      if (NULL == set2)
        GNUNET_SCHEDULER_shutdown ();
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
      count_set2++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 2: got element\n");
      break;
    case GNUNET_SET_STATUS_FAILURE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 2: failure\n");
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      break;
    case GNUNET_SET_STATUS_DONE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 2: done\n");
      GNUNET_SET_destroy (set2);
      set2 = NULL;
      if (NULL == set1)
        GNUNET_SCHEDULER_shutdown ();
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
  struct GNUNET_SET_OperationHandle *oh;

  GNUNET_assert (NULL != context_msg);
  GNUNET_assert (ntohs (context_msg->type) == GNUNET_MESSAGE_TYPE_TEST);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "listen cb called\n");
  GNUNET_SET_listen_cancel (listen_handle);
  oh = GNUNET_SET_accept (request,
                          GNUNET_SET_RESULT_FULL,
                          &result_cb_set2,
                          NULL);
  GNUNET_SET_commit (oh, set2);
}


/**
 * Start the set operation.
 *
 * @param cls closure, unused
 */
static void
start (void *cls)
{
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_MessageHeader context_msg;

  context_msg.size = htons (sizeof context_msg);
  context_msg.type = htons (GNUNET_MESSAGE_TYPE_TEST);

  listen_handle = GNUNET_SET_listen (config,
                                     GNUNET_SET_OPERATION_UNION,
                                     &app_id,
                                     &listen_cb, NULL);
  oh = GNUNET_SET_prepare (&local_id,
                           &app_id,
                           &context_msg,
                           GNUNET_SET_RESULT_FULL,
                           &result_cb_set1, NULL);
  GNUNET_SET_commit (oh, set1);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "initializing set 2\n");
  if (empty)
  {
    start (NULL);
    return;
  }
  element.element_type = 0;
  element.data = "hello";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (set2,
                          &element,
                          NULL,
                          NULL);
  element.data = "quux";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (set2,
                          &element,
                          NULL,
                          NULL);
  element.data = "baz";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (set2,
                          &element,
                          &start, NULL);
}


/**
 * Initialize the first set, continue.
 */
static void
init_set1 (void)
{
  struct GNUNET_SET_Element element;

  if (empty)
  {
    init_set2 (NULL);
    return;
  }
  element.element_type = 0;
  element.data = "hello";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (set1,
                          &element,
                          NULL,
                          NULL);
  element.data = "bar";
  element.size = strlen(element.data);
  GNUNET_SET_add_element (set1,
                          &element,
                          &init_set2,
                          NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "initialized set 1\n");
}


static int
iter_cb (void *cls,
         const struct GNUNET_SET_Element *element)
{
  if (NULL == element)
  {
    GNUNET_assert (iter_count == 3);
    GNUNET_SET_destroy (cls);
    return GNUNET_YES;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "iter: got element\n");
  iter_count++;
  return GNUNET_YES;
}


static void
test_iter ()
{
  struct GNUNET_SET_Element element;
  struct GNUNET_SET_Handle *iter_set;

  iter_count = 0;
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

  GNUNET_SET_iterate (iter_set,
                      &iter_cb,
                      iter_set);
}


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
timeout_fail (void *cls,
              const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_SCHEDULER_shutdown ();
  ret = 1;
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
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
                                &timeout_fail,
                                NULL);

  config = cfg;
  GNUNET_TESTING_peer_get_identity (peer,
                                    &local_id);

  test_iter ();

  set1 = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
  set2 = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &app_id);

  /* test the real set reconciliation */
  init_set1 ();
}


int
main (int argc, char **argv)
{
  empty = 1;
  if (0 != GNUNET_TESTING_peer_run ("test_set_api",
                                    "test_set.conf",
                                    &run, NULL))
  {
    return 1;
  }
  GNUNET_assert (0 == count_set1);
  GNUNET_assert (0 == count_set2);
  empty = 0;
  if (0 != GNUNET_TESTING_peer_run ("test_set_api",
                                    "test_set.conf",
                                    &run, NULL))
  {
    return 1;
  }
  GNUNET_assert (4 == count_set1);
  GNUNET_assert (4 == count_set2);
  return ret;
}
