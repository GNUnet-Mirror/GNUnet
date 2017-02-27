/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2016 GNUnet e.V.

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
 * @file set/test_set_union_result_smmetric
 * @brief testcase for symmetric result mode of the union set operation
 * @author Florian Dold
 * @author Christian Grothoff
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

static struct GNUNET_SET_OperationHandle *oh1;

static struct GNUNET_SET_OperationHandle *oh2;

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

/**
 * Task that is run when the test times out.
 */
static struct GNUNET_SCHEDULER_Task *timeout_task;


static void
result_cb_set1 (void *cls,
                const struct GNUNET_SET_Element *element,
                uint64_t current_size,
                enum GNUNET_SET_Status status)
{
  switch (status)
  {
    case GNUNET_SET_STATUS_ADD_LOCAL:
      count_set1++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 1: got element\n");
      break;
    case GNUNET_SET_STATUS_FAILURE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 1: failure\n");
      oh1 = NULL;
      ret = 1;
      if (NULL != timeout_task)
      {
        GNUNET_SCHEDULER_cancel (timeout_task);
        timeout_task = NULL;
      }
      GNUNET_SCHEDULER_shutdown ();
      break;
    case GNUNET_SET_STATUS_DONE:
      oh1 = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 1: done\n");
      GNUNET_SET_destroy (set1);
      set1 = NULL;
      if (NULL == set2)
      {
        if (NULL != timeout_task)
        {
          GNUNET_SCHEDULER_cancel (timeout_task);
          timeout_task = NULL;
        }
        GNUNET_SCHEDULER_shutdown ();
      }
      break;
    case GNUNET_SET_STATUS_ADD_REMOTE:
      break;
    default:
      GNUNET_assert (0);
  }
}


static void
result_cb_set2 (void *cls,
                const struct GNUNET_SET_Element *element,
                uint64_t current_size,
                enum GNUNET_SET_Status status)
{
  switch (status)
  {
    case GNUNET_SET_STATUS_ADD_LOCAL:
      count_set2++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 2: got element\n");
      break;
    case GNUNET_SET_STATUS_FAILURE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 2: failure\n");
      oh2 = NULL;
      ret = 1;
      if (NULL != timeout_task)
      {
        GNUNET_SCHEDULER_cancel (timeout_task);
        timeout_task = NULL;
      }
      GNUNET_SCHEDULER_shutdown ();
      break;
    case GNUNET_SET_STATUS_DONE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "set 2: done\n");
      oh2 = NULL;
      GNUNET_SET_destroy (set2);
      set2 = NULL;
      if (NULL == set1)
      {
        if (NULL != timeout_task)
        {
          GNUNET_SCHEDULER_cancel (timeout_task);
          timeout_task = NULL;
        }
        GNUNET_SCHEDULER_shutdown ();
      }
      break;
    case GNUNET_SET_STATUS_ADD_REMOTE:
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
  GNUNET_assert (ntohs (context_msg->type) == GNUNET_MESSAGE_TYPE_DUMMY);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "listen cb called\n");
  GNUNET_SET_listen_cancel (listen_handle);
  listen_handle = NULL;
  oh2 = GNUNET_SET_accept (request,
                           GNUNET_SET_RESULT_SYMMETRIC,
                           (struct GNUNET_SET_Option[]) { 0 },
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

  context_msg.size = htons (sizeof context_msg);
  context_msg.type = htons (GNUNET_MESSAGE_TYPE_DUMMY);

  listen_handle = GNUNET_SET_listen (config,
                                     GNUNET_SET_OPERATION_UNION,
                                     &app_id,
                                     &listen_cb, NULL);
  oh1 = GNUNET_SET_prepare (&local_id,
                            &app_id,
                            &context_msg,
                            GNUNET_SET_RESULT_SYMMETRIC,
                            (struct GNUNET_SET_Option[]) { 0 },
                            &result_cb_set1, NULL);
  GNUNET_SET_commit (oh1, set1);
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
 */
static void
timeout_fail (void *cls)
{
  timeout_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "test timed out\n");
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
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
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
  timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
                                               &timeout_fail,
                                               NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  config = cfg;
  GNUNET_TESTING_peer_get_identity (peer,
                                    &local_id);

  if (0)
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
  GNUNET_break (2 == count_set1);
  GNUNET_break (1 == count_set2);
  return ret;
}
