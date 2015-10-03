/*
     This file is part of GNUnet.
     Copyright (C) 2015 Christian Grothoff (and other contributing authors)

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
 * @file set/test_set_union_copy.c
 * @brief testcase for lazy copying of union sets
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_common.h"
#include "gnunet_testing_lib.h"
#include "gnunet_set_service.h"


/**
 * Value to return from #main().
 */
static int ret;

static struct GNUNET_PeerIdentity local_id;

static struct GNUNET_SET_Handle *set1;

static struct GNUNET_SET_Handle *set2;

static const struct GNUNET_CONFIGURATION_Handle *config;


static void
add_element_str (struct GNUNET_SET_Handle *set, char *str)
{
  struct GNUNET_SET_Element element;

  element.element_type = 0;
  element.data = str;
  element.size = strlen (str);

  GNUNET_SET_add_element (set, &element, NULL, NULL);
}


static void
remove_element_str (struct GNUNET_SET_Handle *set, char *str)
{
  struct GNUNET_SET_Element element;

  element.element_type = 0;
  element.data = str;
  element.size = strlen (str);

  GNUNET_SET_remove_element (set, &element, NULL, NULL);
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

typedef void (*Continuation) (void *cls);


struct CountIterClosure
{
  unsigned int expected_count;
  unsigned int ongoing_count;
  Continuation cont;
  void *cont_cls;
  char *what;
};


static int
check_count_iter (void *cls,
                  const struct GNUNET_SET_Element *element)
{
  struct CountIterClosure *ci_cls = cls;

  if (NULL == element)
  {
    if (ci_cls->expected_count != ci_cls->ongoing_count)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Expected count (what: %s) to be %u, but it's actually %u\n",
                  ci_cls->what,
                  ci_cls->expected_count, ci_cls->ongoing_count);
      ret = 1;
      return GNUNET_NO;
    }
    ci_cls->cont (ci_cls->cont_cls);
    return GNUNET_NO;
  }

  ci_cls->ongoing_count += 1;
  return GNUNET_YES;
}



void
check_count (struct GNUNET_SET_Handle *set,
             char *what,
             unsigned int expected_count,
             Continuation cont,
             void *cont_cls)
{
  struct CountIterClosure *ci_cls = GNUNET_new (struct CountIterClosure);

  ci_cls->expected_count = expected_count;
  ci_cls->ongoing_count = 0;
  ci_cls->cont = cont;
  ci_cls->cont_cls = cont_cls;
  ci_cls->what = what;

  GNUNET_assert (GNUNET_YES == GNUNET_SET_iterate (set, check_count_iter, ci_cls));
}


void test_done (void *cls)
{
  if (NULL != set1)
    GNUNET_SET_destroy (set1);
  if (NULL != set2)
    GNUNET_SET_destroy (set2);

  GNUNET_SCHEDULER_shutdown ();
}


void check_new_set_count (void *cls)
{
  check_count (set2, "new set", 4, &test_done, NULL);
}


void copy_done (void *cls, struct GNUNET_SET_Handle *new_set)
{
  printf ("copy done\n");
  set2 = new_set;
  remove_element_str (set2, "spam");
  add_element_str (set2, "new1");
  add_element_str (set2, "new2");
  remove_element_str (set2, "new2");
  remove_element_str (set2, "new3");
  // Check that set1 didn't change.
  check_count (set1, "old set", 3,
               &check_new_set_count, NULL);
}


void test_copy (void *cls)
{
  printf ("about to copy\n");
  GNUNET_SET_copy_lazy (set1, copy_done, NULL);
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

  set1 = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
  add_element_str (set1, "foo");
  add_element_str (set1, "bar");
  /* duplicate -- ignored */
  add_element_str (set1, "bar");
  remove_element_str (set1, "foo");
  /* non-existent -- ignored */
  remove_element_str (set1, "nonexist1");
  add_element_str (set1, "spam");
  /* duplicate -- ignored */
  remove_element_str (set1, "foo");
  add_element_str (set1, "eggs");

  check_count (set1, "initial test", 3, &test_copy, NULL);
}


int
main (int argc, char **argv)
{
  if (0 != GNUNET_TESTING_peer_run ("test_set_union_copy",
                                    "test_set.conf",
                                    &run, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "failed to start testing peer\n");
    return 1;
  }
  return ret;
}
