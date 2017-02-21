/*
     This file is part of GNUnet.
     Copyright (C) 2015, 2016 GNUnet e.V.

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
 * @author Florian Dold
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

static struct GNUNET_SCHEDULER_Task *tt;


static void
add_element_str (struct GNUNET_SET_Handle *set,
                 char *str)
{
  struct GNUNET_SET_Element element;

  element.element_type = 0;
  element.data = str;
  element.size = strlen (str);
  GNUNET_SET_add_element (set,
                          &element,
                          NULL,
                          NULL);
}


static void
remove_element_str (struct GNUNET_SET_Handle *set,
                    char *str)
{
  struct GNUNET_SET_Element element;

  element.element_type = 0;
  element.data = str;
  element.size = strlen (str);
  GNUNET_SET_remove_element (set,
                             &element,
                             NULL,
                             NULL);
}


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 */
static void
timeout_fail (void *cls)
{
  tt = NULL;
  GNUNET_SCHEDULER_shutdown ();
  ret = 1;
}


struct CountIterClosure
{
  unsigned int expected_count;
  unsigned int ongoing_count;
  GNUNET_SCHEDULER_TaskCallback cont;
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
                  ci_cls->expected_count,
                  ci_cls->ongoing_count);
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return GNUNET_NO;
    }
    ci_cls->cont (ci_cls->cont_cls);
    return GNUNET_NO;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Set `%s' has element %.*s\n",
              ci_cls->what,
              (int) element->size,
              (const char *) element->data);

  ci_cls->ongoing_count++;
  return GNUNET_YES;
}


static void
check_count (struct GNUNET_SET_Handle *set,
             char *what,
             unsigned int expected_count,
             GNUNET_SCHEDULER_TaskCallback cont,
             void *cont_cls)
{
  struct CountIterClosure *ci_cls = GNUNET_new (struct CountIterClosure);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Checking count of %s\n",
              what);

  ci_cls->expected_count = expected_count;
  ci_cls->ongoing_count = 0;
  ci_cls->cont = cont;
  ci_cls->cont_cls = cont_cls;
  ci_cls->what = what;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_SET_iterate (set,
                                     &check_count_iter,
                                     ci_cls));
}


static void
test_done (void *cls)
{
  GNUNET_SCHEDULER_shutdown ();
}


static void
check_new_set_count (void *cls)
{
  check_count (set2,
               "new set",
               3,
               &test_done,
               NULL);
}


static void
copy_done (void *cls,
           struct GNUNET_SET_Handle *new_set)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "copy done\n");
  set2 = new_set;
  remove_element_str (set2,
                      "k5555");
  add_element_str (set2,
                   "n66666");
  add_element_str (set2,
                   "new2butremoved");
  remove_element_str (set2,
                      "new2butremoved");
  remove_element_str (set2,
                      "new3justremoved");
  // Check that set1 didn't change.
  check_count (set1,
               "old set",
               3,
               &check_new_set_count,
               NULL);
}


static void
test_copy (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "about to copy\n");
  GNUNET_SET_copy_lazy (set1,
                        &copy_done,
                        NULL);
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
}


/**
 * Signature of the 'main' function for a (single-peer) testcase that
 * is run using #GNUNET_TESTING_peer_run().
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
  tt = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
				     &timeout_fail,
                                     NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  config = cfg;
  GNUNET_TESTING_peer_get_identity (peer,
                                    &local_id);

  set1 = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
  add_element_str (set1,
                   "333");
  add_element_str (set1,
                   "k444");
  /* duplicate -- ignored */
  add_element_str (set1,
                   "k444");
  remove_element_str (set1,
                      "333");
  /* non-existent -- ignored */
  remove_element_str (set1,
                      "999999999");
  add_element_str (set1,
                   "k5555");
  /* duplicate -- ignored */
  remove_element_str (set1,
                      "333");
  add_element_str (set1,
                   "k2");

  check_count (set1,
               "initial test",
               3,
               &test_copy,
               NULL);
}


int
main (int argc, char **argv)
{
  if (0 != GNUNET_TESTING_peer_run ("test_set_union_copy",
                                    "test_set.conf",
                                    &run, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "failed to start testing peer\n");
    return 1;
  }
  return ret;
}
