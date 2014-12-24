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
 * @file peerinfo/test_peerinfo_api_notify_friend_only.c
 * @brief testcase friend only HELLO restrictions in for peerinfo
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * TODO:
 * - test merging of HELLOs (add same peer twice...)
 */
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_testing_lib.h"
#include "peerinfo.h"

#define TIMEOUT  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

static struct GNUNET_PEERINFO_Handle *h;
static struct GNUNET_PEERINFO_NotifyContext *pnc_w_fo;
static struct GNUNET_PEERINFO_NotifyContext *pnc_wo_fo;

static const struct GNUNET_CONFIGURATION_Handle *mycfg;

static int global_ret;

/**
 * Did we get a HELLO callback for notification handle with friend HELLOS
 * (expected)
 */
static int res_cb_w_fo;

/**
 * Did we get a HELLO callback for notification handle without friend HELLOS
 * (not expected)
 */
static int res_cb_wo_fo;

struct GNUNET_PeerIdentity pid;

struct GNUNET_SCHEDULER_Task * timeout_task;

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  timeout_task = NULL;
  GNUNET_break(0);
  if (NULL != pnc_wo_fo)
  {
    GNUNET_PEERINFO_notify_cancel (pnc_wo_fo);
    pnc_wo_fo = NULL;
  }
  if (NULL != pnc_w_fo)
  {
    GNUNET_PEERINFO_notify_cancel (pnc_w_fo);
    pnc_w_fo = NULL;
  }
  if (NULL != h)
  {
    GNUNET_PEERINFO_disconnect (h);
    h = NULL;
  }
  global_ret = 255;
}

static void
done (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != pnc_w_fo)
    GNUNET_PEERINFO_notify_cancel (pnc_w_fo);
  pnc_w_fo = NULL;
  if (NULL != pnc_wo_fo)
    GNUNET_PEERINFO_notify_cancel (pnc_wo_fo);
  pnc_wo_fo = NULL;
  GNUNET_PEERINFO_disconnect (h);
  h = NULL;

  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }

  if ((GNUNET_YES == res_cb_w_fo) && (GNUNET_NO == res_cb_wo_fo))
    global_ret = 0;
  else
    GNUNET_break(0);
}

static ssize_t
address_generator (void *cls, size_t max, void *buf)
{
  size_t *agc = cls;
  ssize_t ret;
  struct GNUNET_HELLO_Address address;

  if (0 == *agc)
    return GNUNET_SYSERR; /* Done */
  memset (&address.peer, 0, sizeof(struct GNUNET_PeerIdentity));
  address.address = "Address";
  address.transport_name = "peerinfotest";
  address.address_length = *agc;
  ret = GNUNET_HELLO_add_address (&address,
      GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS), buf, max);
  (*agc)--;
  return ret;
}

static void
process_w_fo (void *cls, const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_HELLO_Message *hello, const char *err_msg)
{
  if (err_msg != NULL )
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        _("Error in communication with PEERINFO service\n"));
    GNUNET_SCHEDULER_add_now (&done, NULL );
    return;
  }

  if (NULL != peer)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
        "Received callback for peer `%s' %s HELLO\n", GNUNET_i2s (peer),
        (NULL != hello) ? "with" : "without");

    if (NULL == hello)
      return;

    if (GNUNET_NO == GNUNET_HELLO_is_friend_only (hello))
    {
      GNUNET_break(0);
      return;
    }

    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Received %s HELLO for peer `%s'\n",
        (GNUNET_YES == GNUNET_HELLO_is_friend_only (hello)) ? "friend only" : "public",
        GNUNET_i2s (peer));
    if (0 == memcmp (&pid, peer, sizeof(pid)))
    {
      res_cb_w_fo = GNUNET_YES;
      GNUNET_SCHEDULER_add_now (&done, NULL );
    }
    return;
  }
}

static void
process_wo_fo (void *cls, const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_HELLO_Message *hello, const char *err_msg)
{
  if (err_msg != NULL )
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        _("Error in communication with PEERINFO service\n"));
    GNUNET_SCHEDULER_add_now (&done, NULL );
    return;
  }

  if (NULL != peer)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
        "Received callback for peer `%s' %s HELLO\n", GNUNET_i2s (peer),
        (NULL != hello) ? "with" : "without");

    if (NULL == hello)
      return;

    if (GNUNET_YES == GNUNET_HELLO_is_friend_only (hello))
    {
      GNUNET_break(0);
      return;
    }

    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Received %s HELLO for peer `%s'\n",
        (GNUNET_YES == GNUNET_HELLO_is_friend_only (hello)) ? "friend only" : "public",
        GNUNET_i2s (peer));
    if (0 == memcmp (&pid, peer, sizeof(pid)))
    {
      GNUNET_break(0);
      res_cb_wo_fo = GNUNET_YES;
    }
  }
}

static void
add_peer_done (void *cls, const char *emsg)
{
  if (NULL == emsg)
  {
    return;
  }
  else
  {
    GNUNET_break(0);
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL );
  }
}

static void
add_peer ()
{
  struct GNUNET_HELLO_Message *h2;
  size_t agc;

  agc = 2;
  memset (&pid, 32, sizeof(pid));
  h2 = GNUNET_HELLO_create (&pid.public_key, &address_generator, &agc,
      GNUNET_YES);
  GNUNET_PEERINFO_add_peer (h, h2, &add_peer_done, NULL );
  GNUNET_free(h2);

}

static void
run (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
    struct GNUNET_TESTING_Peer *peer)
{
  timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL );
  mycfg = cfg;
  pnc_w_fo = GNUNET_PEERINFO_notify (mycfg, GNUNET_YES, &process_w_fo, NULL );
  pnc_wo_fo = GNUNET_PEERINFO_notify (mycfg, GNUNET_NO, &process_wo_fo, NULL );
  h = GNUNET_PEERINFO_connect (cfg);
  GNUNET_assert(NULL != h);
  add_peer ();
}

int
main (int argc, char *argv[])
{
  res_cb_w_fo = GNUNET_NO;
  res_cb_wo_fo = GNUNET_NO;
  global_ret = 3;
  if (0
      != GNUNET_TESTING_service_run ("test-peerinfo-api-friend-only",
          "peerinfo", "test_peerinfo_api_data.conf", &run, NULL ))
    return 1;
  return global_ret;
}

/* end of test_peerinfo_api_notify_friend_only.c */
