/*
 * This file is part of GNUnet
 * Copyright (C) 2013 GNUnet e.V.
 *
 * GNUnet is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 */

/**
 * @file multicast/test_multicast.c
 * @brief Tests for the Multicast API.
 * @author Gabor X Toth
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_multicast_service.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Return value from 'main'.
 */
static int res;

/**
 * Handle for task for timeout termination.
 */
static struct GNUNET_SCHEDULER_Task * end_badly_task;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

struct GNUNET_PeerIdentity this_peer;

struct GNUNET_MULTICAST_Origin *origin;
struct GNUNET_MULTICAST_Member *member;

struct GNUNET_CRYPTO_EddsaPrivateKey *group_key;
struct GNUNET_CRYPTO_EddsaPublicKey group_pub_key;

struct GNUNET_CRYPTO_EcdsaPrivateKey *member_key;
struct GNUNET_CRYPTO_EcdsaPublicKey member_pub_key;

struct TransmitClosure {
  struct GNUNET_MULTICAST_OriginTransmitHandle *orig_tmit;
  struct GNUNET_MULTICAST_MemberTransmitHandle *mem_tmit;
  char * data[16];
  uint8_t data_delay[16];
  uint8_t data_count;
  uint8_t paused;
  uint8_t n;
} tmit_cls;

struct OriginClosure {
  uint8_t msgs_expected;
  uint8_t n;
} origin_cls;

struct MemberClosure {
  uint8_t msgs_expected;
  size_t n;
} member_cls;

struct GNUNET_MessageHeader *join_req, *join_resp;

enum
{
  TEST_NONE                = 0,
  TEST_ORIGIN_START        = 1,
  TEST_MEMBER_JOIN_REFUSE  = 2,
  TEST_MEMBER_JOIN_ADMIT   = 3,
  TEST_ORIGIN_TO_ALL       = 4,
  TEST_ORIGIN_TO_ALL_RECV  = 5,
  TEST_MEMBER_TO_ORIGIN    = 6,
  TEST_MEMBER_REPLAY_ERROR = 7,
  TEST_MEMBER_REPLAY_OK    = 8,
  TEST_MEMBER_PART         = 9,
  TEST_ORIGIN_STOP        = 10,
} test;

uint64_t replay_fragment_id;
uint64_t replay_flags;

static void
member_join (int t);


/**
 * Clean up all resources used.
 */
static void
cleanup ()
{
  if (NULL != member)
  {
    GNUNET_MULTICAST_member_part (member, NULL, NULL);
    member = NULL;
  }
  if (NULL != origin)
  {
    GNUNET_MULTICAST_origin_stop (origin, NULL, NULL);
    origin = NULL;
  }
}


/**
 * Terminate the test case (failure).
 *
 * @param cls NULL
 */
static void
end_badly (void *cls)
{
  res = 1;
  cleanup ();
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Test FAILED.\n");
}


/**
 * Terminate the test case (success).
 *
 * @param cls NULL
 */
static void
end_normally (void *cls)
{
  res = 0;
  cleanup ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Test PASSED.\n");
}


/**
 * Finish the test case (successfully).
 */
static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ending tests.\n");

  if (end_badly_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (end_badly_task);
    end_badly_task = NULL;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				&end_normally, NULL);
}


static void
tmit_resume (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmission resumed.\n");
  struct TransmitClosure *tmit = cls;
  if (NULL != tmit->orig_tmit)
    GNUNET_MULTICAST_origin_to_all_resume (tmit->orig_tmit);
  else if (NULL != tmit->mem_tmit)
    GNUNET_MULTICAST_member_to_origin_resume (tmit->mem_tmit);
}


static int
tmit_notify (void *cls, size_t *data_size, void *data)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test #%u: origin_tmit_notify()\n", test);
  struct TransmitClosure *tmit = cls;

  if (0 == tmit->data_count)
  {
    *data_size = 0;
    return GNUNET_YES;
  }

  uint16_t size = strlen (tmit->data[tmit->n]);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmit notify data: %u bytes available, processing fragment %u/%u (size %u).\n",
              (unsigned int) *data_size,
              tmit->n + 1,
              tmit->data_count,
              size);
  if (*data_size < size)
  {
    *data_size = 0;
    GNUNET_assert (0);
    return GNUNET_SYSERR;
  }

  if (GNUNET_YES != tmit->paused && 0 < tmit->data_delay[tmit->n])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmission paused.\n");
    tmit->paused = GNUNET_YES;
    GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                     tmit->data_delay[tmit->n]),
      tmit_resume, tmit);
    *data_size = 0;
    return GNUNET_NO;
  }
  tmit->paused = GNUNET_NO;

  *data_size = size;
  GNUNET_memcpy (data, tmit->data[tmit->n], size);

  return ++tmit->n < tmit->data_count ? GNUNET_NO : GNUNET_YES;
}


static void
member_recv_join_request (void *cls,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *member_key,
                          const struct GNUNET_MessageHeader *join_msg,
                          struct GNUNET_MULTICAST_JoinHandle *jh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_recv_join_request()\n", test);
}


static void
origin_stopped (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_stopped()\n", test);
  end ();
}


static void
schedule_origin_stop (void *cls)
{
  test = TEST_ORIGIN_STOP;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_stop()\n", test);
  GNUNET_MULTICAST_origin_stop (origin, origin_stopped, NULL);
  origin = NULL;
}


static void
member_parted (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_parted()\n", test);
  member = NULL;

  switch (test)
  {
  case TEST_MEMBER_JOIN_REFUSE:
    // Test 3 starts here
    member_join (TEST_MEMBER_JOIN_ADMIT);
    break;

  case TEST_MEMBER_PART:
    GNUNET_SCHEDULER_add_now (&schedule_origin_stop, NULL);
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Invalid test #%d in member_parted()\n", test);
    GNUNET_assert (0);
  }
}


static void
schedule_member_part (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: schedule_member_part()\n", test);
  GNUNET_MULTICAST_member_part (member, member_parted, NULL);
}


static void
member_part ()
{
  test = TEST_MEMBER_PART;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_part()\n", test);
  // Test 10 starts here
  GNUNET_SCHEDULER_add_now (&schedule_member_part, NULL);
}


static void
member_replay_ok ()
{
  // Execution of test 8 here
  test = TEST_MEMBER_REPLAY_OK;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_replay_ok()\n", test);
  replay_fragment_id = 1;
  replay_flags = 1 | 1<<11;
  GNUNET_MULTICAST_member_replay_fragment (member, replay_fragment_id,
                                           replay_flags);
}


static void
member_replay_error ()
{
  test = TEST_MEMBER_REPLAY_ERROR;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_replay_error()\n", test);
  replay_fragment_id = 1234;
  replay_flags = 11 | 1<<11;
  GNUNET_MULTICAST_member_replay_fragment (member, replay_fragment_id,
                                           replay_flags);
}


static void
origin_recv_replay_msg (void *cls,
                        const struct GNUNET_CRYPTO_EcdsaPublicKey *member_key,
                        uint64_t message_id,
                        uint64_t fragment_offset,
                        uint64_t flags,
                        struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_recv_replay_msg()\n", test);
  GNUNET_assert (0);
}


static void
member_recv_replay_msg (void *cls,
                        const struct GNUNET_CRYPTO_EcdsaPublicKey *member_key,
                        uint64_t message_id,
                        uint64_t fragment_offset,
                        uint64_t flags,
                        struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_recv_replay_msg()\n", test);
  GNUNET_assert (0);
}


static void
origin_recv_replay_frag (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPublicKey *member_key,
                         uint64_t fragment_id,
                         uint64_t flags,
                         struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_recv_replay_frag()"
              " - fragment_id=%" PRIu64 " flags=%" PRIu64 "\n",
              test, fragment_id, flags);
  GNUNET_assert (replay_fragment_id == fragment_id && replay_flags == flags);
  switch (test)
  {
  case TEST_MEMBER_REPLAY_ERROR:
    // Test 8 starts here
    GNUNET_MULTICAST_replay_response (rh, NULL, GNUNET_SYSERR);
    member_replay_ok ();
    break;

  case TEST_MEMBER_REPLAY_OK:
  {
    struct GNUNET_MULTICAST_MessageHeader mmsg = {
      .header = {
        .type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE),
        .size = htons (sizeof (mmsg)),
      },
      .fragment_id = GNUNET_htonll (1),
      .message_id = GNUNET_htonll (1),
      .fragment_offset = 0,
      .group_generation = GNUNET_htonll (1),
      .flags = 0,
    };
    member_cls.n = 0;
    member_cls.msgs_expected = 1;
    GNUNET_MULTICAST_replay_response (rh, &mmsg.header, GNUNET_MULTICAST_REC_OK);
    GNUNET_MULTICAST_replay_response_end (rh);
    break;
  }

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Invalid test #%d in origin_recv_replay_frag()\n", test);
    GNUNET_assert (0);
  }
}


static void
member_recv_replay_frag (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPublicKey *member_key,
                         uint64_t fragment_id,
                         uint64_t flags,
                         struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_recv_replay_frag()\n", test);
  GNUNET_assert (0);
}


static void
origin_recv_request (void *cls,
                     const struct GNUNET_MULTICAST_RequestHeader *req)
{
  struct OriginClosure *ocls = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_recv_request()\n", test);
  if (++ocls->n != ocls->msgs_expected)
    return;

  GNUNET_assert (0 == memcmp (&req->member_pub_key,
                              &member_pub_key, sizeof (member_pub_key)));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test #%u: verify message content, take first 3 bytes: %.3s\n",
              test, (char *)&req[1]);
  GNUNET_assert (0 == memcmp (&req[1], "abc", 3));

  // Test 7 starts here
  member_replay_error ();
}


static void
member_to_origin ()
{
  test = TEST_MEMBER_TO_ORIGIN;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_to_origin()\n", test);

  struct TransmitClosure *tmit = &tmit_cls;
  *tmit = (struct TransmitClosure) {};
  tmit->data[0] = "abc def";
  tmit->data[1] = "ghi jkl mno";
  tmit->data_delay[1] = 2;
  tmit->data[2] = "pqr stuw xyz";
  tmit->data_count = 3;

  origin_cls.n = 0;
  origin_cls.msgs_expected = 1;

  tmit->mem_tmit = GNUNET_MULTICAST_member_to_origin (member, 1,
                                                      tmit_notify, tmit);
}


static void
member_recv_message (void *cls,
                     const struct GNUNET_MULTICAST_MessageHeader *msg)
{
  struct MemberClosure *mcls = cls;

  // Test 5 starts here after message has been received from origin
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test #%u: member_recv_message() %u/%u\n",
              test,
              (unsigned int) (mcls->n + 1),
              mcls->msgs_expected);
  if (++mcls->n != mcls->msgs_expected)
    return;

  // FIXME: check message content

  switch (test)
  {
  case TEST_ORIGIN_TO_ALL:
    test = TEST_ORIGIN_TO_ALL_RECV;
    break;

  case TEST_ORIGIN_TO_ALL_RECV:
    // Test 6 starts here
    member_to_origin ();
    break;

  case TEST_MEMBER_REPLAY_OK:
    // Test 9 starts here
    GNUNET_assert (replay_fragment_id == GNUNET_ntohll (msg->fragment_id));
    member_part ();
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Invalid test #%d in origin_recv_message()\n", test);
    GNUNET_assert (0);
  }
}


static void
origin_recv_message (void *cls,
                     const struct GNUNET_MULTICAST_MessageHeader *msg)
{
  struct OriginClosure *ocls = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_recv_message() %u/%u\n",
              test, ocls->n + 1, ocls->msgs_expected);
  if (++ocls->n != ocls->msgs_expected)
    return;

  // FIXME: check message content

  switch (test)
  {
  case TEST_ORIGIN_TO_ALL:
    // Prepare to execute test 5
    test = TEST_ORIGIN_TO_ALL_RECV;
    break;

  case TEST_ORIGIN_TO_ALL_RECV:
    // Test 6 starts here
    member_to_origin ();
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Invalid test #%d in origin_recv_message()\n", test);
    GNUNET_assert (0);
  }
}


static void
origin_to_all ()
{
  test = TEST_ORIGIN_TO_ALL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_to_all()\n", test);

  struct TransmitClosure *tmit = &tmit_cls;
  *tmit = (struct TransmitClosure) {};
  tmit->data[0] = "ABC DEF";
  tmit->data[1] =  GNUNET_malloc (GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD + 1);
  uint16_t i;
  for (i = 0; i < GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD; i++)
    tmit->data[1][i] = (0 == i % 10000) ? '0' + i / 10000 : '_';
  tmit->data[2] = "GHI JKL MNO";
  tmit->data_delay[2] = 2;
  tmit->data[3] = "PQR STUW XYZ";
  tmit->data_count = 4;

  origin_cls.n = member_cls.n = 0;
  origin_cls.msgs_expected = member_cls.msgs_expected = tmit->data_count;

  tmit->orig_tmit = GNUNET_MULTICAST_origin_to_all (origin, 1, 1,
                                                    tmit_notify, tmit);
}


static void
member_recv_join_decision (void *cls,
                           int is_admitted,
                           const struct GNUNET_PeerIdentity *peer,
                           uint16_t relay_count,
                           const struct GNUNET_PeerIdentity *relays,
                           const struct GNUNET_MessageHeader *join_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_recv_join_decision() - is_admitted: %d\n",
              test, is_admitted);

  GNUNET_assert (join_msg->size == join_resp->size);
  GNUNET_assert (join_msg->type == join_resp->type);
  GNUNET_assert (0 == memcmp (join_msg, join_resp, ntohs (join_resp->size)));

  switch (test)
  {
  case TEST_MEMBER_JOIN_REFUSE:
    GNUNET_assert (0 == relay_count);
    // Test 3 starts here
    GNUNET_SCHEDULER_add_now (&schedule_member_part, NULL);
    break;

  case TEST_MEMBER_JOIN_ADMIT:
    GNUNET_assert (1 == relay_count);
    GNUNET_assert (0 == memcmp (relays, &this_peer, sizeof (this_peer)));
    // Test 4 starts here
    origin_to_all ();
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Invalid test #%d in member_recv_join_decision()\n", test);
    GNUNET_assert (0);
  }
}

/**
 * Test: origin receives join request
 */
static void
origin_recv_join_request (void *cls,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *mem_key,
                          const struct GNUNET_MessageHeader *join_msg,
                          struct GNUNET_MULTICAST_JoinHandle *jh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_recv_join_request()\n", test);

  GNUNET_assert (0 == memcmp (mem_key, &member_pub_key, sizeof (member_pub_key)));
  GNUNET_assert (join_msg->size == join_req->size);
  GNUNET_assert (join_msg->type == join_req->type);
  GNUNET_assert (0 == memcmp (join_msg, join_req, ntohs (join_req->size)));

  char data[] = "here's the decision";
  uint8_t data_size = strlen (data) + 1;
  join_resp = GNUNET_malloc (sizeof (join_resp) + data_size);
  join_resp->size = htons (sizeof (join_resp) + data_size);
  join_resp->type = htons (456);
  GNUNET_memcpy (&join_resp[1], data, data_size);

  switch (test)
  {
  case TEST_MEMBER_JOIN_REFUSE:
    // Test 3 starts here
    GNUNET_MULTICAST_join_decision (jh, GNUNET_NO, 0, NULL, join_resp);
    break;

  case TEST_MEMBER_JOIN_ADMIT:
    // Test 3 is running
    GNUNET_MULTICAST_join_decision (jh, GNUNET_YES, 1, &this_peer, join_resp);
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Invalid test #%d in origin_recv_join_request()\n", test);
    GNUNET_assert (0);
    break;
  }
}

/**
 * Test: member joins multicast group
 */
static void
member_join (int t)
{
  test = t;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: member_join()\n", test);

  member_key = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_CRYPTO_ecdsa_key_get_public (member_key, &member_pub_key);

  if (NULL != join_req)
    GNUNET_free (join_req);

  char data[] = "let me in!";
  uint8_t data_size = strlen (data) + 1;
  join_req = GNUNET_malloc (sizeof (join_req) + data_size);
  join_req->size = htons (sizeof (join_req) + data_size);
  join_req->type = htons (123);
  GNUNET_memcpy (&join_req[1], data, data_size);

  member = GNUNET_MULTICAST_member_join (cfg, &group_pub_key, member_key,
                                         &this_peer, 1, &this_peer, join_req,
                                         member_recv_join_request,
                                         member_recv_join_decision,
                                         member_recv_replay_frag,
                                         member_recv_replay_msg,
                                         member_recv_message,
                                         &member_cls);
}

/**
 * Test: Start a multicast group as origin
 */
static void
origin_start ()
{
  test = TEST_ORIGIN_START;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test #%u: origin_start()\n", test);

  group_key = GNUNET_CRYPTO_eddsa_key_create ();
  GNUNET_CRYPTO_eddsa_key_get_public (group_key, &group_pub_key);

  origin = GNUNET_MULTICAST_origin_start (cfg, group_key, 0,
                                          origin_recv_join_request,
                                          origin_recv_replay_frag,
                                          origin_recv_replay_msg,
                                          origin_recv_request,
                                          origin_recv_message,
                                          &origin_cls);
  // Test 2 starts here
  member_join (TEST_MEMBER_JOIN_REFUSE);
}


/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to Multicast service)
 * @param peer handle to access more of the peer (not used)
 */
static void
#if DEBUG_TEST_MULTICAST
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
#else
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_TESTING_Peer *peer)
#endif
{
  cfg = c;
  end_badly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						 &end_badly, NULL);
  GNUNET_CRYPTO_get_peer_identity (cfg, &this_peer);

  // Test 1 starts here
  origin_start ();
}


int
main (int argc, char *argv[])
{
  res = 1;
#if DEBUG_TEST_MULTICAST
  const struct GNUNET_GETOPT_CommandLineOption opts[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc, argv, "test-multicast",
                                       "test-multicast [options]",
                                       opts, &run, NULL))
    return 1;
#else
  if (0 != GNUNET_TESTING_peer_run ("test-multicast", "test_multicast.conf", &run, NULL))
    return 1;
#endif
  return res;
}

/* end of test_multicast.c */
