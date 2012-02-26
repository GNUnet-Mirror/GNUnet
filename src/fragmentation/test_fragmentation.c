/*
     This file is part of GNUnet
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
 * @file fragmentation/test_fragmentation.c
 * @brief test for fragmentation.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fragmentation_lib.h"

#define VERBOSE GNUNET_NO

#define DETAILS GNUNET_NO

/**
 * Number of messages to transmit (note: each uses ~32k memory!)
 */
#define NUM_MSGS 5000

/**
 * MTU to force on fragmentation (must be > 1k + 12)
 */
#define MTU 1111

/**
 * Simulate dropping of 1 out of how many messages? (must be > 1)
 */
#define DROPRATE 10

static int ret = 1;

static unsigned int dups;

static unsigned int fragc;

static unsigned int frag_drops;

static unsigned int acks;

static unsigned int ack_drops;

static struct GNUNET_DEFRAGMENT_Context *defrag;

static struct GNUNET_BANDWIDTH_Tracker trackers[NUM_MSGS];

static struct GNUNET_FRAGMENT_Context *frags[NUM_MSGS];

static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  ret = 0;
  shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_DEFRAGMENT_context_destroy (defrag);
  defrag = NULL;
  for (i = 0; i < NUM_MSGS; i++)
  {
    if (frags[i] == NULL)
      continue;
    GNUNET_FRAGMENT_context_destroy (frags[i]);
    frags[i] = NULL;
  }
}


static void
proc_msgs (void *cls, const struct GNUNET_MessageHeader *hdr)
{
  static unsigned int total;
  unsigned int i;
  const char *buf;

#if DETAILS
  FPRINTF (stderr, "%s",  "!");        /* message complete, good! */
#endif
  buf = (const char *) hdr;
  for (i = sizeof (struct GNUNET_MessageHeader); i < ntohs (hdr->size); i++)
    GNUNET_assert (buf[i] == (char) i);
  total++;
#if ! DETAILS
  if (0 == (total % (NUM_MSGS / 100)))
    FPRINTF (stderr, "%s",  ".");
#endif
  /* tolerate 10% loss, i.e. due to duplicate fragment IDs */
  if ((total >= NUM_MSGS - (NUM_MSGS / 10)) && (ret != 0))
  {
    if (GNUNET_SCHEDULER_NO_TASK == shutdown_task)
      shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  }
}


/**
 * Process ACK (by passing to fragmenter)
 */
static void
proc_acks (void *cls, uint32_t msg_id, const struct GNUNET_MessageHeader *hdr)
{
  unsigned int i;
  int ret;

  if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, DROPRATE))
  {
    ack_drops++;
    return;                     /* random drop */
  }
  for (i = 0; i < NUM_MSGS; i++)
  {
    if (frags[i] == NULL)
      continue;
    ret = GNUNET_FRAGMENT_process_ack (frags[i], hdr);
    if (ret == GNUNET_OK)
    {
#if DETAILS
      FPRINTF (stderr, "%s",  "@");    /* good ACK */
#endif
      GNUNET_FRAGMENT_context_destroy (frags[i]);
      frags[i] = NULL;
      acks++;
      return;
    }
    if (ret == GNUNET_NO)
    {
#if DETAILS
      FPRINTF (stderr, "%s",  "@");    /* good ACK */
#endif
      acks++;
      return;
    }
  }
#if DETAILS
  FPRINTF (stderr, "%s",  "_");        /* BAD: ack that nobody feels responsible for... */
#endif
}


/**
 * Process fragment (by passing to defrag).
 */
static void
proc_frac (void *cls, const struct GNUNET_MessageHeader *hdr)
{
  struct GNUNET_FRAGMENT_Context **fc = cls;
  int ret;

  GNUNET_FRAGMENT_context_transmission_done (*fc);
  if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, DROPRATE))
  {
    frag_drops++;
    return;                     /* random drop */
  }
  if (NULL == defrag)
  {
    FPRINTF (stderr, "%s",  "E");      /* Error: frag after shutdown!? */
    return;
  }
  ret = GNUNET_DEFRAGMENT_process_fragment (defrag, hdr);
  if (ret == GNUNET_NO)
  {
#if DETAILS
    FPRINTF (stderr, "%s",  "?");      /* duplicate fragment */
#endif
    dups++;
  }
  else if (ret == GNUNET_OK)
  {
#if DETAILS
    FPRINTF (stderr, "%s",  ".");      /* good fragment */
#endif
    fragc++;
  }
}


/**
 * Main function run with scheduler.
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  unsigned int i;
  struct GNUNET_MessageHeader *msg;
  char buf[MTU + 32 * 1024];

  defrag = GNUNET_DEFRAGMENT_context_create (NULL, MTU, NUM_MSGS        /* enough space for all */
                                             , NULL, &proc_msgs, &proc_acks);
  for (i = 0; i < sizeof (buf); i++)
    buf[i] = (char) i;
  msg = (struct GNUNET_MessageHeader *) buf;
  for (i = 0; i < NUM_MSGS; i++)
  {
    msg->type = htons ((uint16_t) i);
    msg->size =
        htons (sizeof (struct GNUNET_MessageHeader) + (17 * i) % (32 * 1024));
    frags[i] = GNUNET_FRAGMENT_context_create (NULL /* no stats */ ,
                                               MTU, &trackers[i],
                                               GNUNET_TIME_UNIT_SECONDS, msg,
                                               &proc_frac, &frags[i]);
  }
}


int
main (int argc, char *argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  char *const argv_prog[] = {
    "test-fragmentation",
    "-c",
    "test_fragmentation_data.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };
  unsigned int i;

  GNUNET_log_setup ("test-fragmentation",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  for (i = 0; i < NUM_MSGS; i++)
    GNUNET_BANDWIDTH_tracker_init (&trackers[i],
                                   GNUNET_BANDWIDTH_value_init ((i + 1) * 1024),
                                   100);
  GNUNET_PROGRAM_run (5, argv_prog, "test-fragmentation", "nohelp", options,
                      &run, NULL);
  FPRINTF (stderr,
           "\nHad %u good fragments, %u duplicate fragments, %u acks and %u simulated drops of acks\n",
           fragc, dups, acks, ack_drops);
  return ret;
}
