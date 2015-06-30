/*
     This file is part of GNUnet
     Copyright (C) 2004, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fragmentation/test_fragmentation.c
 * @brief test for fragmentation.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fragmentation_lib.h"

#define DETAILS GNUNET_NO

/**
 * Number of messages to transmit (note: each uses ~32k memory!)
 */
#define NUM_MSGS 1000

/**
 * MTU to force on fragmentation (must be > 1k + 12)
 */
#define MTU 1111

/**
 * Simulate dropping of 1 out of how many messages? (must be > 1)
 */
#define DROPRATE 15

static int ret = 1;

static unsigned int dups;

static unsigned int fragc;

static unsigned int frag_drops;

static unsigned int acks;

static unsigned int ack_drops;

static struct GNUNET_DEFRAGMENT_Context *defrag;

static struct GNUNET_BANDWIDTH_Tracker trackers[NUM_MSGS];

static struct GNUNET_FRAGMENT_Context *frag;

static struct GNUNET_SCHEDULER_Task * shutdown_task;

static struct GNUNET_TIME_Relative msg_delay;

static struct GNUNET_TIME_Relative ack_delay;


static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ret = 0;
  shutdown_task = NULL;
  GNUNET_DEFRAGMENT_context_destroy (defrag);
  defrag = NULL;
  if (NULL != frag)
  {
    GNUNET_FRAGMENT_context_destroy (frag, &msg_delay, &ack_delay);
    frag = NULL;
  }
  fprintf (stderr,
           "\nFinal message-delay: %s\n",
           GNUNET_STRINGS_relative_time_to_string (msg_delay,
                                                   GNUNET_YES));
  fprintf (stderr,
           "Final ack-delay: %s\n",
           GNUNET_STRINGS_relative_time_to_string (ack_delay,
                                                   GNUNET_YES));
}


static void
proc_msgs (void *cls, const struct GNUNET_MessageHeader *hdr)
{
  static unsigned int total;
  unsigned int i;
  const char *buf;

#if DETAILS
  FPRINTF (stderr, "%s",  "M! ");        /* message complete, good! */
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
    if (NULL == shutdown_task)
      shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  }
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
#if DETAILS
    FPRINTF (stderr, "%s",  "DF ");    /* dropped Frag */
#endif
    return;                     /* random drop */
  }
  if (NULL == defrag)
  {
    FPRINTF (stderr, "%s",  "?E ");      /* Error: frag after shutdown!? */
    return;
  }
  ret = GNUNET_DEFRAGMENT_process_fragment (defrag, hdr);
  if (ret == GNUNET_NO)
  {
#if DETAILS
    FPRINTF (stderr, "%s",  "FF ");      /* duplicate fragment */
#endif
    dups++;
  }
  else if (ret == GNUNET_OK)
  {
#if DETAILS
    FPRINTF (stderr, "%s",  "F! ");      /* good fragment */
#endif
    fragc++;
  }
}


static void
next_transmission ()
{
  static unsigned int i;
  struct GNUNET_MessageHeader *msg;
  static char buf[MTU + 32 * 1024];
  unsigned int j;

  if (0 == i)
  {
    for (j = 0; j < sizeof (buf); j++)
      buf[j] = (char) j;
  }
  else
  {
    GNUNET_FRAGMENT_context_destroy (frag,
                                     &msg_delay,
                                     &ack_delay);
    frag = NULL;
  }
  if (i == NUM_MSGS)
    return;
#if DETAILS
  FPRINTF (stderr, "%s",  "T! ");        /* sending message */
#endif
  msg = (struct GNUNET_MessageHeader *) buf;
  msg->type = htons ((uint16_t) i);
  msg->size =
    htons (sizeof (struct GNUNET_MessageHeader) + (17 * i) % (32 * 1024));
  frag = GNUNET_FRAGMENT_context_create (NULL /* no stats */ ,
                                         MTU, &trackers[i],
                                         msg_delay,
                                         ack_delay,
                                         msg,
                                         &proc_frac, &frag);
  i++;
}


/**
 * Process ACK (by passing to fragmenter)
 */
static void
proc_acks (void *cls,
           uint32_t msg_id,
           const struct GNUNET_MessageHeader *hdr)
{
  unsigned int i;
  int ret;

  if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, DROPRATE))
  {
    ack_drops++;
#if DETAILS
    FPRINTF (stderr, "%s",  "DA ");    /* dropped ACK */
#endif
    return;                     /* random drop */
  }
  for (i = 0; i < NUM_MSGS; i++)
  {
    if (NULL == frag)
      continue;
    ret = GNUNET_FRAGMENT_process_ack (frag, hdr);
    if (ret == GNUNET_OK)
    {
#if DETAILS
      FPRINTF (stderr, "%s",  "GA ");    /* good ACK */
#endif
      next_transmission ();
      acks++;
      return;
    }
    if (ret == GNUNET_NO)
    {
#if DETAILS
      FPRINTF (stderr, "%s",  "AA ");    /* duplciate ACK */
#endif
      acks++;
      return;
    }
  }
#if DETAILS
  FPRINTF (stderr, "%s",  "?A ");        /* BAD: ack that nobody feels responsible for... */
#endif
}


/**
 * Main function run with scheduler.
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  defrag = GNUNET_DEFRAGMENT_context_create (NULL, MTU,
                                             3,
                                             NULL,
                                             &proc_msgs,
                                             &proc_acks);
  next_transmission ();
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
    "WARNING",
    NULL
  };
  unsigned int i;

  msg_delay = GNUNET_TIME_UNIT_MILLISECONDS;
  ack_delay = GNUNET_TIME_UNIT_SECONDS;
  GNUNET_log_setup ("test-fragmentation",
                    "WARNING",
                    NULL);
  for (i = 0; i < NUM_MSGS; i++)
    GNUNET_BANDWIDTH_tracker_init (&trackers[i], NULL, NULL,
                                   GNUNET_BANDWIDTH_value_init ((i + 1) * 1024),
                                   100);
  GNUNET_PROGRAM_run (5,
                      argv_prog,
                      "test-fragmentation", "nohelp",
                      options,
                      &run, NULL);
  FPRINTF (stderr,
           "\nHad %u good fragments, %u duplicate fragments, %u acks and %u simulated drops of acks\n",
           fragc,
           dups,
           acks,
           ack_drops);
  return ret;
}
