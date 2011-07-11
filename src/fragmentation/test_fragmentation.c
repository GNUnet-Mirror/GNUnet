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

#define NUM_MSGS 1

#define MTU 1111

static int ret = 1; 

static struct GNUNET_DEFRAGMENT_Context *defrag;

static struct GNUNET_FRAGMENT_Context *frags[NUM_MSGS];

static void
proc_msgs (void *cls,
	   const struct GNUNET_MessageHeader *hdr)
{
  static unsigned int total;

  fprintf (stderr, "!");
  total++;
  if (total == NUM_MSGS)
    {
      ret = 0;
      GNUNET_DEFRAGMENT_context_destroy (defrag);
      defrag = NULL;
    }
}

/**
 * Process ACK (by passing to fragmenter)
 */
static void
proc_acks (void *cls,
	   const struct GNUNET_MessageHeader *hdr)
{
  unsigned int i;
  int ret;

  fprintf (stderr, "@");
  for (i=0;i<NUM_MSGS;i++)
    {
      if (frags[i] == NULL)
	return;     
      ret = GNUNET_FRAGMENT_process_ack (frags[i],
					 hdr);
      if (ret == GNUNET_OK)
	{
	  GNUNET_FRAGMENT_context_destroy (frags[i]);
	  frags[i] = NULL;
	  return;
	}
      if (ret == GNUNET_NO)
	return;
    }
  fprintf (stderr, "Got ACK that nobody feels responsible for...\n");
}


/**
 * Process fragment (by passing to defrag).
 */
static void
proc_frac (void *cls,
	   const struct GNUNET_MessageHeader *hdr)
{
  fprintf (stderr, ".");
  if (NULL == defrag)
    return;
  GNUNET_DEFRAGMENT_process_fragment (defrag, hdr);
}


/**
 * Main function run with scheduler.
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  unsigned int i;
  struct GNUNET_MessageHeader *msg;
  char buf[MTU + 32 * 1024];

  defrag = GNUNET_DEFRAGMENT_context_create (NULL,
					     MTU,
					     NUM_MSGS /* enough space for all */,
					     NULL,
					     &proc_msgs,
					     &proc_acks);
  for (i=0;i<sizeof(buf);i++)
    buf[i] = (char) i;
  msg = (struct GNUNET_MessageHeader* ) buf;
  for (i=0;i<NUM_MSGS;i++)
    {
      msg->type = htons ((uint16_t) i);
      msg->size = htons (MTU + 1 + i % (32 * 1024));
      frags[i] = GNUNET_FRAGMENT_context_create (NULL /* no stats */, 
						 MTU,
						 NULL /* no tracker -- infinite BW */,
						 GNUNET_TIME_UNIT_MILLISECONDS,
						 msg,
						 &proc_frac,
						 NULL);
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

  GNUNET_log_setup ("test-fragmentation",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  GNUNET_PROGRAM_run (5, argv_prog, "test-fragmentation", "nohelp", options, &run, NULL);
  return ret;
}
