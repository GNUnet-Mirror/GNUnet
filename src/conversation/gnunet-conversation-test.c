/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file conversation/gnunet-conversation-test.c
 * @brief tool to test speaker and microphone (for end users!)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_speaker_lib.h"
#include "gnunet_microphone_lib.h"

/**
 * How long do we record before we replay?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * A recording we made.
 */
struct Recording
{
  /**
   * Kept in a DLL.
   */
  struct Recording *next;

  /**
   * Kept in a DLL.
   */
  struct Recording *prev;

  /**
   * Number of bytes that follow.
   */
  size_t size;
};


/**
 * Final status code.
 */
static int ret;

/**
 * Handle to the microphone.
 */
static struct GNUNET_MICROPHONE_Handle *microphone;

/**
 * Handle to the speaker.
 */
static struct GNUNET_SPEAKER_Handle *speaker;

/**
 * Task scheduled to switch from recording to playback.
 */
static struct GNUNET_SCHEDULER_Task * switch_task;

/**
 * The shutdown task.
 */
static struct GNUNET_SCHEDULER_Task * st;

/**
 * Head of DLL with recorded frames.
 */
static struct Recording *rec_head;

/**
 * Tail of DLL with recorded frames.
 */
static struct Recording *rec_tail;


/**
 * Terminate test.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
do_shutdown (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Recording *rec;

  if (NULL != switch_task)
    GNUNET_SCHEDULER_cancel (switch_task);
  if (NULL != microphone)
    GNUNET_MICROPHONE_destroy (microphone);
  if (NULL != speaker)
    GNUNET_SPEAKER_destroy (speaker);
  while (NULL != (rec = rec_head))
  {
    GNUNET_CONTAINER_DLL_remove (rec_head,
				 rec_tail,
				 rec);
    GNUNET_free (rec);
  }
  fprintf (stderr,
	   _("\nEnd of transmission.  Have a GNU day.\n"));
}


/**
 * Terminate recording process and switch to playback.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
switch_to_speaker (void *cls,
		   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Recording *rec;

  switch_task = NULL;
  microphone->disable_microphone (microphone->cls);
  if (GNUNET_OK !=
      speaker->enable_speaker (speaker->cls))
  {
    fprintf (stderr,
	     "Failed to enable microphone\n");
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  fprintf (stderr,
	   _("\nWe are now playing your recording back.  If you can hear it, your audio settings are working..."));
  for (rec=rec_head; NULL != rec; rec = rec->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Replaying %u bytes\n",
		(unsigned int) rec->size);
    speaker->play (speaker->cls,
		   rec->size,
		   &rec[1]);
  }
  GNUNET_SCHEDULER_cancel (st);
  st = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
				     &do_shutdown,
				     NULL);
}


/**
 * Process recorded audio data.
 *
 * @param cls clsoure
 * @param data_size number of bytes in @a data
 * @param data audio data to play
 */
static void
record (void *cls,
	size_t data_size,
	const void *data)
{
  struct Recording *rec;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Recorded %u bytes\n",
	      (unsigned int) data_size);
  rec = GNUNET_malloc (sizeof (struct Recording) + data_size);
  rec->size = data_size;
  memcpy (&rec[1], data, data_size);
  GNUNET_CONTAINER_DLL_insert_tail (rec_head,
				    rec_tail,
				    rec);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  microphone = GNUNET_MICROPHONE_create_from_hardware (cfg);
  GNUNET_assert (NULL != microphone);
  speaker = GNUNET_SPEAKER_create_from_hardware (cfg);
  GNUNET_assert (NULL != speaker);
  switch_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
					      &switch_to_speaker,
					      NULL);
  st = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				     &do_shutdown,
				     NULL);
  fprintf (stderr,
	   _("We will now be recording you for %s. After that time, the recording will be played back to you..."),
	   GNUNET_STRINGS_relative_time_to_string (TIMEOUT, GNUNET_YES));
  if (GNUNET_OK !=
      microphone->enable_microphone (microphone->cls,
				     &record, NULL))
  {
    fprintf (stderr,
	     "Failed to enable microphone\n");
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * The main function of our code to test microphone and speaker.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc, argv, "gnunet-conversation-test",
			     gettext_noop ("help text"), options, &run,
			     NULL)) ? ret : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-conversation-test.c */
