/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file sensordashboard/gnunet-service-sensordashboard.c
 * @brief Service collecting sensor readings from peers
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_applications.h"
#include "sensordashboard.h"
#include "gnunet_cadet_service.h"

static struct GNUNET_CADET_Handle *cadet;

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != cadet)
  {
    GNUNET_CADET_disconnect(cadet);
    cadet = NULL;
  }
  GNUNET_SCHEDULER_shutdown();
}

/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.
 *
 * It must NOT call #GNUNET_CADET_channel_destroy on the channel.
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void cadet_channel_destroyed (void *cls,
    const struct GNUNET_CADET_Channel *channel,
    void *channel_ctx)
{

}

/**
 * Method called whenever another peer has added us to a channel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in #GNUNET_CADET_connect.
 *
 * A call to #GNUNET_CADET_channel_destroy causes the channel to be ignored. In
 * this case the handler MUST return NULL.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @param port Port this channel is for.
 * @param options CadetOption flag field, with all active option bits set to 1.
 *
 * @return initial channel context for the channel
 *         (can be NULL -- that's not an error)
 */
static void *cadet_channel_created (void *cls,
    struct GNUNET_CADET_Channel *channel,
    const struct GNUNET_PeerIdentity *initiator,
    uint32_t port, enum GNUNET_CADET_ChannelOption options)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "CADET channel opened by remote peer `%s'.\n",
      GNUNET_i2s(initiator));
  return NULL; /* FIXME */
}

/**
 * Process sensordashboard requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {NULL, NULL, 0, 0}
  };
  static struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
      {NULL, 0, 0}
  };
  static uint32_t cadet_ports[] = {
      GNUNET_APPLICATION_TYPE_SENSORDASHBOARD,
      GNUNET_APPLICATION_TYPE_END
  };
  cadet = GNUNET_CADET_connect(cfg,
      NULL,
      &cadet_channel_created,
      &cadet_channel_destroyed,
      cadet_handlers,
      cadet_ports);
  if(NULL == cadet)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        _("Failed to connect to CADET service.\n"));
    GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
    return;
  }
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
}


/**
 * The main function for the sensordashboard service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "sensordashboard",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-sensordashboard.c */
