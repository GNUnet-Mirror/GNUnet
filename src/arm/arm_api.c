/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file arm/arm_api.c
 * @brief API for accessing the ARM service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "arm.h"


struct ArmContext
{
  GNUNET_ARM_Callback callback;
  void *cls;
  char *service_name;
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_TIME_Absolute timeout;
  uint16_t type;
};


static void
arm_service_report (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ArmContext *pos = cls;
  pid_t pid;
  char *binary;
  char *config;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
    {
      if (pos->callback != NULL)
        pos->callback (pos->cls, GNUNET_YES);
      GNUNET_free (pos);
      return;
    }
  binary = NULL;
  config = NULL;
  /* start service */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_filename (pos->cfg,
                                                "arm",
                                                "BINARY",
                                                &binary)) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_filename (pos->cfg,
                                                "arm", "CONFIG", &config)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Configuration file or binary for ARM not known!\n"));
      if (pos->callback != NULL)
        pos->callback (pos->cls, GNUNET_SYSERR);
      GNUNET_free_non_null (binary);
      GNUNET_free (pos);
      return;
    }
  pid = GNUNET_OS_start_process (binary, binary, "-d", "-c", config,
#if DEBUG_ARM
                                 "-L", "DEBUG",
#endif
                                 NULL);
  GNUNET_free (binary);
  GNUNET_free (config);
  if (pid == -1)
    {
      if (pos->callback != NULL)
        pos->callback (pos->cls, GNUNET_SYSERR);
      GNUNET_free (pos);
      return;
    }
  /* FIXME: consider checking again to see if it worked!? */
  if (pos->callback != NULL)
    pos->callback (pos->cls, GNUNET_YES);
  GNUNET_free (pos);
}


static void
handle_response (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct ArmContext *sc = cls;
  int ret;

  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Error receiving response from ARM service\n"));
      GNUNET_CLIENT_disconnect (sc->client);
      if (sc->callback != NULL)
        sc->callback (sc->cls, GNUNET_SYSERR);
      GNUNET_free (sc);
      return;
    }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Received response from ARM service\n"));
#endif
  switch (ntohs (msg->type))
    {
    case GNUNET_MESSAGE_TYPE_ARM_IS_UP:
      ret = GNUNET_YES;
      break;
    case GNUNET_MESSAGE_TYPE_ARM_IS_DOWN:
      ret = GNUNET_NO;
      break;
    case GNUNET_MESSAGE_TYPE_ARM_IS_UNKNOWN:
      ret = GNUNET_SYSERR;
      break;
    default:
      GNUNET_break (0);
      ret = GNUNET_SYSERR;
    }
  GNUNET_CLIENT_disconnect (sc->client);
  if (sc->callback != NULL)
    sc->callback (sc->cls, ret);
  GNUNET_free (sc);
}


static size_t
send_service_msg (void *cls, size_t size, void *buf)
{
  struct ArmContext *sctx = cls;
  struct GNUNET_MessageHeader *msg;
  size_t slen;

  if (buf == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Error while trying to transmit to ARM service\n"));
      GNUNET_CLIENT_disconnect (sctx->client);
      if (sctx->callback != NULL)
        sctx->callback (sctx->cls, GNUNET_SYSERR);
      GNUNET_free (sctx->service_name);
      GNUNET_free (sctx);
      return 0;
    }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Transmitting service request to ARM.\n"));
#endif
  slen = strlen (sctx->service_name) + 1;
  GNUNET_assert (size >= slen);
  msg = buf;
  msg->size = htons (sizeof (struct GNUNET_MessageHeader) + slen);
  msg->type = htons (sctx->type);
  memcpy (&msg[1], sctx->service_name, slen);
  GNUNET_free (sctx->service_name);
  sctx->service_name = NULL;
  GNUNET_CLIENT_receive (sctx->client,
                         &handle_response,
                         sctx,
                         GNUNET_TIME_absolute_get_remaining (sctx->timeout));
  return slen + sizeof (struct GNUNET_MessageHeader);
}


/**
 * Start or stop a service.
 *
 * @param service_name name of the service
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param sched scheduler to use
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
static void
change_service (const char *service_name,
                struct GNUNET_CONFIGURATION_Handle *cfg,
                struct GNUNET_SCHEDULER_Handle *sched,
                struct GNUNET_TIME_Relative timeout,
                GNUNET_ARM_Callback cb, void *cb_cls, uint16_t type)
{
  struct GNUNET_CLIENT_Connection *client;
  struct ArmContext *sctx;
  size_t slen;

  slen = strlen (service_name) + 1;
  if (slen + sizeof (struct GNUNET_MessageHeader) >
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      if (cb != NULL)
        cb (cb_cls, GNUNET_NO);
      return;
    }
  client = GNUNET_CLIENT_connect (sched, "arm", cfg);
  if (client == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to connect to ARM service\n"));
      if (cb != NULL)
        cb (cb_cls, GNUNET_SYSERR);
      return;
    }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("ARM requests starting of service `%s'.\n"), service_name);
#endif
  sctx = GNUNET_malloc (sizeof (struct ArmContext));
  sctx->callback = cb;
  sctx->cls = cb_cls;
  sctx->client = client;
  sctx->service_name = GNUNET_strdup (service_name);
  sctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  sctx->type = type;
  if (NULL ==
      GNUNET_CLIENT_notify_transmit_ready (client,
                                           slen +
                                           sizeof (struct
                                                   GNUNET_MessageHeader),
                                           timeout, &send_service_msg, sctx))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to transmit request to ARM service\n"));
      GNUNET_free (sctx->service_name);
      GNUNET_free (sctx);
      if (cb != NULL)
        cb (cb_cls, GNUNET_SYSERR);
      GNUNET_CLIENT_disconnect (client);
      return;
    }
}


/**
 * Start a service.
 *
 * @param service_name name of the service
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param sched scheduler to use
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
void
GNUNET_ARM_start_service (const char *service_name,
                          struct GNUNET_CONFIGURATION_Handle *cfg,
                          struct GNUNET_SCHEDULER_Handle *sched,
                          struct GNUNET_TIME_Relative timeout,
                          GNUNET_ARM_Callback cb, void *cb_cls)
{
  struct ArmContext *sctx;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Starting service `%s'\n"), service_name);
  if (0 == strcmp ("arm", service_name))
    {
      sctx = GNUNET_malloc (sizeof (struct ArmContext));
      sctx->callback = cb;
      sctx->cls = cb_cls;
      sctx->cfg = cfg;
      GNUNET_CLIENT_service_test (sched,
                                  "arm",
                                  cfg, timeout, &arm_service_report, sctx);
      return;
    }
  change_service (service_name,
                  cfg,
                  sched, timeout, cb, cb_cls, GNUNET_MESSAGE_TYPE_ARM_START);
}




/**
 * Stop a service.
 *
 * @param service_name name of the service
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param sched scheduler to use
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
void
GNUNET_ARM_stop_service (const char *service_name,
                         struct GNUNET_CONFIGURATION_Handle *cfg,
                         struct GNUNET_SCHEDULER_Handle *sched,
                         struct GNUNET_TIME_Relative timeout,
                         GNUNET_ARM_Callback cb, void *cb_cls)
{
  struct GNUNET_CLIENT_Connection *client;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Stopping service `%s'\n"), service_name);
  if (0 == strcmp ("arm", service_name))
    {
      client = GNUNET_CLIENT_connect (sched, "arm", cfg);
      if (client == NULL)
        {
          if (cb != NULL)
            cb (cb_cls, GNUNET_SYSERR);
          return;
        }
      GNUNET_CLIENT_service_shutdown (client);
      GNUNET_CLIENT_disconnect (client);
      if (cb != NULL)
        cb (cb_cls, GNUNET_NO);
      return;
    }
  change_service (service_name,
                  cfg,
                  sched, timeout, cb, cb_cls, GNUNET_MESSAGE_TYPE_ARM_STOP);
}

/* end of arm_api.c */
