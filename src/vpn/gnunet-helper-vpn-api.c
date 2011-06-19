/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff

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
 * @file vpn/gnunet-helper-vpn-api.c
 * @brief exposes the API (the convenience-functions) of dealing with the
 *        helper-vpn
 * @author Philipp Toelke
 */

#include <platform.h>
#include <gnunet_common.h>
#include <gnunet_server_lib.h>
#include <gnunet_os_lib.h>

#include "gnunet-helper-vpn-api.h"

static void
stop_helper (struct GNUNET_VPN_HELPER_Handle *handle)
{
  if (NULL == handle->helper_proc)
    return;
  GNUNET_OS_process_kill (handle->helper_proc, SIGKILL);
  GNUNET_OS_process_wait (handle->helper_proc);
  GNUNET_OS_process_close (handle->helper_proc);
  handle->helper_proc = NULL;

  GNUNET_DISK_pipe_close (handle->helper_in);
  GNUNET_DISK_pipe_close (handle->helper_out);

  GNUNET_SERVER_mst_destroy(handle->mst);
}

extern GNUNET_SCHEDULER_TaskIdentifier shs_task;

/**
 * Read from the helper-process
 */
static void
helper_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tsdkctx)
{
  struct GNUNET_VPN_HELPER_Handle *handle = cls;
  /* no message can be bigger then 64k */
  char buf[65535];

  if (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  int t = GNUNET_DISK_file_read (handle->fh_from_helper, &buf, 65535);

  /* On read-error, restart the helper */
  if (t <= 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Read error for header from vpn-helper: %m\n");
      stop_helper (handle);

      /* Restart the helper */
      shs_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    handle->restart_task, handle);
      return;
    }

  if (GNUNET_SYSERR ==
      GNUNET_SERVER_mst_receive (handle->mst, handle->client, buf, t, 0, 0))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "SYSERR from mst\n");
      stop_helper (handle);

      /* Restart the helper */
      shs_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    handle->restart_task, handle);
      return;

    }

  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                  handle->fh_from_helper, &helper_read,
                                  handle);
}

void
cleanup_helper (struct GNUNET_VPN_HELPER_Handle *handle)
{
  stop_helper (handle);
  GNUNET_free (handle);
}

struct GNUNET_VPN_HELPER_Handle *
start_helper (const char *ifname,
              const char *ipv6addr,
              const char *ipv6prefix,
              const char *ipv4addr,
              const char *ipv4mask, const char *process_name,
              GNUNET_SCHEDULER_Task restart_task,
              GNUNET_SERVER_MessageTokenizerCallback cb, void *cb_cls)
{
  struct GNUNET_VPN_HELPER_Handle *handle =
    GNUNET_malloc (sizeof (struct GNUNET_VPN_HELPER_Handle));

  handle->helper_in = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO);
  handle->helper_out = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_NO, GNUNET_YES);

  handle->restart_task = restart_task;

  if (handle->helper_in == NULL || handle->helper_out == NULL)
    {
      GNUNET_free (handle);
      return NULL;
    }

  handle->helper_proc =
    GNUNET_OS_start_process (handle->helper_in, handle->helper_out,
                             "gnunet-helper-vpn", process_name, ifname,
                             ipv6addr, ipv6prefix, ipv4addr, ipv4mask, NULL);

  handle->fh_from_helper =
    GNUNET_DISK_pipe_handle (handle->helper_out, GNUNET_DISK_PIPE_END_READ);
  handle->fh_to_helper =
    GNUNET_DISK_pipe_handle (handle->helper_in, GNUNET_DISK_PIPE_END_WRITE);

  GNUNET_DISK_pipe_close_end (handle->helper_out, GNUNET_DISK_PIPE_END_WRITE);
  GNUNET_DISK_pipe_close_end (handle->helper_in, GNUNET_DISK_PIPE_END_READ);

  handle->mst = GNUNET_SERVER_mst_create (cb, cb_cls);

  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                  handle->fh_from_helper, &helper_read,
                                  handle);

  return handle;
}
