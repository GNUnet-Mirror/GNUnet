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
 * @file vpn/gnunet-helper-vpn-api.h
 * @brief exposes the API (the convenience-functions) of dealing with the
 *        helper-vpn
 * @author Philipp Toelke
 */
#ifndef GNUNET_HELPER_VPN_API_H
#define GNUNET_HELPER_VPN_API_H

/**
 * The handle to a helper.
 * sometimes a few entries may be made opaque.
 */
struct GNUNET_VPN_HELPER_Handle
{
/**
 * PipeHandle to receive data from the helper
 */
  struct GNUNET_DISK_PipeHandle *helper_in;

/**
 * PipeHandle to send data to the helper
 */
  struct GNUNET_DISK_PipeHandle *helper_out;

/**
 * FileHandle to receive data from the helper
 */
  const struct GNUNET_DISK_FileHandle *fh_from_helper;

/**
 * FileHandle to send data to the helper
 */
  const struct GNUNET_DISK_FileHandle *fh_to_helper;

  /**
   * The process id of the helper
   */
  struct GNUNET_OS_Process *helper_proc;

  /**
   * The Message-Tokenizer that tokenizes the messages comming from the helper
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  /**
   * The client-identifier passed to the mst-callback
   */
  void *client;

  /**
   * The name of the interface
   */
  char *ifname;

  /**
   * The task called when the helper dies.
   * Will be called with the handle as cls
   */
  GNUNET_SCHEDULER_Task restart_task;
};

/**
 * @brief Starts a helper and begins reading from it
 *
 * @param ifname The name of the new interface
 * @param ipv6addr The IPv6 address of the new interface
 * @param ipv6prefix The IPv6 prefix length of the new IP
 * @param ipv4addr The IPv4 address of the new interface
 * @param ipv4mask The associated netmask
 * @param process_name How the helper should appear in process-listings
 * @param restart_task The task called when the helper dies. Will be called with the handle as cls
 * @param cb A callback for messages from the helper
 * @param cb_cls Closure for the callback
 *
 * @return A pointer to the new Handle, NULL on error
 */
struct GNUNET_VPN_HELPER_Handle *start_helper (const char *ifname,
                                               const char *ipv6addr,
                                               const char *ipv6prefix,
                                               const char *ipv4addr,
                                               const char *ipv4mask,
                                               const char *process_name,
                                               GNUNET_SCHEDULER_Task
                                               restart_task,
                                               GNUNET_SERVER_MessageTokenizerCallback
                                               cb, void *cb_cls);

/**
 * @brief Kills the helper, closes the pipe and free()s the handle
 */
void cleanup_helper (struct GNUNET_VPN_HELPER_Handle *);

#endif /* end of include guard: GNUNET_HELPER_VPN_API_H */
