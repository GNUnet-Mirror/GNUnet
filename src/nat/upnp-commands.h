/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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

/*
 * Code in this file is originally based on the miniupnp library.
 * Copyright (c) 2005-2009, Thomas BERNARD. All rights reserved.
 *
 * Original licence:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * The name of the author may not be used to endorse or promote products
 * 	   derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file nat/upnp-commands.h
 * @brief Commands to control UPnP IGD devices
 *
 * @author Milan Bouchet-Valat
 */
#ifndef UPNP_COMMANDS_H
#define UPNP_COMMANDS_H

#include "platform.h"
#include "gnunet_scheduler_lib.h"

/**
 * Generic UPnP error codes.
 */
#define UPNP_COMMAND_SUCCESS (0)
#define UPNP_COMMAND_UNKNOWN_ERROR (-1)
#define UPNP_COMMAND_INVALID_ARGS (-2)

/**
 * Size of the buffer used to store anwsers to UPnP commands.
 */
#define UPNP_COMMAND_BUFSIZE 4096

/**
 * Name-value pair containing an argumeny to a UPnP command.
 */
struct UPNP_Arg_
{
  const char *elt;
  const char *val;
};

/**
 * Callback for UPNP_command_().
 *
 * @param response the buffer passed to UPNP_command_(), filled with
 *   NULL-terminated content (if any)
 * @param received length of the content received and stored in response
 * @param cls closure passed to UPNP_command_()
 */
typedef void (*UPNP_command_cb_) (char *response, size_t received, void *cls);

/**
 * Send UPnP command to the device identified by url and service.
 * 
 * @param url control URL of the device
 * @param service type of the service corresponding to the command
 * @param action action to send
 * @param args arguments for action
 * @param buffer buffer
 * @param buf_size buffer size
 * @param caller_cb user callback to trigger when done
 * @param caller_cls closure to pass to caller_cb
 */
void UPNP_command_ (const char *url, const char *service,
                    const char *action, struct UPNP_Arg_ *args,
                    char *buffer, size_t buf_size,
                    UPNP_command_cb_ caller_cb, void *caller_cls);

/**
 * Callback to UPNP_get_external_ip_address_().
 *
 * Possible UPnP Errors :
 * 402 Invalid Args - See UPnP Device Architecture section on Control.
 * 501 Action Failed - See UPnP Device Architecture section on Control.
 *
 * @param error GNUNET_OK on success, another value on error (see above)
 * @param ext_ip_addr the external IP address reported by the device (IPv4 or v6)
 * @param cls the closure passed to UPNP_get_external_ip_address_()
 */
typedef void (*UPNP_get_external_ip_address_cb_) (int error,
                                                  char *ext_ip_addr,
                                                  void *cls);

/**
 * Get the IP address associated with the WAN connection of the device.
 * See UPNP_get_external_ip_address_cb_.
 *
 * @param control_url the control URL corresponding to service_type on the device
 * @param service_type service type to call the command on
 * @param caller_cb function to call when done
 * @param caller_cls closure passed to caller_cb
 */
void
UPNP_get_external_ip_address_ (const char *control_url,
                               const char *service_type,
                               UPNP_get_external_ip_address_cb_ caller_cb,
                               void *caller_cls);

/**
 * Callback to UPNP_add_port_mapping_() and UPNP_delete_port_mapping_().
 *
 * Possible UPnP Errors with UPNP_add_port_mapping_():
 * 402 Invalid Args - See UPnP Device Architecture section on Control.
 * 501 Action Failed - See UPnP Device Architecture section on Control.
 * 715 WildCardNotPermittedInSrcIP - The source IP address cannot be
 *                                   wild-carded
 * 716 WildCardNotPermittedInext_port - The external port cannot be wild-carded
 * 718 ConflictInMappingEntry - The port mapping entry specified conflicts
 *                     with a mapping assigned previously to another client
 * 724 SamePortValuesRequired - Internal and External port values
 *                              must be the same 
 * 725 OnlyPermanentLeasesSupported - The NAT implementation only supports
 *                  permanent lease times on port mappings
 * 726 RemoteHostOnlySupportsWildcard - RemoteHost must be a wildcard
 *                             and cannot be a specific IP address or DNS name
 * 727 ExternalPortOnlySupportsWildcard - ExternalPort must be a wildcard and
 *                                        cannot be a specific port value
 * 
 * Possible UPnP Errors with UPNP_delete_port_mapping_():
 * 402 Invalid Args - See UPnP Device Architecture section on Control.
 * 714 NoSuchEntryInArray - The specified value does not exist in the array 
 *
 * @param error GNUNET_OK on success, another value on error (see above)
 * @param control_url the control URL the command was called on
 * @param service_type service the command was called on
 * @param ext_port external port
 * @param inPort port on the gateway on the LAN side which was requested
 * @param proto protocol for which port mapping was requested
 * @param remote_host remote host for which port mapping was requested
 * @param cls the closure passed to the command function
 */
typedef void (*UPNP_port_mapping_cb_) (int error,
                                       const char *control_url,
                                       const char *service_type,
                                       const char *ext_port,
                                       const char *inPort, const char *proto,
                                       const char *remote_host, void *cls);


/**
 * Request opening a port on the IGD device.
 * (remote_host is usually NULL because IGDs don't support it.)
 *
 * @param control_url the control URL corresponding to service_type on the device
 * @param service_type service type to call the command on
 * @param ext_port port that should be opened on the WAN side
 * @param in_port port on the gateway on the LAN side which should map ext_port
 * @param in_client address in the LAN to which packets should be redirected
 * @param desc description
 * @param proto protocol for which to request port mapping
 * @param remote_host remote host for which to request port mapping
 * @param caller_cb function to call when done
 * @param caller_cls closure passed to caller_cb
 */
void
UPNP_add_port_mapping_ (const char *control_url, const char *service_type,
                        const char *ext_port,
                        const char *in_port,
                        const char *in_client,
                        const char *desc,
                        const char *proto, const char *remote_host,
                        UPNP_port_mapping_cb_ caller_cb, void *caller_cls);

/**
 * Request closing a a port on the IGD device that was previously opened
 * using UPNP_add_port_mapping_(). Use the same argument values that were
 * used when opening the port.
 * (remote_host is usually NULL because IGDs don't support it.)
 *
 * @param control_url the control URL the command was called on
 * @param service_type service the command was called on
 * @param ext_port external port
 * @param proto protocol for which port mapping was requested
 * @param remote_host remote host for which port mapping was requested
 * @param caller_cb function to call when done
 * @param cls closure passed to caller_cb
 */
void
UPNP_delete_port_mapping_ (const char *control_url, const char *service_type,
                           const char *ext_port, const char *proto,
                           const char *remote_host,
                           UPNP_port_mapping_cb_ caller_cb, void *caller_cls);


/**
 * Callback to UPNP_get_specific_port_mapping_entry _().
 *
 * @param error GNUNET_OK if port is currently mapped, another value on error
 * @param control_url the control URL the command was called on
 * @param service_type service the command was called on
 * @param ext_port external port
 * @param proto protocol for which port mapping was requested
 * @param in_port port on the gateway on the LAN side which was requested
 * @param in_client address in the LAN which was requested
 * @param cls the closure passed to the command function
 */
typedef void (*UPNP_get_specific_port_mapping_entry_cb_) (int error,
                                                          const char
                                                          *control_url,
                                                          const char
                                                          *service_type,
                                                          const char
                                                          *ext_port,
                                                          const char *proto,
                                                          const char *in_port,
                                                          const char
                                                          *in_client,
                                                          void *cls);

/**
 * Check that a port mapping set up with UPNP_add_port_mapping_()
 * is alive.
 *
 * @param control_url the control URL the command was called on
 * @param service_type service the command was called on
 * @param ext_port external port
 * @param proto protocol for which port mapping was requested
 * @param caller_cb function to call when done
 * @param callers_cls closure passed to caller_cb
 */
void
UPNP_get_specific_port_mapping_entry_ (const char *control_url,
                                       const char *service_type,
                                       const char *ext_port,
                                       const char *proto,
                                       UPNP_get_specific_port_mapping_entry_cb_
                                       caller_cb, void *caller_cls);

#endif
