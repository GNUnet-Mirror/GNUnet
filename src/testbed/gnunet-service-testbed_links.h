/*
  This file is part of GNUnet.
  (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed_links.h
 * @brief TESTBED service components that deals with starting slave controllers
 *          and establishing lateral links between controllers
 * @author Sree Harsha Totakura
 */

struct Neighbour;


/**
 * Structure representing a connected(directly-linked) controller
 */
struct Slave
{
  /**
   * The controller process handle if we had started the controller
   */
  struct GNUNET_TESTBED_ControllerProc *controller_proc;

  /**
   * The controller handle
   */
  struct GNUNET_TESTBED_Controller *controller;

  /**
   * handle to lcc which is associated with this slave startup. Should be set to
   * NULL when the slave has successfully started up
   */
  struct LinkControllersContext *lcc;

  /**
   * Head of the host registration DLL
   */
  struct HostRegistration *hr_dll_head;

  /**
   * Tail of the host registration DLL
   */
  struct HostRegistration *hr_dll_tail;

  /**
   * The current host registration handle
   */
  struct GNUNET_TESTBED_HostRegistrationHandle *rhandle;

  /**
   * Hashmap to hold Registered host contexts
   */
  struct GNUNET_CONTAINER_MultiHashMap *reghost_map;

  /**
   * Operation handle for opening a lateral connection to another controller.
   * Will be NULL if the slave controller is started by this controller
   */
  struct GNUNET_TESTBED_Operation *conn_op;

  /**
   * The id of the host this controller is running on
   */
  uint32_t host_id;

};

/**
 * A list of directly linked neighbours
 */
extern struct Slave **GST_slave_list;

/**
 * The size of directly linked neighbours list
 */
extern unsigned int GST_slave_list_size;

void
GST_neighbour_list_clean();

struct Neighbour *
GST_get_neighbour (uint32_t id);

void
GST_free_nccq ();

struct NeighbourConnectNotification;

typedef void (*GST_NeigbourConnectNotifyCallback) (void *cls,
                                                   struct
                                                   GNUNET_TESTBED_Controller
                                                   *controller);

struct NeighbourConnectNotification *
GST_neighbour_get_connection (struct Neighbour *n,
                              GST_NeigbourConnectNotifyCallback cb,
                              void *cb_cls);

void
GST_neighbour_get_connection_cancel (struct NeighbourConnectNotification *h);

void
GST_neighbour_release_connection (struct Neighbour *n);

/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_LCONTROLLERS message
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_link_controllers (void *cls, struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message);


/**
 * Cleans up the slave list
 */
void
GST_slave_list_clear ();
