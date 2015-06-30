/*
  This file is part of GNUnet.
  Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed_links.h
 * @brief TESTBED service components that deals with starting slave controllers
 *          and establishing lateral links between controllers
 * @author Sree Harsha Totakura
 */


/**
 * A connected controller which is not our child
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


/**
 * Cleans up the neighbour list
 */
void
GST_neighbour_list_clean();


/**
 * Get a neighbour from the neighbour list
 *
 * @param id the index of the neighbour in the neighbour list
 * @return the Neighbour; NULL if the given index in invalid (index greater than
 *           the list size or neighbour at that index is NULL)
 */
struct Neighbour *
GST_get_neighbour (uint32_t id);


/**
 * Function to cleanup the neighbour connect contexts
 */
void
GST_free_nccq ();


/**
 * Notification context to be used to notify when connection to the neighbour's
 * controller is opened
 */
struct NeighbourConnectNotification;


/**
 * The notification callback to call when we are connect to neighbour
 *
 * @param cls the closure given to GST_neighbour_get_connection()
 * @param controller the controller handle to the neighbour
 */
typedef void (*GST_NeigbourConnectNotifyCallback) (void *cls,
                                                   struct
                                                   GNUNET_TESTBED_Controller
                                                   *controller);


/**
 * Try to open a connection to the given neigbour.  If the connection is open
 * already, then it is re-used.  If not, the request is queued in the operation
 * queues responsible for bounding the total number of file descriptors.  The
 * actual connection will happen when the operation queue marks the
 * corresponding operation as active.
 *
 * @param n the neighbour to open a connection to
 * @param cb the notification callback to call when the connection is opened
 * @param cb_cls the closure for the above callback
 */
struct NeighbourConnectNotification *
GST_neighbour_get_connection (struct Neighbour *n,
                              GST_NeigbourConnectNotifyCallback cb,
                              void *cb_cls);


/**
 * Cancel the request for opening a connection to the neighbour
 *
 * @param h the notification handle
 */
void
GST_neighbour_get_connection_cancel (struct NeighbourConnectNotification *h);


/**
 * Release the connection to the neighbour.  The actual connection will be
 * closed if connections to other neighbour are waiting (to maintain a bound on
 * the total number of connections that are open).
 *
 * @param n the neighbour whose connection can be closed
 */
void
GST_neighbour_release_connection (struct Neighbour *n);


/**
 * Function to create a neigbour and add it into the neighbour list
 *
 * @param host the host of the neighbour
 */
struct Neighbour *
GST_create_neighbour (struct GNUNET_TESTBED_Host *host);


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
