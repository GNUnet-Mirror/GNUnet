/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_services.c
 * @brief convenience functions for accessing services
 * @author Christian Grothoff
 */
#include "platform.h"
#include "testbed_api.h"
#include "testbed_api_peers.h"
#include "testbed_api_operations.h"

struct ServiceConnectData
{
  /**
   * helper function callback to establish the connection
   */
  GNUNET_TESTBED_ConnectAdapter ca;

  /**
   * helper function callback to close the connection
   */
  GNUNET_TESTBED_DisconnectAdapter da;

  /**
   * Closure to the above callbacks
   */
  void *cada_cls;

  /**
   * Service name
   */
  char *service_name;
  
  /**
   * Closure for operation event
   */
  void *op_cls;

};


/**
 * Context information for forwarded operation used in service connect
 */
struct SCFOContext
{
  
};



/**
 * Function called when a service connect operation is ready
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void 
opstart_service_connect (void *cls)
{
  GNUNET_break (0);
}


/**
 * Callback which will be called when service connect type operation is
 * released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void 
oprelease_service_connect (void *cls)
{
  GNUNET_break (0); 
}


/**
 * Connect to a service offered by the given peer.  Will ensure that
 * the request is queued to not overwhelm our ability to create and
 * maintain connections with other systems.  The actual service
 * handle is then returned via the 'op_result' member in the event
 * callback.  The 'ca' callback is used to create the connection
 * when the time is right; the 'da' callback will be used to 
 * destroy the connection (upon 'GNUNET_TESTBED_operation_done').
 * 'GNUNET_TESTBED_operation_cancel' can be used to abort this
 * operation until the event callback has been called.
 *
 * @param op_cls closure to pass in operation event
 * @param peer peer that runs the service
 * @param service_name name of the service to connect to
 * @param ca helper function to establish the connection
 * @param da helper function to close the connection
 * @param cada_cls closure for ca and da
 * @return handle for the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_service_connect (void *op_cls,
				struct GNUNET_TESTBED_Peer *peer,
				const char *service_name,
				GNUNET_TESTBED_ConnectAdapter ca,
				GNUNET_TESTBED_DisconnectAdapter da,
				void *cada_cls)
{
  struct OperationContext *opc;
  struct ServiceConnectData *data;

  data = GNUNET_malloc (sizeof (struct ServiceConnectData));
  data->ca = ca;
  data->da = da;
  data->cada_cls = cada_cls;
  data->op_cls = op_cls;  
  opc = GNUNET_malloc (sizeof (struct OperationContext));
  opc->data = data;
  opc->c = peer->controller;
  opc->id = peer->controller->operation_counter++;
  opc->type = OP_SERVICE_CONNECT;
  opc->op = GNUNET_TESTBED_operation_create_ (opc, &opstart_service_connect,
                                              &oprelease_service_connect);
  GNUNET_TESTBED_operation_queue_insert_
    (opc->c->opq_parallel_service_connections, opc->op);
  GNUNET_TESTBED_operation_queue_insert_ (opc->c->opq_parallel_operations,
                                          opc->op);
  return opc->op;
}

/* end of testbed_api_services.c */
