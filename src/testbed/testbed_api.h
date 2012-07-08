/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api.h
 * @brief Interface for functions internally exported from testbed_api.c
 * @author Sree Harsha Totakura
 */

#ifndef TESTBED_API_H
#define TESTBED_API_H


/**
 * Enumeration of operations
 */
enum OperationType
  {
    /**
     * Peer destroy operation
     */
    OP_PEER_DESTROY
  };


/**
 * The counter for generating unique operation ids. Use its current value and
 * increment it (defined in testbed_api.c)
 */
extern uint64_t GNUNET_TESTBED_operation_id;

/**
 * Testbed operation structure
 */
struct GNUNET_TESTBED_Operation
{
  /**
   * next pointer for DLL
   */
  struct GNUNET_TESTBED_Operation *next;

  /**
   * prev pointer for DLL
   */
  struct GNUNET_TESTBED_Operation *prev;

  /**
   * The ID for the operation;
   */
  uint64_t operation_id;

  /**
   * The type of operation
   */
  enum OperationType type;

  /**
   * Data specific to OperationType
   */
  void *data;
};


/**
 * Queues a message in send queue for sending to the service
 *
 * @param controller the handle to the controller
 * @param msg the message to queue
 */
void
GNUNET_TESTBED_queue_message (struct GNUNET_TESTBED_Controller *controller,
                              struct GNUNET_MessageHeader *msg);


/**
 * Compresses given configuration using zlib compress
 *
 * @param config the serialized configuration
 * @param size the size of config
 * @param xconfig will be set to the compressed configuration (memory is fresly
 *          allocated) 
 * @return the size of the xconfig
 */
size_t
GNUNET_TESTBED_compress_config (const char *config, size_t size,
                                char **xconfig);


/**
 * Adds an operation to the queue of operations
 *
 * @param op the operation to add
 */
void
GNUNET_TESTBED_operation_add (struct GNUNET_TESTBED_Operation *op);

#endif
