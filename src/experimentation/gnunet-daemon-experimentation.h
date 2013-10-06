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
 * @file experimentation/gnunet-daemon-experimentation.h
 * @brief experimentation daemon
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"


/**
 * Timeout between request and expected response
 */
#define EXP_RESPONSE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Default experiment frequency
 */
#define EXP_DEFAULT_EXP_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 6)

/**
 * Default experiment duration
 */
#define EXP_DEFAULT_EXP_DUR GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Statistics handle shared between components
 */
extern struct GNUNET_STATISTICS_Handle *GED_stats;

/**
 * Configuration handle shared between components
 */
extern struct GNUNET_CONFIGURATION_Handle *GED_cfg;

/**
 * Capability value shared between components
 */
extern uint32_t GSE_node_capabilities;


/**
 * Capabilities a node has or an experiment requires
 */
enum GNUNET_EXPERIMENTATION_capabilities
{
  NONE = 0,
  PLUGIN_TCP = 1,
  PLUGIN_UDP = 2,
  PLUGIN_UNIX = 4,
  PLUGIN_HTTP_CLIENT = 8,
  PLUGIN_HTTP_SERVER = 16,
  PLUGIN_HTTPS_CLIENT = 32,
  PLUGIN_HTTPS_SERVER = 64,
  PLUGIN_WLAN = 128,
  HAVE_IPV6 = 256,
  BEHIND_NAT = 512
};


/**
 * Struct to store information about a specific experiment
 */
struct Experiment
{
  /* Header */
  /* ----------------- */
  char *name;

  /**
   * Experiment issuer
   */
  struct GNUNET_CRYPTO_EccPublicSignKey issuer;

  /**
   * Experiment version as timestamp of creation
   */
  struct GNUNET_TIME_Absolute version;

  /**
   * Description
   */
  char *description;

  /**
   * Required capabilities
   */
  uint32_t required_capabilities;

  /* Experiment timing */
  /* ----------------- */

  /**
   * When to start experiment
   */
  struct GNUNET_TIME_Absolute start;

  /**
   * When to end experiment
   */
  struct GNUNET_TIME_Absolute stop;

  /**
   * How often to run experiment
   */
  struct GNUNET_TIME_Relative frequency;

  /**
   * How long to run each execution
   */
  struct GNUNET_TIME_Relative duration;


  /* Experiment itself */
  /* ----------------- */

  /* TBD */
};


/**
 * A experimentation node
 */
struct Node
{
  /**
   * Peer id
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Task for response timeout
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Core transmission handle
   */
  struct GNUNET_CORE_TransmitHandle *cth;

  /**
   * Node capabilities
   */
  uint32_t capabilities;

  /**
   * Experiment version as timestamp of creation
   */
  struct GNUNET_TIME_Absolute version;

  struct NodeComCtx *e_req_head;

  struct NodeComCtx *e_req_tail;

  /**
   * Array of issuers accepted by this neighbor.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey *issuer_id;

  unsigned int issuer_count;

};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Experimentation request message
 * Used to detect experimentation capability
 *
 * This struct is followed by issuer identities:
 * (issuer_count * struct GNUNET_CRYPTO_EccPublicSignKey)
 *
 */
struct Experimentation_Request
{
  struct GNUNET_MessageHeader msg;

  uint32_t capabilities GNUNET_PACKED;

  uint32_t issuer_count GNUNET_PACKED;
};


/**
 * Experimentation response message
 * Sent if peer is running the daemon
 *
 * This struct is followed by issuer identities:
 * (issuer_count * struct GNUNET_CRYPTO_EccPublicSignKey)
 */
struct Experimentation_Response
{
  struct GNUNET_MessageHeader msg;

  uint32_t capabilities GNUNET_PACKED;

  uint32_t issuer_count GNUNET_PACKED;
};


/**
 * Struct to store information about an experiment issuer
 */
struct Issuer
{
  struct GNUNET_CRYPTO_EccPublicSignKey pubkey;
};


/**
 * Hashmap containing valid experiment issuers
 * (the key is the hash of the respective public key,
 * the values are of type `struct Issuer').
 */
struct GNUNET_CONTAINER_MultiHashMap *valid_issuers;

/**
 * Experiment start message
 *
 * struct is followed by string with length len_name
 */
struct GED_start_message
{
  struct GNUNET_MessageHeader header;

  /**
   * String length of experiment name following the struct
   */
  uint32_t len_name GNUNET_PACKED;

  /**
   * Experiment issuer
   */
  struct GNUNET_CRYPTO_EccPublicSignKey issuer;

  /**
   * Experiment version as timestamp of creation
   */
  struct GNUNET_TIME_AbsoluteNBO version_nbo;
};


struct GED_start_ack_message
{
  struct GNUNET_MessageHeader header;

  /**
   * String length of experiment name following the struct
   */
  uint32_t len_name GNUNET_PACKED;

  /**
   * Experiment issuer
   */
  struct GNUNET_CRYPTO_EccPublicSignKey issuer;

  /**
   * Experiment version as timestamp of creation
   */
  struct GNUNET_TIME_AbsoluteNBO version_nbo;
};


struct GED_stop_message
{
  struct GNUNET_MessageHeader header;

  /**
   * String length of experiment name following the struct
   */
  uint32_t len_name GNUNET_PACKED;

  /**
   * Experiment issuer
   */
  struct GNUNET_CRYPTO_EccPublicSignKey issuer;

  /**
   * Experiment version as timestamp of creation
   */
  struct GNUNET_TIME_AbsoluteNBO version_nbo;
};

GNUNET_NETWORK_STRUCT_END


int
GED_nodes_rts (struct Node *n);


int
GED_nodes_send_start (struct Node *n, struct Experiment *e);


/**
 * Confirm a experiment START with a node
 *
 * @return #GNUNET_NO if core was busy with sending, #GNUNET_OK otherwise
 */
int
GED_nodes_send_start_ack (struct Node *n, struct Experiment *e);

/**
 * Start the nodes management
 */
void
GED_nodes_start (void);


/**
 * Stop the nodes management
 */
void
GED_nodes_stop (void);


/**
 * Print a single capability value
 *
 * @param cap capability value
 * @return the string to print
 */
const char *
GED_capability_to_str (uint32_t cap);


/**
 * Are the capabilities provided?
 *
 * @param have bitstring containing the provided capabilities
 * @param desired bitstring containing the desired capabilities\
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
GED_capabilities_have (uint32_t have, uint32_t desired);


/**
 * Start the detecting capabilities
 */
void
GED_capabilities_start (void);


/**
 * Stop the detecting capabilities
 */
void
GED_capabilities_stop (void);


/**
 * Start experiments management
 *
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
GED_experiments_issuer_accepted (const struct GNUNET_CRYPTO_EccPublicSignKey *issuer_ID);


/*
 * Find an experiment based on issuer name and version
 *
 * @param issuer the issuer
 * @param name experiment name
 * @param version experiment version
 * @return the experiment or NULL if not found
 */
struct Experiment *
GED_experiments_find (const struct GNUNET_CRYPTO_EccPublicSignKey *issuer,
		      const char *name,
		      const struct GNUNET_TIME_Absolute version);


typedef void (*GNUNET_EXPERIMENTATION_experiments_get_cb) (struct Node *n,
							   struct Experiment *e);


void
GED_experiments_get (struct Node *n,
		     struct GNUNET_CRYPTO_EccPublicSignKey *issuer,
		     GNUNET_EXPERIMENTATION_experiments_get_cb get_cb);


/**
 * Start experiments management
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GED_experiments_start (void);


/**
 * Stop experiments management
 */
void
GED_experiments_stop (void);


/**
 * Handle a START message from a remote node
 *
 * @param n the node
 * @param e the experiment
 */
void
GED_scheduler_handle_start (struct Node *n, struct Experiment *e);


/**
 * Handle a START_ACL message from a remote node
 *
 * @param n the node
 * @param e the experiment
 */
void
GED_scheduler_handle_start_ack (struct Node *n, struct Experiment *e);


/**
 * Handle a STOP message from a remote node
 *
 * @param n the node
 * @param e the experiment
 */
void
GED_scheduler_handle_stop (struct Node *n, struct Experiment *e);


/**
 * Add a new experiment for a node
 *
 * @param n the node
 * @param e the experiment
 * @param outbound are we initiator (#GNUNET_YES) or client (#GNUNET_NO)?
 */
void
GED_scheduler_add (struct Node *n,
		   struct Experiment *e,
		   int outbound);


/**
 * Start the scheduler component
 */
void
GED_scheduler_start (void);


/**
 * Stop the scheduler component
 */
void
GED_scheduler_stop (void);


/**
 * Start the storage component
 */
void
GED_storage_start (void);


/**
 * Stop the storage component
 */
void
GED_storage_stop (void);


/* end of gnunet-daemon-experimentation.h */
