/*
     This file is part of GNUnet.
     (C)

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
 * @file sensor/sensor_util_lib.c
 * @brief sensor utilities
 * @author Omar Tarabai
 */

#ifndef GNUNET_SENSOR_UTIL_LIB_H
#define GNUNET_SENSOR_UTIL_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Structure containing sensor definition
 */
struct GNUNET_SENSOR_SensorInfo
{

  /**
   * The configuration handle
   * carrying sensor information
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Sensor name
   */
  char *name;

  /**
   * Path to definition file
   */
  char *def_file;

  /**
   * First part of version number
   */
  uint16_t version_major;

  /**
   * Second part of version number
   */
  uint16_t version_minor;

  /**
   * Sensor description
   */
  char *description;

  /**
   * Sensor currently enabled
   */
  int enabled;

  /**
   * Category under which the sensor falls (e.g. tcp, datastore)
   */
  char *category;

  /**
   * When does the sensor become active
   */
  struct GNUNET_TIME_Absolute *start_time;

  /**
   * When does the sensor expire
   */
  struct GNUNET_TIME_Absolute *end_time;

  /**
   * Time interval to collect sensor information (e.g. every 1 min)
   */
  struct GNUNET_TIME_Relative interval;

  /**
   * Lifetime of an information sample after which it is deleted from storage
   * If not supplied, will default to the interval value
   */
  struct GNUNET_TIME_Relative lifetime;

  /**
   * A set of required peer capabilities for the sensor to collect meaningful information (e.g. ipv6)
   */
  char *capabilities;

  /**
   * Either "gnunet-statistics" or external "process"
   */
  char *source;

  /**
   * Name of the GNUnet service that is the source for the gnunet-statistics entry
   */
  char *gnunet_stat_service;

  /**
   * Name of the gnunet-statistics entry
   */
  char *gnunet_stat_name;

  /**
   * Handle to statistics get request (OR GNUNET_SCHEDULER_NO_TASK)
   */
  struct GNUNET_STATISTICS_GetHandle *gnunet_stat_get_handle;

  /**
   * Name of the external process to be executed
   */
  char *ext_process;

  /**
   * Arguments to be passed to the external process
   */
  char *ext_args;

  /**
   * Handle to the external process
   */
  struct GNUNET_OS_CommandHandle *ext_cmd;

  /**
   * Did we already receive a value
   * from the currently running external
   * proccess ? #GNUNET_YES / #GNUNET_NO
   */
  int ext_cmd_value_received;

  /**
   * The output datatype to be expected
   */
  char *expected_datatype;

  /**
   * Peer-identity of peer running collection point
   */
  struct GNUNET_PeerIdentity *collection_point;

  /**
   * Do we report received sensor values to collection point?
   * #GNUNET_YES / #GNUNET_NO
   */
  int report_values;

  /**
   * Time interval to send sensor values to collection point (e.g. every 30 mins)
   */
  struct GNUNET_TIME_Relative value_reporting_interval;

  /**
   * Do we report anomalies to collection point?
   * #GNUNET_YES / #GNUNET_NO
   */
  int report_anomalies;

  /**
   * Execution task (OR GNUNET_SCHEDULER_NO_TASK)
   */
  GNUNET_SCHEDULER_TaskIdentifier execution_task;

  /**
   * Is the sensor being executed
   */
  int running;

};

/**
 * Anomaly report received and stored by sensor dashboard.
 * Sensor name and peer id are not included because they are part of the
 * peerstore key.
 */
struct GNUNET_SENSOR_DashboardAnomalyEntry
{

  /**
   * New anomaly status
   */
  uint16_t anomalous;

  /**
   * Percentage of neighbors reported the same anomaly
   */
  float anomalous_neighbors;

};

GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Used to communicate brief information about a sensor.
 */
    struct GNUNET_SENSOR_SensorBriefMessage
{

  /**
   * GNUNET general message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Size of sensor name string, allocated at position 0 after this struct.
   */
  uint16_t name_size;

  /**
   * First part of sensor version number
   */
  uint16_t version_major;

  /**
   * Second part of sensor version number
   */
  uint16_t version_minor;

};

/**
 * Used to communicate full information about a sensor.
 */
struct GNUNET_SENSOR_SensorFullMessage
{

  /**
   * GNUNET general message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Size of sensor name.
   * Name allocated at position 0 after this struct.
   */
  uint16_t sensorname_size;

  /**
   * Size of the sensor definition file carrying full sensor information.
   * The file content allocated at position 1 after this struct.
   */
  uint16_t sensorfile_size;

  /**
   * Name of the file (usually script) associated with this sensor.
   * At the moment we only support having one file per sensor.
   * The file name is allocated at position 2 after this struct.
   */
  uint16_t scriptname_size;

  /**
   * Size of the file (usually script) associated with this sensor.
   * The file content is allocated at position 3 after this struct.
   */
  uint16_t scriptfile_size;

};

/**
 * Used to communicate sensor values to
 * collection points (SENSORDASHBAORD service)
 */
struct GNUNET_SENSOR_ValueMessage
{

  /**
   * GNUNET general message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Hash of sensor name
   */
  struct GNUNET_HashCode sensorname_hash;

  /**
   * First part of sensor version number
   */
  uint16_t sensorversion_major;

  /**
   * Second part of sensor version number
   */
  uint16_t sensorversion_minor;

  /**
   * Timestamp of recorded reading
   */
  struct GNUNET_TIME_Absolute timestamp;

  /**
   * Size of sensor value, allocated at poistion 0 after this struct
   */
  uint16_t value_size;

};

/**
 * Message carrying an anomaly status change report
 */
struct GNUNET_SENSOR_AnomalyReportMessage
{

  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Hash of sensor name
   */
  struct GNUNET_HashCode sensorname_hash;

  /**
   * First part of sensor version number
   */
  uint16_t sensorversion_major;

  /**
   * Second part of sensor version name
   */
  uint16_t sensorversion_minor;

  /**
   * New anomaly status
   */
  uint16_t anomalous;

  /**
   * Percentage of neighbors reported the same anomaly
   */
  float anomalous_neighbors;

};

GNUNET_NETWORK_STRUCT_END
/**
 * Given two version numbers as major and minor, compare them.
 *
 * @param v1_major First part of first version number
 * @param v1_minor Second part of first version number
 * @param v2_major First part of second version number
 * @param v2_minor Second part of second version number
 */
    int
GNUNET_SENSOR_version_compare (uint16_t v1_major, uint16_t v1_minor,
                               uint16_t v2_major, uint16_t v2_minor);


/**
 * Reads sensor definitions from given sensor directory.
 *
 * @param sensordir Path to sensor directory.
 * @return a multihashmap of loaded sensors
 */
struct GNUNET_CONTAINER_MultiHashMap *
GNUNET_SENSOR_load_all_sensors (char *sensor_dir);


/**
 * Get path to the default directory containing the sensor definition files with
 * a trailing directory separator.
 *
 * @return Default sensor files directory full path
 */
char *
GNUNET_SENSOR_get_default_sensor_dir ();


/**
 * Destroys a group of sensors in a hashmap and the hashmap itself
 *
 * @param sensors hashmap containing the sensors
 */
void
GNUNET_SENSOR_destroy_sensors (struct GNUNET_CONTAINER_MultiHashMap *sensors);


struct GNUNET_SENSOR_crypto_pow_context;

/**
 * Block carrying arbitrary data + its proof-of-work + signature
 */
struct GNUNET_SENSOR_crypto_pow_block
{

  /**
   * Proof-of-work value
   */
  uint64_t pow;

  /**
   * Data signature
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;

  /**
   * Size of the msg component (allocated after this struct)
   */
  size_t msg_size;

  /**
   * Purpose of signing.
   * Data is allocated after this (timestamp, public_key, msg).
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * First part of data - timestamp
   */
  struct GNUNET_TIME_Absolute timestamp;

  /**
   * Second part of data - Public key
   */
  struct GNUNET_CRYPTO_EddsaPublicKey public_key;

};


/**
 * Continuation called with a status result.
 *
 * @param cls closure
 * @param pow Proof-of-work value
 * @param purpose Signed block (size, purpose, data)
 * @param signature Signature, NULL on error
 */
typedef void (*GNUNET_SENSOR_UTIL_pow_callback) (void *cls,
                                                 struct
                                                 GNUNET_SENSOR_crypto_pow_block
                                                 * block);


/**
 * Cancel an operation started by #GNUNET_SENSOR_crypto_pow_sign().
 * Call only before callback function passed to #GNUNET_SENSOR_crypto_pow_sign()
 * is called with the result.
 */
void
GNUNET_SENSOR_crypto_pow_sign_cancel (struct GNUNET_SENSOR_crypto_pow_context
                                      *cx);


/**
 * Calculate proof-of-work and sign a message.
 *
 * @param msg Message to calculate pow and sign
 * @param msg_size size of msg
 * @param timestamp Timestamp to add to the message to protect against replay attacks
 * @param public_key Public key of the origin peer, to protect against redirect attacks
 * @param private_key Private key of the origin peer to sign the result
 * @param matching_bits Number of leading zeros required in the result hash
 * @param callback Callback function to call with the result
 * @param callback_cls Closure for callback
 * @return Operation context
 */
struct GNUNET_SENSOR_crypto_pow_context *
GNUNET_SENSOR_crypto_pow_sign (void *msg, size_t msg_size,
                               struct GNUNET_TIME_Absolute *timestamp,
                               struct GNUNET_CRYPTO_EddsaPublicKey *public_key,
                               struct GNUNET_CRYPTO_EddsaPrivateKey
                               *private_key, int matching_bits,
                               GNUNET_SENSOR_UTIL_pow_callback callback,
                               void *callback_cls);


/**
 * Verify that proof-of-work and signature in the given block are valid.
 * If all valid, a pointer to the payload within the block is set and the size
 * of the payload is returned.
 *
 * **VERY IMPORTANT** : You will still need to verify the timestamp yourself.
 *
 * @param block The block received and needs to be verified
 * @param matching_bits Number of leading zeros in the hash used to verify pow
 * @param public_key Public key of the peer that sent this block
 * @param purpose Expected signing purpose
 * @param payload Where to store the pointer to the payload
 * @return Size of the payload
 */
size_t
GNUNET_SENSOR_crypto_verify_pow_sign (struct GNUNET_SENSOR_crypto_pow_block *
                                      block, int matching_bits,
                                      struct GNUNET_CRYPTO_EddsaPublicKey *
                                      public_key, uint32_t purpose,
                                      void **payload);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SENSOR_UTIL_LIB_H */
#endif
/* end of gnunet_sensor_util_lib.h */
