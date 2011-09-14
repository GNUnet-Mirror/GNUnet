/*
 * helper_common.c
 *
 *  Created on: 28.03.2011
 *      Author: David Brodski
 */

#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_os_lib.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"
#include "gnunet_util_lib.h"
#include "plugin_transport_wlan.h"
#include "gnunet_common.h"
#include "gnunet_transport_plugin.h"
//#include "gnunet_util_lib.h"

/**
 * function to create GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL message for plugin
 * @param buffer pointer to buffer for the message
 * @param mac pointer to the mac address
 * @return number of bytes written
 */
int
send_mac_to_plugin (char *buffer, struct MacAddress *mac)
{

  struct Wlan_Helper_Control_Message macmsg;

  memcpy (&macmsg.mac, (char *) mac, sizeof (struct MacAddress));
  macmsg.hdr.size = htons (sizeof (struct Wlan_Helper_Control_Message));
  macmsg.hdr.type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL);

  memcpy (buffer, &macmsg, sizeof (struct Wlan_Helper_Control_Message));
  return sizeof (struct Wlan_Helper_Control_Message);
}
