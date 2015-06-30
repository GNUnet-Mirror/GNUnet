/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2012 Christian Grothoff

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
 * @file vpn/gnunet-helper-vpn-windows.c
 * @brief the helper for the VPN service in win32 builds.
 * Opens a virtual network-interface, sends data received on the if to stdout,
 * sends data received on stdin to the interface
 * @author Christian M. Fuchs
 *
 * The following list of people have reviewed this code and considered
 * it safe since the last modification (if you reviewed it, please
 * have your name added to the list):
 *
 */

#include <stdio.h>
#include <Winsock2.h>
#include <windows.h>
#include <setupapi.h>
#ifndef __MINGW64_VERSION_MAJOR
#include <ddk/cfgmgr32.h>
#include <ddk/newdev.h>
#else
#include <cfgmgr32.h>
#include <newdev.h>
#endif
#include <time.h>
#include "platform.h"
#include "tap-windows.h"
/**
 * Need 'struct GNUNET_HashCode' and 'struct GNUNET_PeerIdentity'.
 */
#include "gnunet_crypto_lib.h"
/**
 * Need 'struct GNUNET_MessageHeader'.
 */
#include "gnunet_common.h"

/**
 * Need VPN message types.
 */
#include "gnunet_protocols.h"

/**
 * Should we print (interesting|debug) messages that can happen during
 * normal operation?
 */
#define DEBUG GNUNET_NO

#if DEBUG
/* FIXME: define with varargs... */
#define LOG_DEBUG(msg) fprintf (stderr, "%s", msg);
#else
#define LOG_DEBUG(msg) do {} while (0)
#endif

/**
 * Will this binary be run in permissions testing mode?
 */
static boolean privilege_testing = FALSE;

/**
 * Maximum size of a GNUnet message (GNUNET_SERVER_MAX_MESSAGE_SIZE)
 */
#define MAX_SIZE 65536

/**
 * Name or Path+Name of our win32 driver.
 * The .sys and .cat files HAVE to be in the same location as this file!
 */
#define INF_FILE "share/gnunet/openvpn-tap32/tapw32/OemWin2k.inf"

/**
 * Name or Path+Name of our win64 driver.
 * The .sys and .cat files HAVE to be in the same location as this file!
 */
#define INF_FILE64 "share/gnunet/openvpn-tap32/tapw64/OemWin2k.inf"

/**
 * Hardware ID used in the inf-file.
 * This might change over time, as openvpn advances their driver
 */
#define HARDWARE_ID "tap0901"

/**
 * Minimum major-id of the driver version we can work with
 */
#define TAP_WIN_MIN_MAJOR 9

/**
 * Minimum minor-id of the driver version we can work with.
 * v <= 7 has buggy IPv6.
 * v == 8 is broken for small IPv4 Packets
 */
#define TAP_WIN_MIN_MINOR 9

/**
 * Time in seconds to wait for our virtual device to go up after telling it to do so.
 *
 * openvpn doesn't specify a value, 4 seems sane for testing, even for openwrt
 * (in fact, 4 was chosen by a fair dice roll...)
 */
#define TAP32_POSTUP_WAITTIME 4

/**
 * Location of the network interface list resides in registry.
 */
#define INTERFACE_REGISTRY_LOCATION "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

/**
 * Our local process' PID. Used for creating a sufficiently unique additional
 * hardware ID for our device.
 */
static char secondary_hwid[LINE_LEN / 2];

/**
 * Device's visible Name, used to identify a network device in netsh.
 * eg: "Local Area Connection 9"
 */
static char device_visible_name[256];

/**
 * This is our own local instance of a virtual network interface
 * It is (somewhat) equivalent to using tun/tap in unixoid systems
 *
 * Upon initialization, we create such an device node.
 * Upon termination, we remove it again.
 *
 * If we crash this device might stay around.
 */
static HDEVINFO DeviceInfo = INVALID_HANDLE_VALUE;

/**
 * Registry Key we hand over to windows to spawn a new virtual interface
 */
static SP_DEVINFO_DATA DeviceNode;

/**
 * GUID of our virtual device in the form of
 * {12345678-1234-1234-1234-123456789abc} - in hex
 */
static char device_guid[256];


/**
 * Possible states of an IO facility.
 */
enum IO_State
{

  /**
   * overlapped I/O is ready for work
   */
  IOSTATE_READY = 0,

  /**
   * overlapped I/O has been queued
   */
  IOSTATE_QUEUED,

  /**
   * overlapped I/O has finished, but is waiting for it's write-partner
   */
  IOSTATE_WAITING,

  /**
   * there is a full buffer waiting
   */
  IOSTATE_RESUME,

  /**
   * Operlapped IO states for facility objects
   * overlapped I/O has failed, stop processing
   */
  IOSTATE_FAILED

};


/**
 * A IO Object + read/writebuffer + buffer-size for windows asynchronous IO handling
 */
struct io_facility
{
  /**
   * The mode the state machine associated with this object is in.
   */
  enum IO_State facility_state;

  /**
   * If the path is open or blocked in general (used for quickly checking)
   */
  BOOL path_open; // BOOL is winbool (int), NOT boolean (unsigned char)!

  /**
   * Windows Object-Handle (used for accessing TAP and STDIN/STDOUT)
   */
  HANDLE handle;

  /**
   * Overlaped IO structure used for asynchronous IO in windows.
   */
  OVERLAPPED overlapped;

  /**
   * Buffer for reading things to and writing from...
   */
  unsigned char buffer[MAX_SIZE];

  /**
   * How much of this buffer was used when reading or how much data can be written
   */
  DWORD buffer_size;

  /**
   * Amount of data actually written or read by readfile/writefile.
   */
  DWORD buffer_size_processed;

  /**
   * How much of this buffer we have writte in total
   */
  DWORD buffer_size_written;
};

/**
 * ReOpenFile is only available as of XP SP2 and 2003 SP1
 */
WINBASEAPI HANDLE WINAPI ReOpenFile (HANDLE, DWORD, DWORD, DWORD);

/**
 * IsWow64Process definition for our is_win64, as this is a kernel function
 */
typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

/**
 * Determines if the host OS is win32 or win64
 *
 * @return true if
 */
BOOL
is_win64 ()
{
#if defined(_WIN64)
  //this is a win64 binary,
  return TRUE;
#elif defined(_WIN32)
  //this is a 32bit binary, and we need to check if we are running in WOW64
  BOOL success = FALSE;
  BOOL on_wow64 = FALSE;
  LPFN_ISWOW64PROCESS IsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress (GetModuleHandle ("kernel32"), "IsWow64Process");

  if (NULL != IsWow64Process)
      success = IsWow64Process (GetCurrentProcess (), &on_wow64);

  return success && on_wow64;
#endif
}
/**
 * Wrapper for executing a shellcommand in windows.
 *
 * @param command - the command + parameters to execute
 * @return * exitcode of the program executed,
 *         * EINVAL (cmd/file not found)
 *         * EPIPE (could not read STDOUT)
 */
static int
execute_shellcommand (const char *command)
{
  FILE *pipe;

  if ( (NULL == command) ||
       (NULL == (pipe = _popen (command, "rt"))) )
    return EINVAL;

#if DEBUG
  fprintf (stderr, "DEBUG: Command output: \n");
  char output[LINE_LEN];
  while (NULL != fgets (output, sizeof (output), pipe))
    fprintf (stderr, "%s", output);
#endif

  return _pclose (pipe);
}


/**
 * @brief Sets the IPv6-Address given in address on the interface dev
 *
 * @param address the IPv6-Address
 * @param prefix_len the length of the network-prefix
 */
static int
set_address6 (const char *address, unsigned long prefix_len)
{
  int ret = EINVAL;
  char command[LINE_LEN];
  struct sockaddr_in6 sa6;

  /*
   * parse the new address
   */
  memset (&sa6, 0, sizeof (struct sockaddr_in6));
  sa6.sin6_family = AF_INET6;
  if (1 != inet_pton (AF_INET6, address, &sa6.sin6_addr.s6_addr))
    {
      fprintf (stderr, "ERROR: Failed to parse address `%s': %s\n", address,
               strerror (errno));
      return -1;
    }

  /*
   * prepare the command
   */
  snprintf (command, LINE_LEN,
            "netsh interface ipv6 add address \"%s\" %s/%d store=active",
            device_visible_name, address, prefix_len);
  /*
   * Set the address
   */
  ret = execute_shellcommand (command);

  /* Did it work?*/
  if (0 != ret)
    fprintf (stderr, "FATAL: Setting IPv6 address failed: %s\n", strerror (ret));
  return ret;
}


/**
 * @brief Removes the IPv6-Address given in address from the interface dev
 *
 * @param address the IPv4-Address
 */
static void
remove_address6 (const char *address)
{
  char command[LINE_LEN];
  int ret = EINVAL;

  // sanity checking was already done in set_address6
  /*
   * prepare the command
   */
  snprintf (command, LINE_LEN,
            "netsh interface ipv6 delete address \"%s\" store=persistent",
            device_visible_name);
  /*
   * Set the address
   */
  ret = execute_shellcommand (command);

  /* Did it work?*/
  if (0 != ret)
    fprintf (stderr,
	     "FATAL: removing IPv6 address failed: %s\n",
	     strerror (ret));
}


/**
 * @brief Sets the IPv4-Address given in address on the interface dev
 *
 * @param address the IPv4-Address
 * @param mask the netmask
 */
static int
set_address4 (const char *address, const char *mask)
{
  int ret = EINVAL;
  char command[LINE_LEN];

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;

  /*
   * Parse the address
   */
  if (1 != inet_pton (AF_INET, address, &addr.sin_addr.s_addr))
    {
      fprintf (stderr, "ERROR: Failed to parse address `%s': %s\n", address,
               strerror (errno));
      return -1;
    }
  // Set Device to Subnet-Mode? do we really need openvpn/tun.c:2925 ?

  /*
   * prepare the command
   */
  snprintf (command, LINE_LEN,
            "netsh interface ipv4 add address \"%s\" %s %s store=active",
            device_visible_name, address, mask);
  /*
   * Set the address
   */
  ret = execute_shellcommand (command);

  /* Did it work?*/
  if (0 != ret)
    fprintf (stderr,
	     "FATAL: Setting IPv4 address failed: %s\n",
	     strerror (ret));
  return ret;
}


/**
 * @brief Removes the IPv4-Address given in address from the interface dev
 *
 * @param address the IPv4-Address
 */
static void
remove_address4 (const char *address)
{
  char command[LINE_LEN];
  int ret = EINVAL;

  // sanity checking was already done in set_address4

  /*
   * prepare the command
   */
  snprintf (command, LINE_LEN,
            "netsh interface ipv4 delete address \"%s\" gateway=all store=persistent",
            device_visible_name);
  /*
   * Set the address
   */
  ret = execute_shellcommand (command);

  /* Did it work?*/
  if (0 != ret)
    fprintf (stderr, "FATAL: removing IPv4 address failed: %s\n", strerror (ret));
}


/**
 * Setup a new virtual interface to use for tunneling.
 *
 * @return: TRUE if setup was successful, else FALSE
 */
static BOOL
setup_interface ()
{
  /*
   * where to find our inf-file. (+ the "full" path, after windows found")
   *
   * We do not directly input all the props here, because openvpn will update
   * these details over time.
   */
  char inf_file_path[MAX_PATH];
  char * temp_inf_filename;
  char hwidlist[LINE_LEN + 4];
  char class_name[128];
  GUID class_guid;
  int str_length = 0;

  /**
   * Set the device's hardware ID and add it to a list.
   * This information will later on identify this device in registry.
   */
  strncpy (hwidlist, HARDWARE_ID, LINE_LEN);
  /**
   * this is kind of over-complicated, but allows keeps things independent of
   * how the openvpn-hwid is actually stored.
   *
   * A HWID list is double-\0 terminated and \0 separated
   */
  str_length = strlen (hwidlist) + 1;
  strncpy (&hwidlist[str_length], secondary_hwid, LINE_LEN);
  str_length += strlen (&hwidlist[str_length]) + 1;

  /**
   * Locate the inf-file, we need to store it somewhere where the system can
   * find it. We need to pick the correct driver for win32/win64.
   */
  if (is_win64())
    GetFullPathNameA (INF_FILE64, MAX_PATH, inf_file_path, &temp_inf_filename);
  else
    GetFullPathNameA (INF_FILE, MAX_PATH, inf_file_path, &temp_inf_filename);

  fprintf (stderr, "INFO: Located our driver's .inf file at %s\n", inf_file_path);
  /**
   * Bootstrap our device info using the drivers inf-file
   */
  if ( ! SetupDiGetINFClassA (inf_file_path,
                            &class_guid,
                            class_name, sizeof (class_name) / sizeof (char),
                            NULL))
    return FALSE;

  /**
   * Collect all the other needed information...
   * let the system fill our this form
   */
  DeviceInfo = SetupDiCreateDeviceInfoList (&class_guid, NULL);
  if (DeviceInfo == INVALID_HANDLE_VALUE)
    return FALSE;

  DeviceNode.cbSize = sizeof (SP_DEVINFO_DATA);
  if ( ! SetupDiCreateDeviceInfoA (DeviceInfo,
                                 class_name,
                                 &class_guid,
                                 NULL,
                                 0,
                                 DICD_GENERATE_ID,
                                 &DeviceNode))
    return FALSE;

  /* Deploy all the information collected into the registry */
  if ( ! SetupDiSetDeviceRegistryPropertyA (DeviceInfo,
                                          &DeviceNode,
                                          SPDRP_HARDWAREID,
                                          (LPBYTE) hwidlist,
                                          str_length * sizeof (char)))
    return FALSE;

  /* Install our new class(=device) into the system */
  if ( ! SetupDiCallClassInstaller (DIF_REGISTERDEVICE,
                                  DeviceInfo,
                                  &DeviceNode))
    return FALSE;

  /* This system call tends to take a while (several seconds!) on
     "modern" Windoze systems */
  if ( ! UpdateDriverForPlugAndPlayDevicesA (NULL,
                                           secondary_hwid,
                                           inf_file_path,
                                           INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE,
                                           NULL)) //reboot required? NEVER!
    return FALSE;

  fprintf (stderr, "DEBUG: successfully created a network device\n");
  return TRUE;
}


/**
 * Remove our new virtual interface to use for tunneling.
 * This function must be called AFTER setup_interface!
 *
 * @return: TRUE if destruction was successful, else FALSE
 */
static BOOL
remove_interface ()
{
  SP_REMOVEDEVICE_PARAMS remove;

  if (INVALID_HANDLE_VALUE == DeviceInfo)
    return FALSE;

  remove.ClassInstallHeader.cbSize = sizeof (SP_CLASSINSTALL_HEADER);
  remove.HwProfile = 0;
  remove.Scope = DI_REMOVEDEVICE_GLOBAL;
  remove.ClassInstallHeader.InstallFunction = DIF_REMOVE;
  /*
   * 1. Prepare our existing device information set, and place the
   *    uninstall related information into the structure
   */
  if ( ! SetupDiSetClassInstallParamsA (DeviceInfo,
                                      (PSP_DEVINFO_DATA) & DeviceNode,
                                      &remove.ClassInstallHeader,
                                      sizeof (remove)))
    return FALSE;
  /*
   * 2. Uninstall the virtual interface using the class installer
   */
  if ( ! SetupDiCallClassInstaller (DIF_REMOVE,
                                  DeviceInfo,
                                  (PSP_DEVINFO_DATA) & DeviceNode))
    return FALSE;

  SetupDiDestroyDeviceInfoList (DeviceInfo);

  fprintf (stderr, "DEBUG: removed interface successfully\n");

  return TRUE;
}


/**
 * Do all the lookup necessary to retrieve the inteface's actual name
 * off the registry.
 *
 * @return: TRUE if we were able to lookup the interface's name, else FALSE
 */
static BOOL
resolve_interface_name ()
{
  SP_DEVINFO_LIST_DETAIL_DATA device_details;
  char pnp_instance_id [MAX_DEVICE_ID_LEN];
  HKEY adapter_key_handle;
  LONG status;
  DWORD len;
  int i = 0;
  int retrys;
  BOOL retval = FALSE;
  char adapter[] = INTERFACE_REGISTRY_LOCATION;

  /* We can obtain the PNP instance ID from our setupapi handle */
  device_details.cbSize = sizeof (device_details);
  if (CR_SUCCESS != CM_Get_Device_ID_ExA (DeviceNode.DevInst,
                                          (PCHAR) pnp_instance_id,
                                          MAX_DEVICE_ID_LEN,
                                          0, //must be 0
                                          NULL)) //hMachine, we are local
    return FALSE;

  fprintf (stderr, "DEBUG: Resolving interface name for network device %s\n",pnp_instance_id);

  /* Registry is incredibly slow, retry for up to 30 seconds to allow registry to refresh */
  for (retrys = 0; retrys < 120 && !retval; retrys++)
    {
      /* sleep for 250ms*/
      Sleep (250);

      /* Now we can use this ID to locate the correct networks interface in registry */
      if (ERROR_SUCCESS != RegOpenKeyExA (
                                          HKEY_LOCAL_MACHINE,
                                          adapter,
                                          0,
                                          KEY_READ,
                                          &adapter_key_handle))
        return FALSE;

      /* Of course there is a multitude of entries here, with arbitrary names,
       * thus we need to iterate through there.
       */
      while (!retval)
        {
          char instance_key[256];
          char query_key [256];
          HKEY instance_key_handle;
          char pnpinstanceid_name[] = "PnpInstanceID";
          char pnpinstanceid_value[256];
          char adaptername_name[] = "Name";
          DWORD data_type;

          len = 256 * sizeof (char);
          /* optain a subkey of {4D36E972-E325-11CE-BFC1-08002BE10318} */
          status = RegEnumKeyExA (
                                  adapter_key_handle,
                                  i,
                                  instance_key,
                                  &len,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL);

          /* this may fail due to one of two reasons:
           * we are at the end of the list*/
          if (ERROR_NO_MORE_ITEMS == status)
            break;
          // * we found a broken registry key, continue with the next key.
          if (ERROR_SUCCESS != status)
            goto cleanup;

          /* prepare our new query string: */
          snprintf (query_key, 256, "%s\\%s\\Connection",
                    adapter,
                    instance_key);

          /* look inside instance_key\\Connection */
          if (ERROR_SUCCESS != RegOpenKeyExA (
                                  HKEY_LOCAL_MACHINE,
                                  query_key,
                                  0,
                                  KEY_READ,
                                  &instance_key_handle))
            goto cleanup;

          /* now, read our PnpInstanceID */
          len = sizeof (pnpinstanceid_value);
          status = RegQueryValueExA (instance_key_handle,
                                     pnpinstanceid_name,
                                     NULL, //reserved, always NULL according to MSDN
                                     &data_type,
                                     (LPBYTE) pnpinstanceid_value,
                                     &len);

          if (status != ERROR_SUCCESS || data_type != REG_SZ)
            goto cleanup;

          /* compare the value we got to our devices PNPInstanceID*/
          if (0 != strncmp (pnpinstanceid_value, pnp_instance_id,
                            sizeof (pnpinstanceid_value) / sizeof (char)))
            goto cleanup;

          len = sizeof (device_visible_name);
          status = RegQueryValueExA (
                                     instance_key_handle,
                                     adaptername_name,
                                     NULL, //reserved, always NULL according to MSDN
                                     &data_type,
                                     (LPBYTE) device_visible_name,
                                     &len);

          if (status != ERROR_SUCCESS || data_type != REG_SZ)
            goto cleanup;

          /*
           * we have successfully found OUR instance,
           * save the device GUID before exiting
           */

          strncpy (device_guid, instance_key, 256);
          retval = TRUE;
          fprintf (stderr, "DEBUG: Interface Name lookup succeeded on retry %d, got \"%s\" %s\n", retrys, device_visible_name, device_guid);

cleanup:
          RegCloseKey (instance_key_handle);

          ++i;
        }

      RegCloseKey (adapter_key_handle);
    }
  return retval;
}


/**
 * Determines the version of the installed TAP32 driver and checks if it's sufficiently new for GNUNET
 *
 * @param handle the handle to our tap device
 * @return TRUE if the version is sufficient, else FALSE
 */
static BOOL
check_tapw32_version (HANDLE handle)
{
  ULONG version[3];
  DWORD len;
  memset (&(version), 0, sizeof (version));

  if (DeviceIoControl (handle, TAP_WIN_IOCTL_GET_VERSION,
                       &version, sizeof (version),
                       &version, sizeof (version), &len, NULL))
      fprintf (stderr, "INFO: TAP-Windows Driver Version %d.%d %s\n",
               (int) version[0],
               (int) version[1],
               (version[2] ? "(DEBUG)" : ""));

  if ((version[0] != TAP_WIN_MIN_MAJOR) ||
      (version[1] < TAP_WIN_MIN_MINOR )){
      fprintf (stderr, "FATAL:  This version of gnunet requires a TAP-Windows driver that is at least version %d.%d\n",
               TAP_WIN_MIN_MAJOR,
               TAP_WIN_MIN_MINOR);
      return FALSE;
    }

  return TRUE;
}


/**
 * Creates a tun-interface called dev;
 *
 * @return the fd to the tun or -1 on error
 */
static HANDLE
init_tun ()
{
  char device_path[256];
  HANDLE handle;

  if (! setup_interface ())
    {
      errno = ENODEV;
      return INVALID_HANDLE_VALUE;
    }

  if (! resolve_interface_name ())
    {
      errno = ENODEV;
      return INVALID_HANDLE_VALUE;
    }

  /* Open Windows TAP-Windows adapter */
  snprintf (device_path, sizeof (device_path), "%s%s%s",
            USERMODEDEVICEDIR,
            device_guid,
            TAP_WIN_SUFFIX);

  handle = CreateFile (
                       device_path,
                       GENERIC_READ | GENERIC_WRITE,
                       0, /* was: FILE_SHARE_READ */
                       0,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                       0
                       );

  if (INVALID_HANDLE_VALUE == handle)
    {
      fprintf (stderr, "FATAL: CreateFile failed on TAP device: %s\n", device_path);
      return handle;
    }

  /* get driver version info */
  if (! check_tapw32_version (handle))
    {
      CloseHandle (handle);
      return INVALID_HANDLE_VALUE;
    }

  /* TODO (opt?): get MTU-Size */

  fprintf (stderr, "DEBUG: successfully opened TAP device\n");
  return handle;
}


/**
 * Brings a TAP device up and sets it to connected state.
 *
 * @param handle the handle to our TAP device
 * @return True if the operation succeeded, else false
 */
static BOOL
tun_up (HANDLE handle)
{
  ULONG status = TRUE;
  DWORD len;
  if (! DeviceIoControl (handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                        &status, sizeof (status),
                        &status, sizeof (status), &len, NULL))
    {
      fprintf (stderr, "FATAL: TAP driver ignored request to UP interface (DeviceIoControl call)\n");
      return FALSE;
    }

  /* Wait for the device to go UP, might take some time. */
  Sleep (TAP32_POSTUP_WAITTIME * 1000);
  fprintf (stderr, "DEBUG: successfully set TAP device to UP\n");

  return TRUE;
}


/**
 * Attempts to read off an input facility (tap or named pipe) in overlapped mode.
 *
 * 1.
 * If the input facility is in IOSTATE_READY, it will issue a new read operation to the
 * input handle. Then it goes into IOSTATE_QUEUED state.
 * In case the read succeeded instantly the input facility enters 3.
 *
 * 2.
 * If the input facility is in IOSTATE_QUEUED state, it will check if the queued read has finished already.
 * If it has finished, go to state 3.
 * If it has failed, set IOSTATE_FAILED
 *
 * 3.
 * If the output facility is in state IOSTATE_READY, the read-buffer is copied to the output buffer.
 *   The input facility enters state IOSTATE_READY
 *   The output facility enters state IOSTATE_READY
 * If the output facility is in state IOSTATE_QUEUED, the input facility enters IOSTATE_WAITING
 *
 * IOSTATE_WAITING is reset by the output facility, once it has completed.
 *
 * @param input_facility input named pipe or file to work with.
 * @param output_facility output pipe or file to hand over data to.
 * @return false if an event reset was impossible (OS error), else true
 */
static BOOL
attempt_read_tap (struct io_facility * input_facility,
                  struct io_facility * output_facility)
{
  struct GNUNET_MessageHeader * hdr;
  unsigned short size;

  switch (input_facility->facility_state)
    {
    case IOSTATE_READY:
      {
        if (! ResetEvent (input_facility->overlapped.hEvent))
          {
            return FALSE;
          }

        input_facility->buffer_size = 0;

        /* Check how the task is handled */
        if (ReadFile (input_facility->handle,
                      input_facility->buffer,
                      sizeof (input_facility->buffer) - sizeof (struct GNUNET_MessageHeader),
                      &input_facility->buffer_size,
                      &input_facility->overlapped))
          {/* async event processed immediately*/

            /* reset event manually*/
            if (! SetEvent (input_facility->overlapped.hEvent))
              return FALSE;

            fprintf (stderr, "DEBUG: tap read succeeded immediately\n");

            /* we successfully read something from the TAP and now need to
             * send it our via STDOUT. Is that possible at the moment? */
            if ((IOSTATE_READY == output_facility->facility_state ||
                 IOSTATE_WAITING == output_facility->facility_state)
                && (0 < input_facility->buffer_size))
              { /* hand over this buffers content and apply message header for gnunet */
                hdr = (struct GNUNET_MessageHeader *) output_facility->buffer;
                size = input_facility->buffer_size + sizeof (struct GNUNET_MessageHeader);

                memcpy (output_facility->buffer + sizeof (struct GNUNET_MessageHeader),
                        input_facility->buffer,
                        input_facility->buffer_size);

                output_facility->buffer_size = size;
                hdr->size = htons (size);
                hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
                output_facility->facility_state = IOSTATE_READY;
              }
            else if (0 < input_facility->buffer_size)
                /* If we have have read our buffer, wait for our write-partner*/
                input_facility->facility_state = IOSTATE_WAITING;
          }
        else /* operation was either queued or failed*/
          {
            int err = GetLastError ();
            if (ERROR_IO_PENDING == err)
              { /* operation queued */
                input_facility->facility_state = IOSTATE_QUEUED;
              }
            else
              { /* error occurred, let the rest of the elements finish */
                input_facility->path_open = FALSE;
                input_facility->facility_state = IOSTATE_FAILED;
                if (IOSTATE_WAITING == output_facility->facility_state)
                  output_facility->path_open = FALSE;

                fprintf (stderr, "FATAL: Read from handle failed, allowing write to finish\n");
              }
          }
      }
      return TRUE;
      // We are queued and should check if the read has finished
    case IOSTATE_QUEUED:
      {
        // there was an operation going on already, check if that has completed now.

        if (GetOverlappedResult (input_facility->handle,
                                 &input_facility->overlapped,
                                 &input_facility->buffer_size,
                                 FALSE))
          {/* successful return for a queued operation */
            if (! ResetEvent (input_facility->overlapped.hEvent))
              return FALSE;

            fprintf (stderr, "DEBUG: tap read succeeded delayed\n");

            /* we successfully read something from the TAP and now need to
             * send it our via STDOUT. Is that possible at the moment? */
            if ((IOSTATE_READY == output_facility->facility_state ||
                 IOSTATE_WAITING == output_facility->facility_state)
                && 0 < input_facility->buffer_size)
              { /* hand over this buffers content and apply message header for gnunet */
                hdr = (struct GNUNET_MessageHeader *) output_facility->buffer;
                size = input_facility->buffer_size + sizeof (struct GNUNET_MessageHeader);

                memcpy (output_facility->buffer + sizeof (struct GNUNET_MessageHeader),
                        input_facility->buffer,
                        input_facility->buffer_size);

                output_facility->buffer_size = size;
                hdr->size = htons(size);
                hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
                output_facility->facility_state = IOSTATE_READY;
                input_facility->facility_state = IOSTATE_READY;
              }
            else if (0 < input_facility->buffer_size)
              { /* If we have have read our buffer, wait for our write-partner*/
                input_facility->facility_state = IOSTATE_WAITING;
                // TODO: shall we attempt to fill our buffer or should we wait for our write-partner to finish?
              }
          }
        else
          { /* operation still pending/queued or failed? */
            int err = GetLastError ();
            if ((ERROR_IO_INCOMPLETE != err) && (ERROR_IO_PENDING != err))
              { /* error occurred, let the rest of the elements finish */
                input_facility->path_open = FALSE;
                input_facility->facility_state = IOSTATE_FAILED;
                if (IOSTATE_WAITING == output_facility->facility_state)
                  output_facility->path_open = FALSE;
                fprintf (stderr, "FATAL: Read from handle failed, allowing write to finish\n");
              }
          }
      }
      return TRUE;
    case IOSTATE_RESUME:
      hdr = (struct GNUNET_MessageHeader *) output_facility->buffer;
      size = input_facility->buffer_size + sizeof (struct GNUNET_MessageHeader);

      memcpy (output_facility->buffer + sizeof (struct GNUNET_MessageHeader),
              input_facility->buffer,
              input_facility->buffer_size);

      output_facility->buffer_size = size;
      hdr->size = htons (size);
      hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
      output_facility->facility_state = IOSTATE_READY;
      input_facility->facility_state = IOSTATE_READY;
      return TRUE;
    default:
      return TRUE;
    }
}


/**
 * Attempts to read off an input facility (tap or named pipe) in overlapped mode.
 *
 * 1.
 * If the input facility is in IOSTATE_READY, it will issue a new read operation to the
 * input handle. Then it goes into IOSTATE_QUEUED state.
 * In case the read succeeded instantly the input facility enters 3.
 *
 * 2.
 * If the input facility is in IOSTATE_QUEUED state, it will check if the queued read has finished already.
 * If it has finished, go to state 3.
 * If it has failed, set IOSTATE_FAILED
 *
 * 3.
 * If the facility is finished with ready
 *   The read-buffer is copied to the output buffer, except for the GNUNET_MessageHeader.
 *   The input facility enters state IOSTATE_READY
 *   The output facility enters state IOSTATE_READY
 * If the output facility is in state IOSTATE_QUEUED, the input facility enters IOSTATE_WAITING
 *
 * IOSTATE_WAITING is reset by the output facility, once it has completed.
 *
 * @param input_facility input named pipe or file to work with.
 * @param output_facility output pipe or file to hand over data to.
 * @return false if an event reset was impossible (OS error), else true
 */
static BOOL
attempt_read_stdin (struct io_facility * input_facility,
                    struct io_facility * output_facility)
{
  struct GNUNET_MessageHeader * hdr;

  switch (input_facility->facility_state)
    {
    case IOSTATE_READY:
      {
        input_facility->buffer_size = 0;

partial_read_iostate_ready:
        if (! ResetEvent (input_facility->overlapped.hEvent))
          return FALSE;

        /* Check how the task is handled */
        if (ReadFile (input_facility->handle,
                           input_facility->buffer + input_facility->buffer_size,
                           sizeof (input_facility->buffer) - input_facility->buffer_size,
                           &input_facility->buffer_size_processed,
                           &input_facility->overlapped))
          {/* async event processed immediately*/
            hdr = (struct GNUNET_MessageHeader *) input_facility->buffer;

            /* reset event manually*/
            if (!SetEvent (input_facility->overlapped.hEvent))
              return FALSE;

            fprintf (stderr, "DEBUG: stdin read succeeded immediately\n");
            input_facility->buffer_size += input_facility->buffer_size_processed;

            if (ntohs (hdr->type) != GNUNET_MESSAGE_TYPE_VPN_HELPER ||
                ntohs (hdr->size) > sizeof (input_facility->buffer))
              {
                fprintf (stderr, "WARNING: Protocol violation, got GNUnet Message type %h, size %h\n", ntohs (hdr->type), ntohs (hdr->size));
                input_facility->facility_state = IOSTATE_READY;
                return TRUE;
              }
            /* we got the a part of a packet */
            if (ntohs (hdr->size) > input_facility->buffer_size)
              goto partial_read_iostate_ready;

            /* have we read more than 0 bytes of payload? (sizeread > header)*/
            if (input_facility->buffer_size > sizeof (struct GNUNET_MessageHeader) &&
                ((IOSTATE_READY == output_facility->facility_state) ||
                 (IOSTATE_WAITING == output_facility->facility_state)))
              {/* we successfully read something from the TAP and now need to
             * send it our via STDOUT. Is that possible at the moment? */

                /* hand over this buffers content and strip gnunet message header */
                memcpy (output_facility->buffer,
                        input_facility->buffer + sizeof (struct GNUNET_MessageHeader),
                        input_facility->buffer_size - sizeof (struct GNUNET_MessageHeader));
                output_facility->buffer_size = input_facility->buffer_size - sizeof (struct GNUNET_MessageHeader);
                output_facility->facility_state = IOSTATE_READY;
                input_facility->facility_state = IOSTATE_READY;
              }
            else if (input_facility->buffer_size > sizeof (struct GNUNET_MessageHeader))
              /* If we have have read our buffer, wait for our write-partner*/
              input_facility->facility_state = IOSTATE_WAITING;
            else /* we read nothing */
              input_facility->facility_state = IOSTATE_READY;
          }
        else /* operation was either queued or failed*/
          {
            int err = GetLastError ();
            if (ERROR_IO_PENDING == err) /* operation queued */
                input_facility->facility_state = IOSTATE_QUEUED;
            else
              { /* error occurred, let the rest of the elements finish */
                input_facility->path_open = FALSE;
                input_facility->facility_state = IOSTATE_FAILED;
                if (IOSTATE_WAITING == output_facility->facility_state)
                  output_facility->path_open = FALSE;

                fprintf (stderr, "FATAL: Read from handle failed, allowing write to finish\n");
              }
          }
      }
      return TRUE;
      // We are queued and should check if the read has finished
    case IOSTATE_QUEUED:
      {
        // there was an operation going on already, check if that has completed now.
        if (GetOverlappedResult (input_facility->handle,
                                 &input_facility->overlapped,
                                 &input_facility->buffer_size_processed,
                                 FALSE))
          {/* successful return for a queued operation */
            hdr = (struct GNUNET_MessageHeader *) input_facility->buffer;

            if (! ResetEvent (input_facility->overlapped.hEvent))
              return FALSE;

            fprintf (stderr, "DEBUG: stdin read succeeded delayed\n");
            input_facility->buffer_size += input_facility->buffer_size_processed;

            if ((ntohs (hdr->type) != GNUNET_MESSAGE_TYPE_VPN_HELPER) ||
                (ntohs (hdr->size) > sizeof (input_facility->buffer)))
              {
                fprintf (stderr, "WARNING: Protocol violation, got GNUnet Message type %h, size %h\n", ntohs (hdr->type), ntohs (hdr->size));
                input_facility->facility_state = IOSTATE_READY;
                return TRUE;
              }
            /* we got the a part of a packet */
            if (ntohs (hdr->size) > input_facility->buffer_size );
              goto partial_read_iostate_ready;

            /* we successfully read something from the TAP and now need to
             * send it our via STDOUT. Is that possible at the moment? */
            if ((IOSTATE_READY == output_facility->facility_state ||
                 IOSTATE_WAITING == output_facility->facility_state)
                && input_facility->buffer_size > sizeof(struct GNUNET_MessageHeader))
              { /* hand over this buffers content and strip gnunet message header */
                memcpy (output_facility->buffer,
                        input_facility->buffer + sizeof(struct GNUNET_MessageHeader),
                        input_facility->buffer_size - sizeof(struct GNUNET_MessageHeader));
                output_facility->buffer_size = input_facility->buffer_size - sizeof(struct GNUNET_MessageHeader);
                output_facility->facility_state = IOSTATE_READY;
                input_facility->facility_state = IOSTATE_READY;
              }
            else if (input_facility->buffer_size > sizeof(struct GNUNET_MessageHeader))
              input_facility->facility_state = IOSTATE_WAITING;
            else
              input_facility->facility_state = IOSTATE_READY;
          }
        else
          { /* operation still pending/queued or failed? */
            int err = GetLastError ();
            if ((ERROR_IO_INCOMPLETE != err) && (ERROR_IO_PENDING != err))
              { /* error occurred, let the rest of the elements finish */
                input_facility->path_open = FALSE;
                input_facility->facility_state = IOSTATE_FAILED;
                if (IOSTATE_WAITING == output_facility->facility_state)
                  output_facility->path_open = FALSE;
                fprintf (stderr, "FATAL: Read from handle failed, allowing write to finish\n");
              }
          }
      }
      return TRUE;
    case IOSTATE_RESUME: /* Our buffer was filled already but our write facility was busy. */
      memcpy (output_facility->buffer,
              input_facility->buffer + sizeof (struct GNUNET_MessageHeader),
              input_facility->buffer_size - sizeof (struct GNUNET_MessageHeader));
      output_facility->buffer_size = input_facility->buffer_size - sizeof (struct GNUNET_MessageHeader);
      output_facility->facility_state = IOSTATE_READY;
      input_facility->facility_state = IOSTATE_READY;
      return TRUE;
    default:
      return TRUE;
    }
}


/**
 * Attempts to write to an output facility (tap or named pipe) in overlapped mode.
 *
 * TODO: high level description
 *
 * @param output_facility output pipe or file to hand over data to.
 * @param input_facility input named pipe or file to work with.
 * @return false if an event reset was impossible (OS error), else true
 */
static BOOL
attempt_write (struct io_facility * output_facility,
               struct io_facility * input_facility)
{
  switch (output_facility->facility_state)
    {
    case IOSTATE_READY:
      output_facility->buffer_size_written = 0;

continue_partial_write:
      if (! ResetEvent (output_facility->overlapped.hEvent))
        return FALSE;

      /* Check how the task was handled */
      if (WriteFile (output_facility->handle,
                          output_facility->buffer + output_facility->buffer_size_written,
                          output_facility->buffer_size - output_facility->buffer_size_written,
                          &output_facility->buffer_size_processed,
                          &output_facility->overlapped))
        {/* async event processed immediately*/

          fprintf (stderr, "DEBUG: write succeeded immediately\n");
          output_facility->buffer_size_written += output_facility->buffer_size_processed;

          /* reset event manually*/
          if (! SetEvent (output_facility->overlapped.hEvent))
            return FALSE;

          /* partial write */
          if (output_facility->buffer_size_written < output_facility->buffer_size)
            goto continue_partial_write;

          /* we are now waiting for our buffer to be filled*/
          output_facility->facility_state = IOSTATE_WAITING;

          /* we successfully wrote something and now need to reset our reader */
          if (IOSTATE_WAITING == input_facility->facility_state)
            input_facility->facility_state = IOSTATE_RESUME;
          else if (IOSTATE_FAILED == input_facility->facility_state)
            output_facility->path_open = FALSE;
        }
      else /* operation was either queued or failed*/
        {
          int err = GetLastError ();
          if (ERROR_IO_PENDING == err)
            { /* operation queued */
              output_facility->facility_state = IOSTATE_QUEUED;
            }
          else
            { /* error occurred, close this path */
              output_facility->path_open = FALSE;
              output_facility->facility_state = IOSTATE_FAILED;
              fprintf (stderr, "FATAL: Write to handle failed, exiting\n");
            }
        }
      return TRUE;
    case IOSTATE_QUEUED:
      // there was an operation going on already, check if that has completed now.

      if (GetOverlappedResult (output_facility->handle,
                                    &output_facility->overlapped,
                                    &output_facility->buffer_size_processed,
                                    FALSE))
        {/* successful return for a queued operation */
          if (! ResetEvent (output_facility->overlapped.hEvent))
            return FALSE;

          fprintf (stderr, "DEBUG: write succeeded delayed\n");
          output_facility->buffer_size_written += output_facility->buffer_size_processed;

          /* partial write */
          if (output_facility->buffer_size_written < output_facility->buffer_size)
            goto continue_partial_write;

          /* we are now waiting for our buffer to be filled*/
          output_facility->facility_state = IOSTATE_WAITING;

          /* we successfully wrote something and now need to reset our reader */
          if (IOSTATE_WAITING == input_facility->facility_state)
            input_facility->facility_state = IOSTATE_RESUME;
          else if (IOSTATE_FAILED == input_facility->facility_state)
            output_facility->path_open = FALSE;
        }
      else
        { /* operation still pending/queued or failed? */
          int err = GetLastError ();
          if ((ERROR_IO_INCOMPLETE != err) && (ERROR_IO_PENDING != err))
            { /* error occurred, close this path */
              output_facility->path_open = FALSE;
              output_facility->facility_state = IOSTATE_FAILED;
              fprintf (stderr, "FATAL: Write to handle failed, exiting\n");
            }
        }
    default:
      return TRUE;
    }
}


/**
 * Initialize a overlapped structure
 *
 * @param elem the element to initilize
 * @param initial_state the initial state for this instance
 * @param signaled if the hEvent created should default to signaled or not
 * @return true on success, else false
 */
static BOOL
initialize_io_facility (struct io_facility * elem,
                        int initial_state,
                        BOOL signaled)
{
  elem->path_open = TRUE;
  elem->handle = INVALID_HANDLE_VALUE;
  elem->facility_state = initial_state;
  elem->buffer_size = 0;
  elem->overlapped.hEvent = CreateEvent (NULL, TRUE, signaled, NULL);
  if (NULL == elem->overlapped.hEvent)
    return FALSE;

  return TRUE;
}


/**
 * Start forwarding to and from the tunnel.
 *
 * @param tap_handle device handle for interacting with the Virtual interface
 */
static void
run (HANDLE tap_handle)
{
  /* IO-Facility for reading from our virtual interface */
  struct io_facility tap_read;
  /* IO-Facility for writing to our virtual interface */
  struct io_facility tap_write;
  /* IO-Facility for reading from stdin */
  struct io_facility std_in;
  /* IO-Facility for writing to stdout */
  struct io_facility std_out;

  HANDLE parent_std_in_handle = GetStdHandle (STD_INPUT_HANDLE);
  HANDLE parent_std_out_handle = GetStdHandle (STD_OUTPUT_HANDLE);

  /* tun up: */
  /* we do this HERE and not beforehand (in init_tun()), in contrast to openvpn
   * to remove the need to flush the arp cache, handle DHCP and wrong IPs.
   *
   * DHCP and such are all features we will never use in gnunet afaik.
   * But for openvpn those are essential.
   */
  if ((privilege_testing) || (! tun_up (tap_handle)))
    goto teardown_final;

  /* Initialize our overlapped IO structures*/
  if (! (initialize_io_facility (&tap_read, IOSTATE_READY, FALSE)
        && initialize_io_facility (&tap_write, IOSTATE_WAITING, TRUE)
        && initialize_io_facility (&std_in, IOSTATE_READY, FALSE)
        && initialize_io_facility (&std_out, IOSTATE_WAITING, TRUE)))
    goto teardown_final;

  /* Handles for STDIN and STDOUT */
  tap_read.handle = tap_handle;
  tap_write.handle = tap_handle;

#ifdef DEBUG_TO_CONSOLE
  /* Debug output to console STDIN/STDOUT*/
  std_in.handle = parent_std_in_handle;
  std_out.handle = parent_std_out_handle;

#else
  fprintf (stderr, "DEBUG: reopening stdin/out for overlapped IO\n");
  /*
   * Find out the types of our handles.
   * This part is a problem, because in windows we need to handle files,
   * pipes and the console differently.
   */
  if ((FILE_TYPE_PIPE != GetFileType (parent_std_in_handle)) ||
      (FILE_TYPE_PIPE != GetFileType (parent_std_out_handle)))
    {
      fprintf (stderr, "ERROR: stdin/stdout must be named pipes\n");
      goto teardown;
    }

  std_in.handle = ReOpenFile (parent_std_in_handle,
                              GENERIC_READ,
                              FILE_SHARE_WRITE | FILE_SHARE_READ,
                              FILE_FLAG_OVERLAPPED);

  if (INVALID_HANDLE_VALUE == std_in.handle)
    {
      fprintf (stderr, "FATAL: Could not reopen stdin for in overlapped mode, has to be a named pipe\n");
      goto teardown;
    }

  std_out.handle = ReOpenFile (parent_std_out_handle,
                               GENERIC_WRITE,
                               FILE_SHARE_READ,
                               FILE_FLAG_OVERLAPPED);

  if (INVALID_HANDLE_VALUE == std_out.handle)
    {
      fprintf (stderr, "FATAL: Could not reopen stdout for in overlapped mode, has to be a named pipe\n");
      goto teardown;
    }
#endif

  fprintf (stderr, "DEBUG: mainloop has begun\n");

  while (std_out.path_open || tap_write.path_open)
    {
      /* perform READ from stdin if possible */
      if (std_in.path_open && (! attempt_read_stdin (&std_in, &tap_write)))
        break;

      /* perform READ from tap if possible */
      if (tap_read.path_open && (! attempt_read_tap (&tap_read, &std_out)))
        break;

      /* perform WRITE to tap if possible */
      if (tap_write.path_open && (! attempt_write (&tap_write, &std_in)))
        break;

      /* perform WRITE to STDOUT if possible */
      if (std_out.path_open && (! attempt_write (&std_out, &tap_read)))
        break;
    }

  fprintf (stderr, "DEBUG: teardown initiated\n");
teardown:
  CancelIo (tap_handle);
  CancelIo (std_in.handle);
  CancelIo (std_out.handle);
teardown_final:
  CloseHandle (tap_handle);
}


/**
 * Open VPN tunnel interface.
 *
 * @param argc must be 6
 * @param argv 0: binary name (gnunet-helper-vpn)
 *             [1: dryrun/testrun (does not execute mainloop)]
 *             2: tunnel interface prefix (gnunet-vpn)
 *             3: IPv6 address (::1), "-" to disable
 *             4: IPv6 netmask length in bits (64), ignored if #2 is "-"
 *             5: IPv4 address (1.2.3.4), "-" to disable
 *             6: IPv4 netmask (255.255.0.0), ignored if #4 is "-"
 */
int
main (int argc, char **argv)
{
  char hwid[LINE_LEN];
  HANDLE handle;
  int global_ret = 0;
  BOOL have_ip4 = FALSE;
  BOOL have_ip6 = FALSE;

  if (argc > 1 && 0 == strcmp (argv[1], "-d")){
      privilege_testing = TRUE;
      fprintf (stderr,
	       "%s",
	       "DEBUG: Running binary in privilege testing mode.");
      argv++;
      argc--;
    }

  if (6 != argc)
    {
      fprintf (stderr,
	       "%s",
	       "FATAL: must supply 5 arguments\nUsage:\ngnunet-helper-vpn [-d] <if name prefix> <address6 or \"-\"> <netbits6> <address4 or \"-\"> <netmask4>\n");
      return 1;
    }

  strncpy (hwid, argv[1], LINE_LEN);
  hwid[LINE_LEN - 1] = '\0';

  /*
   * We use our PID for finding/resolving the control-panel name of our virtual
   * device. PIDs are (of course) unique at runtime, thus we can safely use it
   * as additional hardware-id for our device.
   */
  snprintf (secondary_hwid, LINE_LEN / 2, "%s-%d",
            hwid,
            _getpid ());

  if (INVALID_HANDLE_VALUE == (handle = init_tun ()))
    {
      fprintf (stderr, "FATAL: could not initialize virtual-interface %s with IPv6 %s/%s and IPv4 %s/%s\n",
               hwid,
               argv[2],
               argv[3],
               argv[4],
               argv[5]);
      global_ret = -1;
      goto cleanup;
    }

  fprintf (stderr, "DEBUG: Setting IPs, if needed\n");
  if (0 != strcmp (argv[2], "-"))
    {
      const char *address = argv[2];
      long prefix_len = atol (argv[3]);

      if ((prefix_len < 1) || (prefix_len > 127))
        {
          fprintf (stderr, "FATAL: ipv6 prefix_len out of range\n");
          global_ret = -1;
          goto cleanup;
        }

      fprintf (stderr, "DEBUG: Setting IP6 address: %s/%d\n",address,prefix_len);
      if (0 != (global_ret = set_address6 (address, prefix_len)))
        goto cleanup;

      have_ip6 = TRUE;
    }

  if (0 != strcmp (argv[4], "-"))
    {
      const char *address = argv[4];
      const char *mask = argv[5];

      fprintf (stderr, "DEBUG: Setting IP4 address: %s/%s\n",address,mask);
      if (0 != (global_ret = set_address4 (address, mask)))
        goto cleanup;

      have_ip4 = TRUE;
    }

  run (handle);
cleanup:

  if (have_ip4)
    {
      const char *address = argv[4];
      fprintf (stderr, "DEBUG: Removing IP4 address\n");
      remove_address4 (address);
    }
  if (have_ip6)
    {
      const char *address = argv[2];
      fprintf (stderr, "DEBUG: Removing IP6 address\n");
      remove_address6 (address);
    }

  fprintf (stderr, "DEBUG: removing interface\n");
  remove_interface ();
  fprintf (stderr, "DEBUG: graceful exit completed\n");

  return global_ret;
}
