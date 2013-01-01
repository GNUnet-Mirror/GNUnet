/*
     This file is part of GNUnet.
     (C) 2010, 2012 Christian Grothoff

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
#include <windows.h>
#include <setupapi.h>
#include <ddk/cfgmgr32.h>
#include "platform.h"
#include "tap-windows.h"
#include <Winsock2.h>

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

/**
 * Maximum size of a GNUnet message (GNUNET_SERVER_MAX_MESSAGE_SIZE)
 */
#define MAX_SIZE 65536

/**
 * Name or Path+Name of our driver in Unicode.
 * The .sys and .cat files HAVE to be in the same location as this file!
 */
#define INF_FILE "tapw32.inf"

/**
 * Hardware ID used in the inf-file. 
 * This might change over time, as openvpn advances their driver
 */
#define HARDWARE_ID "TAP0901"

/**
 * Component ID if our driver
 */
#define TAP_WIN_COMPONENT_ID "tap0901"

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
 * TODO: is this fixed on all version of windows? Checked with XP and 7
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
 * inet_pton() wrapper for WSAStringToAddress()
 *
 * this is needed as long as we support WinXP, because only Vista+ support 
 * inet_pton at all, and mingw does not yet offer inet_pton/ntop at all
 * 
 * @param af - IN - the aftype this address is supposed to be (v4/v6) 
 * @param src - IN - the presentation form of the address
 * @param dst - OUT - the numerical form of the address
 * @return 0 on success, 1 on failure
 */
#if WINVER >= 0x0600
int inet_pton (int af, const char *src, void *dst);
#else

int
inet_pton (int af, const char *src, void *dst)
{
  struct sockaddr_storage addr;
  int size = sizeof (addr);
  char local_copy[INET6_ADDRSTRLEN + 1];

  ZeroMemory (&addr, sizeof (addr));
  /* stupid non-const API */
  strncpy (local_copy, src, INET6_ADDRSTRLEN + 1);
  local_copy[INET6_ADDRSTRLEN] = 0;

  if (WSAStringToAddressA (local_copy, af, NULL, (struct sockaddr *) &addr, &size) == 0)
    {
      switch (af)
        {
        case AF_INET:
          *(struct in_addr *) dst = ((struct sockaddr_in *) &addr)->sin_addr;
          return 1;
        case AF_INET6:
          *(struct in6_addr *) dst = ((struct sockaddr_in6 *) &addr)->sin6_addr;
          return 1;
        }
    }
  return 0;
}
#endif

/**
 * Wrapper for executing a shellcommand in windows.
 * 
 * @param command - the command + parameters to execute
 * @return * exitcode of the program executed, 
 *         * EINVAL (cmd/file not found)
 *         * EPIPE (could not read STDOUT)
 */
static int
execute_shellcommand (char * command)
{
  FILE *pipe;

  if (NULL == command ||
      NULL == (pipe = _popen (command, "rt")))
    return EINVAL;

#ifdef TESTING
  {
    char output[LINE_LEN];

    printf ("executed command: %s", command);
    while (NULL != fgets (output, sizeof (output), pipe))
      printf (output);
  }
#endif

  if (!feof (pipe))
    return EPIPE;

  return _pclose (pipe);
}

/**
 * @brief Sets the IPv6-Address given in address on the interface dev
 *
 * @param address the IPv6-Address
 * @param prefix_len the length of the network-prefix
 */
static void
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
      fprintf (stderr, "Failed to parse address `%s': %s\n", address,
               strerror (errno));
      exit (1);
    }

  /*
   * prepare the command
   */
  snprintf (command, LINE_LEN,
            "netsh interface ipv6 add address \"%s\" %s/%d",
            device_visible_name, address, prefix_len);
  /*
   * Set the address
   */
  ret = execute_shellcommand (command);

  /* Did it work?*/
  if (0 != ret)
    {
      fprintf (stderr, "Setting IPv6 address failed: %s\n", strerror (ret));
      exit (1); // FIXME: return error code, shut down interface / unload driver
    }
}

/**
 * @brief Sets the IPv4-Address given in address on the interface dev
 *
 * @param dev the interface to configure
 * @param address the IPv4-Address
 * @param mask the netmask
 */
static void
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
      fprintf (stderr, "Failed to parse address `%s': %s\n", address,
               strerror (errno));
      exit (1);
    }

  /*
   * prepare the command
   */
  snprintf (command, LINE_LEN,
            "netsh interface ipv4 add address \"%s\" %s %s",
            device_visible_name, address, mask);
  /*
   * Set the address
   */
  ret = execute_shellcommand (command);

  /* Did it work?*/
  if (0 != ret)
    {
      fprintf (stderr, "Setting IPv4 address failed: %s\n", strerror (ret));
      exit (1); // FIXME: return error code, shut down interface / unload driver
    }
}

/**
 * Setup a new virtual interface to use for tunneling. 
 * 
 * @return: TRUE if setup was successful, else FALSE
 */
static boolean
setup_interface ()
{
  /*
   * where to find our inf-file. (+ the "full" path, after windows found")
   * 
   * We do not directly input all the props here, because openvpn will update
   * these details over time.
   */
  char inf_file_path[MAX_PATH];
  char hwidlist[LINE_LEN + 4];
  char class_name[128];
  GUID class_guid;
  int str_lenth = 0;

  /** 
   * Set the device's hardware ID and add it to a list.
   * This information will later on identify this device in registry. 
   * 
   * TODO: Currently we just use TAP0901 as HWID, 
   * but we might want to add additional information
   */
  strncpy (hwidlist, HARDWARE_ID, LINE_LEN);
  /**
   * this is kind of over-complicated, but allows keeps things independent of 
   * how the openvpn-hwid is actually stored. 
   * 
   * A HWID list is double-\0 terminated and \0 separated
   */
  str_lenth = strlen (hwidlist) + 1;
  strncpy (&hwidlist[str_lenth], secondary_hwid, LINE_LEN - str_lenth);

  /** 
   * Locate the inf-file, we need to store it somewhere where the system can
   * find it. A good choice would be CWD/PDW or %WINDIR$\system32\
   * 
   * TODO: How about win64 in the future? 
   *       We need to use a different driver for amd64/i386 !
   */
  GetFullPathNameA (INF_FILE, MAX_PATH, inf_file_path, NULL);

  /** 
   * Bootstrap our device info using the drivers inf-file
   */
  if (!SetupDiGetINFClassA (inf_file_path,
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
  if (!SetupDiCreateDeviceInfoA (DeviceInfo,
                                 class_name,
                                 &class_guid,
                                 NULL,
                                 NULL,
                                 DICD_GENERATE_ID,
                                 &DeviceNode))
    return FALSE;

  /* Deploy all the information collected into the registry */
  if (!SetupDiSetDeviceRegistryPropertyA (DeviceInfo,
                                          &DeviceNode,
                                          SPDRP_HARDWAREID,
                                          (LPBYTE) hwidlist,
                                          (strlen (hwidlist) + 2) * sizeof (char)))
    return FALSE;

  /* Install our new class(=device) into the system */
  if (!SetupDiCallClassInstaller (DIF_REGISTERDEVICE,
                                  DeviceInfo,
                                  &DeviceNode))
    return FALSE;

  return TRUE;
}

/**
 * Remove our new virtual interface to use for tunneling. 
 * This function must be called AFTER setup_interface!
 * 
 * @return: TRUE if destruction was successful, else FALSE
 */
static boolean
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
  if (!SetupDiSetClassInstallParamsA (DeviceInfo,
                                      (PSP_DEVINFO_DATA) & DeviceNode,
                                      &remove.ClassInstallHeader,
                                      sizeof (remove)))
    return FALSE;
  /*
   * 2. Uninstall the virtual interface using the class installer
   */
  if (!SetupDiCallClassInstaller (DIF_REMOVE,
                                  DeviceInfo,
                                  (PSP_DEVINFO_DATA) & DeviceNode))
    return FALSE;

  SetupDiDestroyDeviceInfoList (DeviceInfo);

  return TRUE;
}

/**
 * Do all the lookup necessary to retrieve the inteface's actual name
 * off the registry. 
 * 
 * @return: TRUE if we were able to lookup the interface's name, else FALSE
 */
static boolean
resolve_interface_name ()
{

  SP_DEVINFO_LIST_DETAIL_DATA device_details;
  char pnp_instance_id [MAX_DEVICE_ID_LEN];
  HKEY adapter_key_handle;
  LONG status;
  DWORD len;
  int i = 0;
  boolean retval = FALSE;
  char adapter[] = INTERFACE_REGISTRY_LOCATION;

  /* We can obtain the PNP instance ID from our setupapi handle */
  device_details.cbSize = sizeof (device_details);
  if (CR_SUCCESS != CM_Get_Device_ID_ExA (DeviceNode.DevInst,
                                          (PCHAR) pnp_instance_id,
                                          MAX_DEVICE_ID_LEN,
                                          0, //must be 0
                                          NULL)) //hMachine, we are local
    return FALSE;

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

      len = sizeof (adapter_key_handle);
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
                INTERFACE_REGISTRY_LOCATION,
                instance_key);

      /* look inside instance_key\\Connection */
      status = RegOpenKeyExA (
                              HKEY_LOCAL_MACHINE,
                              query_key,
                              0,
                              KEY_READ,
                              &instance_key_handle);

      if (status != ERROR_SUCCESS)
        continue;

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

cleanup:
      RegCloseKey (instance_key_handle);

      ++i;
    }

  RegCloseKey (adapter_key_handle);

  return retval;
}

static boolean
check_tapw32_version (HANDLE handle)
{
  {
    ULONG version[3];
    DWORD len;
    memset (&(version), 0, sizeof (version));


    if (DeviceIoControl (handle, TAP_WIN_IOCTL_GET_VERSION,
                         &version, sizeof (version),
                         &version, sizeof (version), &len, NULL))
      {
#ifdef TESTING
        fprintf (stderr, "TAP-Windows Driver Version %d.%d %s",
                 (int) version[0],
                 (int) version[1],
                 (version[2] ? "(DEBUG)" : ""));
#endif
      }

    if (version[0] != TAP_WIN_MIN_MAJOR || version[1] < TAP_WIN_MIN_MINOR)
      {
        fprintf (stderr, "ERROR:  This version of gnunet requires a TAP-Windows driver that is at least version %d.%d!\n",
                 TAP_WIN_MIN_MAJOR,
                 TAP_WIN_MIN_MINOR);
        return FALSE;
      }
    return TRUE;
  }
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

  if (!setup_interface ())
    {
      errno = ENODEV;
      return INVALID_HANDLE_VALUE;
    }

  if (!resolve_interface_name ())
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

  if (handle == INVALID_HANDLE_VALUE)
    {
      fprintf (stderr, "CreateFile failed on TAP device: %s\n", device_path);
      return handle;
    }

  /* get driver version info */
  if (!check_tapw32_version (handle))
    {
      CloseHandle (handle);
      return INVALID_HANDLE_VALUE;
    }
  
  /* TODO (opt?): get MTU-Size */

  return handle;
}

static boolean
tun_up (HANDLE handle)
{
  ULONG status = TRUE;
  DWORD len;
  if (DeviceIoControl (handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                       &status, sizeof (status),
                       &status, sizeof (status), &len, NULL))
    {
      fprintf (stderr, "The TAP-Windows driver ignored our request to set the interface UP (TAP_WIN_IOCTL_SET_MEDIA_STATUS DeviceIoControl call)!\n");
      return FALSE;
    }

  /* Wait for the device to go UP, might take some time. */
  Sleep ((TAP32_POSTUP_WAITTIME)*1000);

  return TRUE;

}

/**
 * Start forwarding to and from the tunnel.
 *
 * @param fd_tun tunnel FD
 */
static void
run (HANDLE handle)
{
  /*
   * The buffer filled by reading from fd_tun
   */
  unsigned char buftun[MAX_SIZE];
  ssize_t buftun_size = 0;
  unsigned char *buftun_read = NULL;

  /*
   * The buffer filled by reading from stdin
   */
  unsigned char bufin[MAX_SIZE];
  ssize_t bufin_size = 0;
  ssize_t bufin_rpos = 0;
  unsigned char *bufin_read = NULL;

  //openvpn  
  // Set Device to Subnet-Mode? 
  // do we really need tun.c:2925 ?
  // Why does openvpn assign IPv4's there??? Foobar??

  /* tun up: */
  /* we do this HERE and not beforehand (in init_tun()), in contrast to openvpn
   * to remove the need to flush the arp cache, handle DHCP and wrong IPs.
   *  
   * DHCP and such are all features we will never use in gnunet afaik.
   * But for openvpn those are essential.
   */
  if (!tun_up (handle))
    goto teardown;
 
  fd_set fds_w;
  fd_set fds_r;

  /* read refers to reading from fd_tun, writing to stdout */
  int read_open = 1;

  /* write refers to reading from stdin, writing to fd_tun */
  int write_open = 1;

  // Setup should be complete here.
  // If something is missing, check init.c:3400+
  
  // mainloop:
  // tunnel_point_to_point
  // openvpn.c:62
  
  while ((1 == read_open) || (1 == write_open))
  {
    FD_ZERO (&fds_w);
    FD_ZERO (&fds_r);
    
    // openvpn.c:80 ?
    
    /*
     * We are supposed to read and the buffer is empty
     * -> select on read from tun
     */
    if (read_open && (0 == buftun_size))
    //  FD_SET (fd_tun, &fds_r);
      ;

    /*
     * We are supposed to read and the buffer is not empty
     * -> select on write to stdout
     */
    if (read_open && (0 != buftun_size))
      FD_SET (1, &fds_w);

    /*
     * We are supposed to write and the buffer is empty
     * -> select on read from stdin
     */
    if (write_open && (NULL == bufin_read))
      FD_SET (0, &fds_r);

    /*
     * We are supposed to write and the buffer is not empty
     * -> select on write to tun
     */
    if (write_open && (NULL != bufin_read))
    //  FD_SET (fd_tun, &fds_w);
      ;


  // init.c:3337
  /* setup ansync IO */
  //forward.c: 1515

    }
teardown:
  ;
  //init.c:3472
}

/**
 * Open VPN tunnel interface.
 *
 * @param argc must be 6
 * @param argv 0: binary name (gnunet-helper-vpn)
 *             1: tunnel interface name (gnunet-vpn)
 *             2: IPv6 address (::1), "-" to disable
 *             3: IPv6 netmask length in bits (64), ignored if #2 is "-"
 *             4: IPv4 address (1.2.3.4), "-" to disable
 *             5: IPv4 netmask (255.255.0.0), ignored if #4 is "-"
 */
int
main (int argc, char **argv)
{
  char hwid[LINE_LEN];
  HANDLE handle;
  int global_ret;

  if (6 != argc)
    {
      fprintf (stderr, "Fatal: must supply 5 arguments!\n");
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
      fprintf (stderr, "Fatal: could not initialize virtual-interface %s with IPv6 %s/%s and IPv4 %s/%s\n",
               hwid,
               argv[2],
               argv[3],
               argv[4],
               argv[5]);
      return 1;
    }

  if (0 != strcmp (argv[2], "-"))
    {
      const char *address = argv[2];
      long prefix_len = atol (argv[3]);

      if ((prefix_len < 1) || (prefix_len > 127))
        {
          fprintf (stderr, "Fatal: prefix_len out of range\n");
          global_ret = -1;
          goto cleanup;
        }

      set_address6 (address, prefix_len);
    }

  if (0 != strcmp (argv[4], "-"))
    {
      const char *address = argv[4];
      const char *mask = argv[5];

      set_address4 (address, mask);
    }

  //eventuell: 
  // tap_allow_nonadmin_access
  //tun.c:2023

  run (handle);
  global_ret = 0;
cleanup:
  remove_interface ();

  return global_ret;
}
