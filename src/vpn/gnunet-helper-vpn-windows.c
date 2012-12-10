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
#include <tchar.h>
#include <windows.h>
#include <setupapi.h>
#include "platform.h"

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
#define INF_FILE _T("tapw32.inf")

/**
 * Hardware ID used in the inf-file. 
 * This might change over time, as openvpn advances their driver
 */
#define HARDWARE_ID _T("TAP0901")

/*
 * Our local process' PID. Used for creating a sufficiently unique additional 
 * hardware ID for our device.
 */
static TCHAR secondary_hwid[LINE_LEN / 2];

/*
 * Device's Friendly Name, used to identify a network device in netsh.
 * eg: "TAP-Windows Adapter V9 #4"
 */
static TCHAR device_friendly_name[LINE_LEN / 2];
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
 * Class-tag of our virtual device
 */
static TCHAR class[128];

/**
 * GUID of our virtual device in the form of 
 * {12345678-1234-1234-1234-123456789abc} - in hex
 */
static GUID guid;

/**
 * @brief Sets the IPv6-Address given in address on the interface dev
 *
 * @param address the IPv6-Address
 * @param prefix_len the length of the network-prefix
 */
static void
set_address6 (const char *address, unsigned long prefix_len)
{
  int fd = -1;

  /*
   * parse the new address
   */

  /*
   * Get the index of the if
   */

  /*
   * Set the address
   */

  /*
   * Get the flags
   */


  /*
   * Add the UP and RUNNING flags
   */


  if (0 != close (fd))
    {
      fprintf (stderr, "close failed: %s\n", strerror (errno));
      exit (1);
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
set_address4 (const char *dev, const char *address, const char *mask)
{
  int fd = -1;

  /*
   * Parse the address
   */

  /*
   * Set the address
   */

  /*
   * Parse the netmask
   */


  /*
   * Set the netmask
   */


  /*
   * Get the flags
   */


  /*
   * Add the UP and RUNNING flags
   */


  if (0 != close (fd))
    {
      fprintf (stderr, "close failed: %s\n", strerror (errno));
      (void) close (fd);
      exit (1);
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
  TCHAR inf_file_path[MAX_PATH];
  TCHAR hwidlist[LINE_LEN + 4];
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
  str_lenth = strlen (hwidlist) + 1 ;
  hwidlist[str_lenth] = _T("\0");
  strncpy (&hwidlist[str_lenth], secondary_hwid, LINE_LEN - str_lenth);
  
  /** 
   * Locate the inf-file, we need to store it somewhere where the system can
   * find it. A good choice would be CWD/PDW or %WINDIR$\system32\
   * 
   * TODO: How about win64 in the future? 
   *       We need to use a different driver for amd64/i386 !
   */
  GetFullPathName (INF_FILE, MAX_PATH, inf_file_path, NULL);

  /** 
   * Bootstrap our device info using the drivers inf-file
   */
  if (!SetupDiGetINFClass (inf_file_path,
                           &guid,
                           class, sizeof (class) / sizeof (TCHAR),
                           NULL))
      return FALSE;
  
  /** 
   * Collect all the other needed information... 
   * let the system fill our this form 
   */
  DeviceInfo = SetupDiCreateDeviceInfoList (&guid, NULL);
  if (DeviceInfo == INVALID_HANDLE_VALUE)
      return FALSE;
  
  DeviceNode.cbSize = sizeof (SP_DEVINFO_DATA);
  if (! SetupDiCreateDeviceInfo (DeviceInfo,
                                class,
                                &guid,
                                NULL,
                                NULL,
                                DICD_GENERATE_ID,
                                &DeviceNode))
      return FALSE;
  
  /* Deploy all the information collected into the registry */
  if (!SetupDiSetDeviceRegistryProperty (DeviceInfo,
                                         &DeviceNode,
                                         SPDRP_HARDWAREID,
                                         (LPBYTE) hwidlist,
                                         (lstrlen (hwidlist) + 2) * sizeof (TCHAR)))
      return FALSE;
  
  /* Install our new class(=device) into the system */
  if (! SetupDiCallClassInstaller (DIF_REGISTERDEVICE,
                                 DeviceInfo,
                                 &DeviceNode))
      return FALSE;
  
  /* Now, pull the device device's FriendlyName off the registry. */
  if ( !SetupDiGetDeviceRegistryProperty(DeviceInfo,
                                   (PSP_DEVINFO_DATA) & DeviceNode,
                                   SPDRP_FRIENDLYNAME,
                                   NULL,
                                   (LPBYTE)device_friendly_name,
                                   LINE_LEN / 2,
                                   NULL) || strlen(device_friendly_name) < 1){
      return FALSE;
    }
  device_friendly_name[LINE_LEN / 2 - 1] = _T("\0");
  
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
  if (! SetupDiSetClassInstallParams (DeviceInfo,
				      (PSP_DEVINFO_DATA) &DeviceNode,
				      &remove.ClassInstallHeader,
				      sizeof (remove)))
    return FALSE;
  /*
   * 2. Uninstall the virtual interface using the class installer
   */
  if (! SetupDiCallClassInstaller (DIF_REMOVE, 
				   DeviceInfo, 
				   (PSP_DEVINFO_DATA) &DeviceNode))
    return FALSE;
  
  SetupDiDestroyDeviceInfoList(DeviceInfo);
  
  return TRUE;
}

/**
 * Creates a tun-interface called dev;
 *
 * @param hwid is asumed to point to a TCHAR[LINE_LEN]
 *        if *dev == '\\0', uses the name supplied by the kernel;
 * @return the fd to the tun or -1 on error
 */
static int
init_tun (TCHAR *hwid)
{
  int fd;

  if (NULL == hwid)
    {
      errno = EINVAL;
      return -1;
    }

  if (! setup_interface()){
      errno = ENODEV;
      return -1;
    }
  
  
  return fd;
}

/**
 * Start forwarding to and from the tunnel.
 *
 * @param fd_tun tunnel FD
 */
static void
run (int fd_tun)
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
  /* Hello, I am a stub function! I did my job, yay me! */

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
  TCHAR hwid[LINE_LEN];
  TCHAR pid_as_string[LINE_LEN / 4];
  int fd_tun;
  int global_ret;
  
  if (6 != argc)
    {
      fprintf (stderr, "Fatal: must supply 5 arguments!\n");
      return 1;
    }

   strncpy (hwid, argv[1], LINE_LEN);
   hwid[LINE_LEN - 1] = _T('\0');
   
   /* 
   * We use our PID for finding/resolving the control-panel name of our virtual 
   * device. PIDs are (of course) unique at runtime, thus we can safely use it 
   * as additional hardware-id for our device.
   */
  _itot(_getpid(), pid_as_string, 10);
  strncpy (secondary_hwid, hwid, LINE_LEN); 
  strncat (secondary_hwid, pid_as_string, LINE_LEN); 

  if (-1 == (fd_tun = init_tun (hwid)))
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
          return 1;
        }

      set_address6 (address, prefix_len);
    }

  if (0 != strcmp (argv[4], "-"))
    {
      const char *address = argv[4];
      const char *mask = argv[5];

      set_address4 (NULL, address, mask);
    }

  if (setup_interface ())
    {
      ;
    }

  /*
  uid_t uid = getuid ();
  if (0 != setresuid (uid, uid, uid))
  {
    fprintf (stderr, "Failed to setresuid: %s\n", strerror (errno));
    global_ret = 2;
    goto cleanup;
  }
   */

  /*if (SIG_ERR == signal (SIGPIPE, SIG_IGN))
  {
    fprintf (stderr, "Failed to protect against SIGPIPE: %s\n",
             strerror (errno));
    // no exit, we might as well die with SIGPIPE should it ever happen 
  }
   */
  //run (fd_tun);
  global_ret = 0;
cleanup:
  remove_interface();

  return global_ret;
}
