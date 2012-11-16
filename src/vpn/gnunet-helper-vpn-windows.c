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
 * Creates a tun-interface called dev;
 *
 * @param dev is asumed to point to a char[IFNAMSIZ]
 *        if *dev == '\\0', uses the name supplied by the kernel;
 * @return the fd to the tun or -1 on error
 */
static int
init_tun (char *dev)
{
  int fd;

  if (NULL == dev)
  {
    errno = EINVAL;
    return -1;
  }

  /* Hello, I am a stub function! I did my job, yay me! */
  
  return fd;
}


/**
 * @brief Sets the IPv6-Address given in address on the interface dev
 *
 * @param dev the interface to configure
 * @param address the IPv6-Address
 * @param prefix_len the length of the network-prefix
 */
static void
set_address6 (const char *dev, const char *address, unsigned long prefix_len)
{
  int fd=0;

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
  int fd=0;

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
  size_t bufin_rpos = 0;
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
  //char dev[IFNAMSIZ];
  int fd_tun;
  int global_ret;

  if (6 != argc)
  {
    fprintf (stderr, "Fatal: must supply 5 arguments!\n");
    return 1;
  }

  /*
   * strncpy (dev, argv[1], IFNAMSIZ);
   * dev[IFNAMSIZ - 1] = '\0';
   */
/*  if (-1 == (fd_tun = init_tun (dev)))
  {
    fprintf (stderr, "Fatal: could not initialize tun-interface  with IPv6 %s/%s and IPv4 %s/%s\n",
	     dev,
	     argv[2],
	     argv[3],
	     argv[4],
	     argv[5]);
    return 1;
  }
 */ 

  if (0 != strcmp (argv[2], "-"))
  {
    const char *address = argv[2];
    long prefix_len = atol (argv[3]);

    if ((prefix_len < 1) || (prefix_len > 127))
    {
      fprintf (stderr, "Fatal: prefix_len out of range\n");
      return 1;
    }

    //set_address6 (dev, address, prefix_len);
  }

  if (0 != strcmp (argv[4], "-"))
  {
    const char *address = argv[4];
    const char *mask = argv[5];

    set_address4 (NULL, address, mask);
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
  //close (fd_tun);
  return global_ret;
}
