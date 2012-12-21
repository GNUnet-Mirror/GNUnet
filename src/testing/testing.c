/*
      This file is part of GNUnet
      (C) 2008, 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file testing/testing.c
 * @brief convenience API for writing testcases for GNUnet
 *        Many testcases need to start and stop a peer/service
 *        and this library is supposed to make that easier
 *        for TESTCASES.  Normal programs should always
 *        use functions from gnunet_{util,arm}_lib.h.  This API is
 *        ONLY for writing testcases (or internal use of the testbed).
 * @author Christian Grothoff
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"

#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "testing-api", __VA_ARGS__)


/**
 * We need pipe control only on WINDOWS
 */
#if WINDOWS
#define PIPE_CONTROL GNUNET_YES
#else
#define PIPE_CONTROL GNUNET_NO
#endif


/**
 * Lowest port used for GNUnet testing.  Should be high enough to not
 * conflict with other applications running on the hosts but be low
 * enough to not conflict with client-ports (typically starting around
 * 32k).
 */
#define LOW_PORT 12000

/**
 * Highest port used for GNUnet testing.  Should be low enough to not
 * conflict with the port range for "local" ports (client apps; see
 * /proc/sys/net/ipv4/ip_local_port_range on Linux for example).
 */
#define HIGH_PORT 56000


/**
 * Handle for a system on which GNUnet peers are executed;
 * a system is used for reserving unique paths and ports.
 */
struct GNUNET_TESTING_System
{
  /**
   * Prefix (i.e. "/tmp/gnunet-testing/") we prepend to each
   * SERVICEHOME.    */
  char *tmppath;

  /**
   * The trusted ip. Can either be a single ip address or a network address in
   * CIDR notation.
   */
  char *trusted_ip;

  /**
   * our hostname
   */
  char *hostname;

  /**
   * Hostkeys data, contains "GNUNET_TESTING_HOSTKEYFILESIZE * total_hostkeys" bytes.
   */
  char *hostkeys_data;

  /**
   * memory map for 'hostkeys_data'.
   */
  struct GNUNET_DISK_MapHandle *map;

  /**
   * File descriptor for the map.
   */
  struct GNUNET_DISK_FileHandle *map_fd;

  /**
   * Bitmap where each TCP port that has already been reserved for
   * some GNUnet peer is recorded.  Note that we additionally need to
   * test if a port is already in use by non-GNUnet components before
   * assigning it to a peer/service.  If we detect that a port is
   * already in use, we also mark it in this bitmap.  So all the bits
   * that are zero merely indicate ports that MIGHT be available for
   * peers.
   */
  uint32_t reserved_tcp_ports[65536 / 32];

  /**
   * Bitmap where each UDP port that has already been reserved for
   * some GNUnet peer is recorded.  Note that we additionally need to
   * test if a port is already in use by non-GNUnet components before
   * assigning it to a peer/service.  If we detect that a port is
   * already in use, we also mark it in this bitmap.  So all the bits
   * that are zero merely indicate ports that MIGHT be available for
   * peers.
   */
  uint32_t reserved_udp_ports[65536 / 32];

  /**
   * Counter we use to make service home paths unique on this system;
   * the full path consists of the tmppath and this number.  Each
   * UNIXPATH for a peer is also modified to include the respective
   * path counter to ensure uniqueness.  This field is incremented
   * by one for each configured peer.  Even if peers are destroyed,
   * we never re-use path counters.
   */
  uint32_t path_counter;  

  /**
   * The number of hostkeys
   */
  uint32_t total_hostkeys;

  /**
   * Lowest port we are allowed to use.
   */
  uint16_t lowport;

  /**
   * Highest port we are allowed to use.
   */
  uint16_t highport;
};


/**
 * Handle for a GNUnet peer controlled by testing.
 */
struct GNUNET_TESTING_Peer
{
  /**
   * The TESTING system associated with this peer
   */
  struct GNUNET_TESTING_System *system;

  /**
   * Path to the configuration file for this peer.
   */
  char *cfgfile;

  /**
   * Binary to be executed during 'GNUNET_TESTING_peer_start'.
   * Typically 'gnunet-service-arm' (but can be set to a 
   * specific service by 'GNUNET_TESTING_service_run' if
   * necessary).
   */ 
  char *main_binary;
  char *args;
  
  /**
   * Handle to the running binary of the service, NULL if the
   * peer/service is currently not running.
   */
  struct GNUNET_OS_Process *main_process;

  /**
   * The keynumber of this peer's hostkey
   */
  uint32_t key_number;
};


/**
 * Testing includes a number of pre-created hostkeys for faster peer
 * startup. This function loads such keys into memory from a file.
 *
 * @param system the testing system handle
 * @return GNUNET_OK on success; GNUNET_SYSERR on error
 */
static int
hostkeys_load (struct GNUNET_TESTING_System *system)
{
  uint64_t fs; 
  char *data_dir;
  char *filename;
  
  GNUNET_assert (NULL == system->hostkeys_data);
  data_dir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  GNUNET_asprintf (&filename, "%s/testing_hostkeys.dat", data_dir);
  GNUNET_free (data_dir);  

  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Hostkeys file not found: %s\n"), filename);
    GNUNET_free (filename);
    return GNUNET_SYSERR;
  }
  /* Check hostkey file size, read entire thing into memory */
  if (GNUNET_OK != 
      GNUNET_DISK_file_size (filename, &fs, GNUNET_YES, GNUNET_YES))
    fs = 0;
  if (0 == fs)
  {
    GNUNET_free (filename);
    return GNUNET_SYSERR;       /* File is empty */
  }
  if (0 != (fs % GNUNET_TESTING_HOSTKEYFILESIZE))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Incorrect hostkey file format: %s\n"), filename);
    GNUNET_free (filename);
    return GNUNET_SYSERR;
  }
  system->map_fd = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
					 GNUNET_DISK_PERM_NONE);
  if (NULL == system->map_fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", filename);
    GNUNET_free (filename);
    return GNUNET_SYSERR;
  }
  system->total_hostkeys = fs / GNUNET_TESTING_HOSTKEYFILESIZE;
  system->hostkeys_data = GNUNET_DISK_file_map (system->map_fd,
						&system->map,
						GNUNET_DISK_MAP_TYPE_READ,
						fs);
  GNUNET_free (filename);
  return GNUNET_OK;
}


/**
 * Function to remove the loaded hostkeys
 *
 * @param system the testing system handle
 */
static void
hostkeys_unload (struct GNUNET_TESTING_System *system)
{
  GNUNET_break (NULL != system->hostkeys_data);
  system->hostkeys_data = NULL;
  GNUNET_DISK_file_unmap (system->map);
  system->map = NULL;
  GNUNET_DISK_file_close (system->map_fd);
  system->map_fd = NULL;
  system->hostkeys_data = NULL;
  system->total_hostkeys = 0;
}


/**
 * Create a system handle.  There must only be one system
 * handle per operating system.
 *
 * @param testdir only the directory name without any path. This is used for
 *          all service homes; the directory will be created in a temporary
 *          location depending on the underlying OS
 * @param trusted_ip the ip address which will be set as TRUSTED HOST in all
 *          service configurations generated to allow control connections from
 *          this ip. This can either be a single ip address or a network address
 *          in CIDR notation.
 * @param hostname the hostname of the system we are using for testing; NULL for
 *          localhost
 * @param lowport lowest port number this system is allowed to allocate (inclusive)
 * @param highport highest port number this system is allowed to allocate (exclusive)
 * @return handle to this system, NULL on error
 */
struct GNUNET_TESTING_System *
GNUNET_TESTING_system_create_with_portrange (const char *testdir,
					     const char *trusted_ip,
					     const char *hostname,
					     uint16_t lowport,
					     uint16_t highport)
{
  struct GNUNET_TESTING_System *system;

  GNUNET_assert (NULL != testdir);
  system = GNUNET_malloc (sizeof (struct GNUNET_TESTING_System));
  system->tmppath = GNUNET_DISK_mkdtemp (testdir);
  system->lowport = lowport;
  system->highport = highport;
  if (NULL == system->tmppath)
  {
    GNUNET_free (system);
    return NULL;
  }
  if (NULL != trusted_ip)
    system->trusted_ip = GNUNET_strdup (trusted_ip);
  if (NULL != hostname)
    system->hostname = GNUNET_strdup (hostname);
  if (GNUNET_OK != hostkeys_load (system))
  {
    GNUNET_TESTING_system_destroy (system, GNUNET_YES);
    return NULL;
  }
  return system;
}


/**
 * Create a system handle.  There must only be one system handle per operating
 * system.  Uses a default range for allowed ports.  Ports are still tested for
 * availability.
 *
 * @param testdir only the directory name without any path. This is used for all
 *          service homes; the directory will be created in a temporary location
 *          depending on the underlying OS
 * @param trusted_ip the ip address which will be set as TRUSTED HOST in all
 *          service configurations generated to allow control connections from
 *          this ip. This can either be a single ip address or a network address
 *          in CIDR notation.
 * @param hostname the hostname of the system we are using for testing; NULL for
 *          localhost
 * @return handle to this system, NULL on error
 */
struct GNUNET_TESTING_System *
GNUNET_TESTING_system_create (const char *testdir,
			      const char *trusted_ip,
			      const char *hostname)
{
  return GNUNET_TESTING_system_create_with_portrange (testdir,
						      trusted_ip,
						      hostname,
						      LOW_PORT,
						      HIGH_PORT);
}


/**
 * Free system resources.
 *
 * @param system system to be freed
 * @param remove_paths should the 'testdir' and all subdirectories
 *        be removed (clean up on shutdown)?
 */
void
GNUNET_TESTING_system_destroy (struct GNUNET_TESTING_System *system,
			       int remove_paths)
{
  if (NULL != system->hostkeys_data)
    hostkeys_unload (system);
  if (GNUNET_YES == remove_paths)
    GNUNET_DISK_directory_remove (system->tmppath);
  GNUNET_free (system->tmppath);
  GNUNET_free_non_null (system->trusted_ip);
  GNUNET_free_non_null (system->hostname);
  GNUNET_free (system);
}


/**
 * Reserve a TCP or UDP port for a peer.
 *
 * @param system system to use for reservation tracking
 * @param is_tcp GNUNET_YES for TCP ports, GNUNET_NO for UDP
 * @return 0 if no free port was available
 */
uint16_t 
GNUNET_TESTING_reserve_port (struct GNUNET_TESTING_System *system,
			     int is_tcp)
{
  struct GNUNET_NETWORK_Handle *socket;
  struct addrinfo hint;
  struct addrinfo *ret;
  struct addrinfo *ai;
  uint32_t *port_buckets;
  char *open_port_str;
  int bind_status;
  uint32_t xor_image;
  uint16_t index;
  uint16_t open_port;
  uint16_t pos;

  /*
  FIXME: Instead of using getaddrinfo we should try to determine the port
         status by the following heurestics.
  
	 On systems which support both IPv4 and IPv6, only ports open on both
	 address families are considered open.
	 On system with either IPv4 or IPv6. A port is considered open if it's
	 open in the respective address family
  */
  hint.ai_family = AF_UNSPEC;	/* IPv4 and IPv6 */
  hint.ai_socktype = (GNUNET_YES == is_tcp)? SOCK_STREAM : SOCK_DGRAM;
  hint.ai_protocol = 0;
  hint.ai_addrlen = 0;
  hint.ai_addr = NULL;
  hint.ai_canonname = NULL;
  hint.ai_next = NULL;
  hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV;	/* Wild card address */
  port_buckets = (GNUNET_YES == is_tcp) ?
    system->reserved_tcp_ports : system->reserved_udp_ports;
  for (index = (system->lowport / 32) + 1; index < (system->highport / 32); index++)
  {
    xor_image = (UINT32_MAX ^ port_buckets[index]);
    if (0 == xor_image)        /* Ports in the bucket are full */
      continue;
    pos = system->lowport % 32;
    while (pos < 32)
    {
      if (0 == ((xor_image >> pos) & 1U))
      {
        pos++;
        continue;
      }
      open_port = (index * 32) + pos;
      if (open_port >= system->highport)
	return 0;
      GNUNET_asprintf (&open_port_str, "%u", (unsigned int) open_port);
      ret = NULL;
      GNUNET_assert (0 == getaddrinfo (NULL, open_port_str, &hint, &ret));
      GNUNET_free (open_port_str);
      bind_status = GNUNET_NO;
      for (ai = ret; NULL != ai; ai = ai->ai_next)
      {
        socket = GNUNET_NETWORK_socket_create (ai->ai_family,
                                               (GNUNET_YES == is_tcp) ?
                                               SOCK_STREAM : SOCK_DGRAM,
                                               0);
        if (NULL == socket)
          continue;
        bind_status = GNUNET_NETWORK_socket_bind (socket,
                                                  ai->ai_addr,
                                                  ai->ai_addrlen);
        GNUNET_NETWORK_socket_close (socket);
        if (GNUNET_OK != bind_status)
          break;
      }
      port_buckets[index] |= (1U << pos); /* Set the port bit */
      freeaddrinfo (ret);
      if (GNUNET_OK == bind_status)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Found a free port %u\n", (unsigned int) open_port);
	return open_port;
      }
      pos++;
    }
  }
  return 0;
}


/**
 * Release reservation of a TCP or UDP port for a peer
 * (used during GNUNET_TESTING_peer_destroy).
 *
 * @param system system to use for reservation tracking
 * @param is_tcp GNUNET_YES for TCP ports, GNUNET_NO for UDP
 * @param port reserved port to release
 */
void
GNUNET_TESTING_release_port (struct GNUNET_TESTING_System *system,
			     int is_tcp,
			     uint16_t port)
{
  uint32_t *port_buckets;
  uint16_t bucket;
  uint16_t pos;

  port_buckets = (GNUNET_YES == is_tcp) ?
    system->reserved_tcp_ports : system->reserved_udp_ports;
  bucket = port / 32;
  pos = port % 32;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Releasing port %u\n", port);
  if (0 == (port_buckets[bucket] & (1U << pos)))
  {
    GNUNET_break(0); /* Port was not reserved by us using reserve_port() */
    return;
  }
  port_buckets[bucket] &= ~(1U << pos);
}


/**
 * Reserve a SERVICEHOME path for a peer.
 *
 * @param system system to use for reservation tracking
 * @return NULL on error, otherwise fresh unique path to use
 *         as the servicehome for the peer; must be freed by the caller
 */
// static 
char *
reserve_path (struct GNUNET_TESTING_System *system)
{
  char *reserved_path;

  GNUNET_asprintf (&reserved_path,
                   "%s/%u", system->tmppath, system->path_counter++);
  return reserved_path;
}	      


/**
 * Testing includes a number of pre-created hostkeys for
 * faster peer startup.  This function can be used to
 * access the n-th key of those pre-created hostkeys; note
 * that these keys are ONLY useful for testing and not
 * secure as the private keys are part of the public 
 * GNUnet source code.
 *
 * This is primarily a helper function used internally
 * by 'GNUNET_TESTING_peer_configure'.
 *
 * @param system the testing system handle
 * @param key_number desired pre-created hostkey to obtain
 * @param id set to the peer's identity (hash of the public
 *        key; if NULL, GNUNET_SYSERR is returned immediately
 * @return NULL on error (not enough keys)
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_TESTING_hostkey_get (const struct GNUNET_TESTING_System *system,
			    uint32_t key_number,
			    struct GNUNET_PeerIdentity *id)
{  
  struct GNUNET_CRYPTO_RsaPrivateKey *private_key;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;
  
  if ((NULL == id) || (NULL == system->hostkeys_data))
    return NULL;
  if (key_number >= system->total_hostkeys)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Key number %u does not exist\n"), key_number);
    return NULL;
  }   
  private_key = GNUNET_CRYPTO_rsa_decode_key (system->hostkeys_data +
                                              (key_number *
                                               GNUNET_TESTING_HOSTKEYFILESIZE),
                                              GNUNET_TESTING_HOSTKEYFILESIZE);
  if (NULL == private_key)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Error while decoding key %u\n"), key_number);
    return NULL;
  }
  GNUNET_CRYPTO_rsa_key_get_public (private_key, &public_key);
  GNUNET_CRYPTO_hash (&public_key,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &(id->hashPubKey));
  return private_key;
}


/**
 * Structure for holding data to build new configurations from a configuration
 * template
 */
struct UpdateContext
{
  /**
   * The system for which we are building configurations
   */
  struct GNUNET_TESTING_System *system;
  
  /**
   * The configuration we are building
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The customized service home path for this peer
   */
  char *service_home;

  /**
   * build status - to signal error while building a configuration
   */
  int status;
};


/**
 * Function to iterate over options.  Copies
 * the options to the target configuration,
 * updating PORT values as needed.
 *
 * @param cls the UpdateContext
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
update_config (void *cls, const char *section, const char *option,
               const char *value)
{
  struct UpdateContext *uc = cls;
  unsigned int ival;
  char cval[12];
  char uval[128];
  char *single_variable;
  char *per_host_variable;
  unsigned long long num_per_host;
  uint16_t new_port;

  if (GNUNET_OK != uc->status)
    return;
  if (! ((0 == strcmp (option, "PORT"))
         || (0 == strcmp (option, "UNIXPATH"))
         || (0 == strcmp (option, "HOSTNAME"))))
    return;
  GNUNET_asprintf (&single_variable, "single_%s_per_host", section);
  GNUNET_asprintf (&per_host_variable, "num_%s_per_host", section);
  if ((0 == strcmp (option, "PORT")) && (1 == SSCANF (value, "%u", &ival)))
  {
    if ((ival != 0) &&
        (GNUNET_YES !=
         GNUNET_CONFIGURATION_get_value_yesno (uc->cfg, "testing",
                                               single_variable)))
    {
      /* FIXME: What about UDP? */
      new_port = GNUNET_TESTING_reserve_port (uc->system, GNUNET_YES);
      if (0 == new_port)
      {
        uc->status = GNUNET_SYSERR;
        GNUNET_free (single_variable);
        GNUNET_free (per_host_variable);
        return;
      }
      GNUNET_snprintf (cval, sizeof (cval), "%u", new_port);
      value = cval;
    }
    else if ((ival != 0) &&
             (GNUNET_YES ==
              GNUNET_CONFIGURATION_get_value_yesno (uc->cfg, "testing",
                                                    single_variable)) &&
             GNUNET_CONFIGURATION_get_value_number (uc->cfg, "testing",
                                                    per_host_variable,
                                                    &num_per_host))
    {
      /* GNUNET_snprintf (cval, sizeof (cval), "%u", */
      /*                  ival + ctx->fdnum % num_per_host); */
      /* value = cval; */
      GNUNET_break (0);         /* FIXME */
    }
  }
  if (0 == strcmp (option, "UNIXPATH"))
  {
    if (GNUNET_YES !=
        GNUNET_CONFIGURATION_get_value_yesno (uc->cfg, "testing",
                                              single_variable))
    {
      GNUNET_snprintf (uval, sizeof (uval), "%s/%s.sock",
                       uc->service_home, section);
      value = uval;
    }
    else if ((GNUNET_YES ==
              GNUNET_CONFIGURATION_get_value_number (uc->cfg, "testing",
                                                     per_host_variable,
                                                     &num_per_host)) &&
             (num_per_host > 0))
    {
      GNUNET_break(0);          /* FIXME */
    }
  }
  if (0 == strcmp (option, "HOSTNAME"))
  {
    value = (NULL == uc->system->hostname) ? "localhost" : uc->system->hostname;
  }
  GNUNET_free (single_variable);
  GNUNET_free (per_host_variable);
  GNUNET_CONFIGURATION_set_value_string (uc->cfg, section, option, value);
}


/**
 * Section iterator to set ACCEPT_FROM/ACCEPT_FROM6 to include the address of
 * 'trusted_hosts' in all sections
 *
 * @param cls the UpdateContext
 * @param section name of the section
 */
static void
update_config_sections (void *cls,
                        const char *section)
{
  struct UpdateContext *uc = cls;  
  char **ikeys;
  char *val;
  char *ptr;
  char *orig_allowed_hosts;
  char *allowed_hosts;
  char *ACCEPT_FROM_key;
  uint16_t ikeys_cnt;
  uint16_t key;
  
  ikeys_cnt = 0;
  val = NULL;
  if (GNUNET_YES == GNUNET_CONFIGURATION_have_value (uc->cfg, section,
                                                     "TESTING_IGNORE_KEYS"))
  {
    GNUNET_assert 
      (GNUNET_YES == 
       GNUNET_CONFIGURATION_get_value_string (uc->cfg, section,
                                              "TESTING_IGNORE_KEYS", &val));
    ptr = val;
    for (ikeys_cnt = 0; NULL != (ptr = strstr (ptr, ";")); ikeys_cnt++)
      ptr++;
    if (0 == ikeys_cnt)
      GNUNET_break (0);
    else
    {
      ikeys = GNUNET_malloc ((sizeof (char *)) * ikeys_cnt);
      ptr = val;
      for (key = 0; key < ikeys_cnt; key++)
      {
        ikeys[key] = ptr;
        ptr = strstr (ptr, ";");
        *ptr = '\0';
        ptr++;
      }
    }
  }
  if (0 != ikeys_cnt)
  {
    for (key = 0; key < ikeys_cnt; key++)
    {
      if (NULL != strstr (ikeys[key], "ADVERTISED_PORT"))
	break;
    }
    if ((key == ikeys_cnt) &&
	(GNUNET_YES == GNUNET_CONFIGURATION_have_value (uc->cfg, section,
							"ADVERTISED_PORT")))
    {
      if (GNUNET_OK == 
	  GNUNET_CONFIGURATION_get_value_string (uc->cfg, section, "PORT", &ptr))
      {
	GNUNET_CONFIGURATION_set_value_string (uc->cfg, section, 
					       "ADVERTISED_PORT", ptr);
	GNUNET_free (ptr);
      }
    }
    for (key = 0; key < ikeys_cnt; key++)
    {
      if (NULL != strstr (ikeys[key], "ACCEPT_FROM"))
      {
        GNUNET_free (ikeys);
        GNUNET_free (val);
        return;
      }
    }
    GNUNET_free (ikeys);
  }
  GNUNET_free_non_null (val);
  ACCEPT_FROM_key = "ACCEPT_FROM";  
  if ((NULL != uc->system->trusted_ip) && 
      (NULL != strstr (uc->system->trusted_ip, ":"))) /* IPv6 in use */
    ACCEPT_FROM_key = "ACCEPT_FROM6";
  if (GNUNET_OK != 
      GNUNET_CONFIGURATION_get_value_string (uc->cfg, section, ACCEPT_FROM_key,
                                             &orig_allowed_hosts))
  {
    orig_allowed_hosts = GNUNET_strdup ("127.0.0.1;");
  }
  if (NULL == uc->system->trusted_ip)
    allowed_hosts = GNUNET_strdup (orig_allowed_hosts);
  else
    GNUNET_asprintf (&allowed_hosts, "%s%s;", orig_allowed_hosts,
                     uc->system->trusted_ip);
  GNUNET_free (orig_allowed_hosts);
  GNUNET_CONFIGURATION_set_value_string (uc->cfg, section, ACCEPT_FROM_key,
                                         allowed_hosts);
  GNUNET_free (allowed_hosts);  
}


/**
 * Create a new configuration using the given configuration as a template;
 * ports and paths will be modified to select available ports on the local
 * system. The default configuration will be available in PATHS section under
 * the option DEFAULTCONFIG after the call. SERVICE_HOME is also set in PATHS
 * section to the temporary directory specific to this configuration. If we run
 * out of "*port" numbers, return SYSERR.
 *
 * This is primarily a helper function used internally
 * by 'GNUNET_TESTING_peer_configure'.
 *
 * @param system system to use to coordinate resource usage
 * @param cfg template configuration to update
 * @return GNUNET_OK on success, GNUNET_SYSERR on error - the configuration will
 *           be incomplete and should not be used there upon
 */
int
GNUNET_TESTING_configuration_create (struct GNUNET_TESTING_System *system,
				     struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct UpdateContext uc;
  char *default_config;
  
  uc.system = system;
  uc.cfg = cfg;
  uc.status = GNUNET_OK;
  GNUNET_asprintf (&uc.service_home, "%s/%u", system->tmppath,
                   system->path_counter++);
  GNUNET_asprintf (&default_config, "%s/config", uc.service_home);
  GNUNET_CONFIGURATION_set_value_string (cfg, "PATHS", "DEFAULTCONFIG",
                                         default_config);
  GNUNET_free (default_config);
  GNUNET_CONFIGURATION_set_value_string (cfg, "PATHS", "SERVICEHOME",
                                         uc.service_home);
  /* make PORTs and UNIXPATHs unique */
  GNUNET_CONFIGURATION_iterate (cfg, &update_config, &uc);
  /* allow connections to services from system trusted_ip host */
  GNUNET_CONFIGURATION_iterate_sections (cfg, &update_config_sections, &uc);
  /* enable loopback-based connections between peers */
  GNUNET_CONFIGURATION_set_value_string (cfg, 
					 "nat",
					 "USE_LOCALADDR", "YES");
  GNUNET_free (uc.service_home);
  return uc.status;
}


/**
 * Configure a GNUnet peer.  GNUnet must be installed on the local
 * system and available in the PATH. 
 *
 * @param system system to use to coordinate resource usage
 * @param cfg configuration to use; will be UPDATED (to reflect needed
 *            changes in port numbers and paths)
 * @param key_number number of the hostkey to use for the peer
 * @param id identifier for the daemon, will be set, can be NULL
 * @param emsg set to freshly allocated error message (set to NULL on success), 
 *          can be NULL
 * @return handle to the peer, NULL on error
 */
struct GNUNET_TESTING_Peer *
GNUNET_TESTING_peer_configure (struct GNUNET_TESTING_System *system,
			       struct GNUNET_CONFIGURATION_Handle *cfg,
			       uint32_t key_number,
			       struct GNUNET_PeerIdentity *id,
			       char **emsg)
{
  struct GNUNET_TESTING_Peer *peer;
  struct GNUNET_DISK_FileHandle *fd;
  char *service_home;  
  char hostkey_filename[128];
  char *config_filename;
  char *libexec_binary;
  char *emsg_;
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;

  if (NULL != emsg)
    *emsg = NULL;
  if (GNUNET_OK != GNUNET_TESTING_configuration_create (system, cfg))
  {
    GNUNET_asprintf (&emsg_,
		       _("Failed to create configuration for peer (not enough free ports?)\n"));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s", emsg_);
    if (NULL != emsg)
      *emsg = emsg_;
    else
      GNUNET_free (emsg_);
    return NULL;
  }
  if (key_number >= system->total_hostkeys)
  {
    GNUNET_asprintf (&emsg_,
		     _("You attempted to create a testbed with more than %u hosts.  Please precompute more hostkeys first.\n"),
		     (unsigned int) system->total_hostkeys);    
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s", emsg_);
    if (NULL != emsg)
      *emsg = emsg_;
    else
      GNUNET_free (emsg_);
    return NULL;
  }
  pk = NULL;
  if ((NULL != id) &&
      (NULL == (pk = GNUNET_TESTING_hostkey_get (system, key_number, id))))
  {
    GNUNET_asprintf (&emsg_,
		     _("Failed to initialize hostkey for peer %u\n"),
		     (unsigned int) key_number);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s", emsg_);
    if (NULL != emsg)
      *emsg = emsg_;
    else
      GNUNET_free (emsg_);
    return NULL;
  }
  if (NULL != pk)
    GNUNET_CRYPTO_rsa_key_free (pk);
  GNUNET_assert (GNUNET_OK == 
                 GNUNET_CONFIGURATION_get_value_string (cfg, "PATHS",
                                                        "SERVICEHOME",
                                                        &service_home));
  GNUNET_snprintf (hostkey_filename, sizeof (hostkey_filename), "%s/.hostkey",
                   service_home);
  GNUNET_free (service_home);
  fd = GNUNET_DISK_file_open (hostkey_filename,
                              GNUNET_DISK_OPEN_CREATE | GNUNET_DISK_OPEN_WRITE,
                              GNUNET_DISK_PERM_USER_READ 
                              | GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == fd)
  {
    GNUNET_break (0); 
    return NULL;
  }
  if (GNUNET_TESTING_HOSTKEYFILESIZE !=
      GNUNET_DISK_file_write (fd, system->hostkeys_data 
			      + (key_number * GNUNET_TESTING_HOSTKEYFILESIZE),
			      GNUNET_TESTING_HOSTKEYFILESIZE))
  {
    GNUNET_asprintf (&emsg_,
		     _("Failed to write hostkey file for peer %u: %s\n"),
		     (unsigned int) key_number,
		     STRERROR (errno));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s", emsg_);
    if (NULL != emsg)
      *emsg = emsg_;
    else
      GNUNET_free (emsg_);
    GNUNET_DISK_file_close (fd);
    return NULL;
  }
  GNUNET_DISK_file_close (fd);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string 
                 (cfg, "PATHS", "DEFAULTCONFIG", &config_filename));  
  if (GNUNET_OK != GNUNET_CONFIGURATION_write (cfg, config_filename))
  {
    GNUNET_asprintf (&emsg_,
		     _("Failed to write configuration file `%s' for peer %u: %s\n"),
		     config_filename,
		     (unsigned int) key_number,
		     STRERROR (errno));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s", emsg_);
    if (NULL != emsg)
      *emsg = emsg_;
    else
      GNUNET_free (emsg_);
    GNUNET_free (config_filename);
    return NULL;
  }
  peer = GNUNET_malloc (sizeof (struct GNUNET_TESTING_Peer));
  peer->cfgfile = config_filename; /* Free in peer_destroy */
  libexec_binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-arm");
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "arm", "PREFIX", &peer->main_binary))
  {
    /* No prefix */
    GNUNET_asprintf(&peer->main_binary, "%s", libexec_binary);
    peer->args = strdup ("");
  }
  else
    peer->args = strdup (libexec_binary);
  peer->system = system;
  peer->key_number = key_number;
  GNUNET_free (libexec_binary);
  return peer;
}


/**
 * Obtain the peer identity from a peer handle.
 *
 * @param peer peer handle for which we want the peer's identity
 * @param id identifier for the daemon, will be set
 */
void
GNUNET_TESTING_peer_get_identity (const struct GNUNET_TESTING_Peer *peer,
				  struct GNUNET_PeerIdentity *id)
{
  GNUNET_CRYPTO_rsa_key_free (GNUNET_TESTING_hostkey_get (peer->system,
							  peer->key_number,
							  id));
}


/**
 * Start the peer. 
 *
 * @param peer peer to start
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (i.e. peer already running)
 */
int
GNUNET_TESTING_peer_start (struct GNUNET_TESTING_Peer *peer)
{
  if (NULL != peer->main_process)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (NULL != peer->cfgfile);
  peer->main_process = GNUNET_OS_start_process (PIPE_CONTROL, 
                                                GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                                NULL, NULL,
                                                peer->main_binary,
                                                peer->main_binary,
                                                peer->args,
                                                "-c",
                                                peer->cfgfile,
                                                NULL);
  if (NULL == peer->main_process)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to start `%s': %s\n"),
		peer->main_binary,
		STRERROR (errno));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Sends SIGTERM to the peer's main process
 *
 * @param peer the handle to the peer
 * @return GNUNET_OK if successful; GNUNET_SYSERR if the main process is NULL
 *           or upon any error while sending SIGTERM
 */
int
GNUNET_TESTING_peer_kill (struct GNUNET_TESTING_Peer *peer)
{
  if (NULL == peer->main_process)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return (0 == GNUNET_OS_process_kill (peer->main_process, SIGTERM)) ?
      GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Waits for a peer to terminate. The peer's main process will also be destroyed.
 *
 * @param peer the handle to the peer
 * @return GNUNET_OK if successful; GNUNET_SYSERR if the main process is NULL
 *           or upon any error while waiting
 */
int
GNUNET_TESTING_peer_wait (struct GNUNET_TESTING_Peer *peer)
{
  int ret;

  if (NULL == peer->main_process)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  ret = GNUNET_OS_process_wait (peer->main_process);
  GNUNET_OS_process_destroy (peer->main_process);
  peer->main_process = NULL;
  return ret;
}


/**
 * Stop the peer. 
 *
 * @param peer peer to stop
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_TESTING_peer_stop (struct GNUNET_TESTING_Peer *peer)
{
  if (GNUNET_SYSERR == GNUNET_TESTING_peer_kill (peer))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR == GNUNET_TESTING_peer_wait (peer))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Destroy the peer.  Releases resources locked during peer configuration.
 * If the peer is still running, it will be stopped AND a warning will be
 * printed (users of the API should stop the peer explicitly first).
 *
 * @param peer peer to destroy
 */
void
GNUNET_TESTING_peer_destroy (struct GNUNET_TESTING_Peer *peer)
{
  if (NULL != peer->main_process)
  {
    GNUNET_break (0);
    GNUNET_TESTING_peer_stop (peer);
  }
  GNUNET_free (peer->cfgfile);
  GNUNET_free (peer->main_binary);
  GNUNET_free (peer->args);
  GNUNET_free (peer);
}


/**
 * Start a single peer and run a test using the testing library.
 * Starts a peer using the given configuration and then invokes the
 * given callback.  This function ALSO initializes the scheduler loop
 * and should thus be called directly from "main".  The testcase
 * should self-terminate by invoking 'GNUNET_SCHEDULER_shutdown'.
 *
 * @param testdir only the directory name without any path. This is used for
 *          all service homes; the directory will be created in a temporary
 *          location depending on the underlying OS
 * @param cfgfilename name of the configuration file to use;
 *         use NULL to only run with defaults
 * @param tm main function of the testcase
 * @param tm_cls closure for 'tm'
 * @return 0 on success, 1 on error
 */
int
GNUNET_TESTING_peer_run (const char *testdir,
			 const char *cfgfilename,
			 GNUNET_TESTING_TestMain tm,
			 void *tm_cls)
{
  return GNUNET_TESTING_service_run (testdir, "arm",
				     cfgfilename, tm, tm_cls);
}


/**
 * Structure for holding service data
 */
struct ServiceContext
{
  /**
   * The configuration of the peer in which the service is run
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Callback to signal service startup
   */
  GNUNET_TESTING_TestMain tm;
  
  /**
   * The peer in which the service is run.
   */
  struct GNUNET_TESTING_Peer *peer;

  /**
   * Closure for the above callback
   */
  void *tm_cls;
};


/**
 * Callback to be called when SCHEDULER has been started
 *
 * @param cls the ServiceContext
 * @param tc the TaskContext
 */
static void
service_run_main (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceContext *sc = cls;

  sc->tm (sc->tm_cls, sc->cfg, sc->peer);
}


/**
 * Start a single service (no ARM, except of course if the given
 * service name is 'arm') and run a test using the testing library.
 * Starts a service using the given configuration and then invokes the
 * given callback.  This function ALSO initializes the scheduler loop
 * and should thus be called directly from "main".  The testcase
 * should self-terminate by invoking 'GNUNET_SCHEDULER_shutdown'.
 *
 * This function is useful if the testcase is for a single service
 * and if that service doesn't itself depend on other services.
 *
 * @param testdir only the directory name without any path. This is used for
 *          all service homes; the directory will be created in a temporary
 *          location depending on the underlying OS
 * @param service_name name of the service to run
 * @param cfgfilename name of the configuration file to use;
 *         use NULL to only run with defaults
 * @param tm main function of the testcase
 * @param tm_cls closure for 'tm'
 * @return 0 on success, 1 on error
 */
int
GNUNET_TESTING_service_run (const char *testdir,
			    const char *service_name,
			    const char *cfgfilename,
			    GNUNET_TESTING_TestMain tm,
			    void *tm_cls)
{
  struct ServiceContext sc;
  struct GNUNET_TESTING_System *system;
  struct GNUNET_TESTING_Peer *peer;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *binary;
  char *libexec_binary;

  GNUNET_log_setup (testdir, "WARNING", NULL);
  system = GNUNET_TESTING_system_create (testdir, "127.0.0.1", NULL);
  if (NULL == system)
    return 1;
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (cfg, cfgfilename))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Failed to load configuration from %s\n"), cfgfilename);
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_TESTING_system_destroy (system, GNUNET_YES);
    return 1;
  }
  peer = GNUNET_TESTING_peer_configure (system, cfg, 0, NULL, NULL);
  if (NULL == peer)
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    hostkeys_unload (system);
    GNUNET_TESTING_system_destroy (system, GNUNET_YES);
    return 1;
  }
  GNUNET_free (peer->main_binary);
  GNUNET_free (peer->args);
  GNUNET_asprintf (&binary, "gnunet-service-%s", service_name);
  libexec_binary = GNUNET_OS_get_libexec_binary_path (binary);
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, service_name, "PREFIX", &peer->main_binary))
  {
    /* No prefix */
    GNUNET_asprintf(&peer->main_binary, "%s", libexec_binary);
    peer->args = strdup ("");
  }
  else
    peer->args = strdup (libexec_binary);

  GNUNET_free (libexec_binary);
  GNUNET_free (binary);
  if (GNUNET_OK != GNUNET_TESTING_peer_start (peer))
  {    
    GNUNET_TESTING_peer_destroy (peer);
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_TESTING_system_destroy (system, GNUNET_YES);
    return 1;
  }
  sc.cfg = cfg;
  sc.tm = tm;
  sc.tm_cls = tm_cls;
  sc.peer = peer;
  GNUNET_SCHEDULER_run (&service_run_main, &sc); /* Scheduler loop */
  if ((NULL != peer->main_process) &&
      (GNUNET_OK != GNUNET_TESTING_peer_stop (peer)))
  {
    GNUNET_TESTING_peer_destroy (peer);
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_TESTING_system_destroy (system, GNUNET_YES);
    return 1;
  }
  GNUNET_TESTING_peer_destroy (peer);
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_TESTING_system_destroy (system, GNUNET_YES);
  return 0;
}


/**
 * Sometimes we use the binary name to determine which specific
 * test to run.  In those cases, the string after the last "_"
 * in 'argv[0]' specifies a string that determines the configuration
 * file or plugin to use.  
 *
 * This function returns the respective substring, taking care
 * of issues such as binaries ending in '.exe' on W32.
 *
 * @param argv0 the name of the binary
 * @return string between the last '_' and the '.exe' (or the end of the string),
 *         NULL if argv0 has no '_' 
 */
char *
GNUNET_TESTING_get_testname_from_underscore (const char *argv0)
{
  size_t slen = strlen (argv0) + 1;
  char sbuf[slen];
  char *ret;
  char *dot;

  memcpy (sbuf, argv0, slen);
  ret = strrchr (sbuf, '_');
  if (NULL == ret)
    return NULL;
  ret++; /* skip underscore */
  dot = strchr (ret, '.');
  if (NULL != dot)
    *dot = '\0';
  return GNUNET_strdup (ret);
}


/* end of testing.c */
