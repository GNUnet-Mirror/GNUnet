/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 Jeffrey Burdges (and other contributing authors)

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
 * @file util/socks.c
 * @brief  SOCKS5 connection support
 * @author Jeffrey Burdges
 *
 * These routines should be called only on newly active connections.
 */
#include "platform.h"
#include "gnunet_util_lib.h"


#define LOG(kind,...) GNUNET_log_from (kind, "socks", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "socks", syscall)


/* SOCKS5 authentication methods */
#define SOCKS5_AUTH_REJECT 0xFF /* No acceptable auth method */
#define SOCKS5_AUTH_NOAUTH 0x00 /* without authentication */
#define SOCKS5_AUTH_GSSAPI 0x01 /* GSSAPI */
#define SOCKS5_AUTH_USERPASS 0x02 /* User/Password */
#define SOCKS5_AUTH_CHAP 0x03 /* Challenge-Handshake Auth Proto. */
#define SOCKS5_AUTH_EAP 0x05 /* Extensible Authentication Proto. */
#define SOCKS5_AUTH_MAF 0x08 /* Multi-Authentication Framework */


/* SOCKS5 connection responces */
#define SOCKS5_REP_SUCCEEDED 0x00 /* succeeded */
#define SOCKS5_REP_FAIL 0x01 /* general SOCKS serer failure */
#define SOCKS5_REP_NALLOWED 0x02 /* connection not allowed by ruleset */
#define SOCKS5_REP_NUNREACH 0x03 /* Network unreachable */
#define SOCKS5_REP_HUNREACH 0x04 /* Host unreachable */
#define SOCKS5_REP_REFUSED 0x05 /* connection refused */
#define SOCKS5_REP_EXPIRED 0x06 /* TTL expired */
#define SOCKS5_REP_CNOTSUP 0x07 /* Command not supported */
#define SOCKS5_REP_ANOTSUP 0x08 /* Address not supported */
#define SOCKS5_REP_INVADDR 0x09 /* Inalid address */

const char * SOCKS5_REP_names(int rep)
{
  switch (rep) {
    case SOCKS5_REP_SUCCEEDED: return "succeeded";
    case SOCKS5_REP_FAIL: return "general SOCKS server failure";
    case SOCKS5_REP_NALLOWED: return "connection not allowed by ruleset";
    case SOCKS5_REP_NUNREACH: return "Network unreachable";
    case SOCKS5_REP_HUNREACH: return "Host unreachable";
    case SOCKS5_REP_REFUSED: return "connection refused";
    case SOCKS5_REP_EXPIRED: return "TTL expired";
    case SOCKS5_REP_CNOTSUP: return "Command not supported";
    case SOCKS5_REP_ANOTSUP: return "Address not supported";
    case SOCKS5_REP_INVADDR: return "Invalid address";
    default: return NULL;
  }
};


/**
 * Encode a string for the SOCKS5 protocol by prefixing it a byte stating its
 * length and stipping the trailing zero byte.  Truncates any string longer
 * than 255 bytes.
 *
 * @param b buffer to contain the encoded string
 * @param s string to encode
 * @return pointer to the end of the encoded string in the buffer
 */
unsigned char * SOCK5_proto_string(unsigned char * b, const char * s)
{
  size_t l = strlen(s);
  if (l>255) {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "SOCKS5 cannot handle hostnames, usernames, or passwords over 255 bytes, truncating.\n");
    l=255;
  }
  *(b++) = (unsigned char)l;
  strncpy((char *)b,s,l);
  return b+l;
}


#define SOCKS5_step_greet 0
#define SOCKS5_step_auth  1
#define SOCKS5_step_cmd   2
#define SOCKS5_step_done  3

/**
 * State of the SOCKS5 handshake.
 */
struct GNUNET_SOCKS_Handshake 
{

  /**
   * Connection handle used for SOCKS5
   */
  struct GNUNET_CONNECTION_Handle *socks5_connection;

  /**
   * Connection handle initially returned to client
   */
  struct GNUNET_CONNECTION_Handle *target_connection;

  /**
   * Transmission handle on socks5_connection.
   */
  struct GNUNET_CONNECTION_TransmitHandle *th;

  /**
   * Our stage in the SOCKS5 handshake 
   */
  int step;

  /**
   * Precomputed SOCKS5 handshake ouput buffer
   */
  unsigned char outbuf[1024];

  /**
   * Pointers delineating protoocol steps in the outbut buffer
   */
  unsigned char * (outstep[4]);

  /**
   * SOCKS5 handshake input buffer
   */
  unsigned char inbuf[1024];

  /**
   * Pointers delimiting the current step in the input buffer
   */
  unsigned char * instart;
  unsigned char * inend;
};


/* Regitering prototypes */

void
register_reciever (struct GNUNET_SOCKS_Handshake *ih, int want);

  /* In fact, the client sends first rule in GNUNet suggests one could take
   * large mac read sizes without fear of screwing up the proxied protocol,
   * but we make a proper SOCKS5 client. */
#define register_reciever_wants(ih) ((SOCKS5_step_cmd == ih->step) ? 10 : 2)


struct GNUNET_CONNECTION_TransmitHandle *
register_sender (struct GNUNET_SOCKS_Handshake *ih);


/**
 * Conclude the SOCKS5 handshake successfully.
 *
 * @param ih SOCKS5 handshake, consumed here.
 * @param c open unused connection, consumed here.
 * @return Connection handle that becomes usable when the handshake completes.
 */
void
SOCKS5_handshake_done(struct GNUNET_SOCKS_Handshake *ih)
{
  GNUNET_CONNECTION_acivate_proxied (ih->target_connection);
}


/**
 * Read one step in the SOCKS5 handshake.
 *
 * @param ih SOCKS5 Handshake
 */
void
SOCKS5_handshake_step (struct GNUNET_SOCKS_Handshake *ih)
{
  unsigned char * b = ih->instart;
  size_t available = ih->inend - b;

  int want = register_reciever_wants(ih);
  if (available < want) {
    register_reciever (ih, want - available);
    return;
  }
  GNUNET_assert (SOCKS5_step_done > ih->step && ih->step >= 0);
  switch (ih->step) {
    case SOCKS5_step_greet:  /* SOCKS5 server's greeting */
      if (b[0] != 5) 
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "Not a SOCKS5 server\n");
        GNUNET_assert (0);
      }
      switch (b[1]) {
        case SOCKS5_AUTH_NOAUTH:
          ih->step=SOCKS5_step_cmd;  /* no authentication to do */
          break;
        case SOCKS5_AUTH_USERPASS:
          ih->step=SOCKS5_step_auth;
          break;
        case SOCKS5_AUTH_REJECT:
          LOG (GNUNET_ERROR_TYPE_ERROR,
               "No authentication method accepted\n");
          return;
        default:
          LOG (GNUNET_ERROR_TYPE_ERROR,
               "Not a SOCKS5 server / Nonsensical authentication\n");
          return;
      }
      b += 2;
      break;
    case SOCKS5_step_auth:  /* SOCKS5 server's responce to authentication */
      if (b[1] != 0)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "SOCKS5 authentication failed\n");
        GNUNET_assert (0);
      }
      ih->step=SOCKS5_step_cmd;
      b += 2;
      break;
    case SOCKS5_step_cmd:  /* SOCKS5 server's responce to command */
      if (b[0] != 5) 
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "SOCKS5 protocol error\n");
        GNUNET_assert (0);
      }
      if (0 != b[1]) {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "SOCKS5 connection error : %s\n",
             SOCKS5_REP_names(b[1]));
        return;
      }
      b += 3;
      /* There is no reason to verify host and port afaik. */
      switch (*(b++)) {
        case 1: /* IPv4 */
          b += sizeof(struct in_addr);  /* 4 */
          break;
        case 4: /* IPv6 */
          b += sizeof(struct in6_addr);  /* 16 */
          break;
        case 3: /* hostname */
          b += *b;
          break;
      }
      b += 2;  /* port */
      if (b > ih->inend) {
        register_reciever (ih, b - ih->inend);
        return;
      }
      ih->step = SOCKS5_step_done;
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "SOCKS5 server : %s\n",
           SOCKS5_REP_names(b[1]));
      ih->instart = b;
      SOCKS5_handshake_done (ih);
      return;
    case SOCKS5_step_done: 
      GNUNET_assert (0);
  }
  ih->instart = b;
  /* Do not reschedule the sender unless we're done reading. 
   * I imagine this lets us avoid ever cancelling the transmit handle. */
  register_sender (ih);
}


/**
 * Callback to read from the SOCKS5 proxy.
 *
 * @param client the service
 * @param handler function to call with the message
 * @param handler_cls closure for @a handler
 */
void
reciever (void *cls, 
          const void *buf, size_t available,
          const struct sockaddr * addr,
          socklen_t addrlen, int errCode)
{
  struct GNUNET_SOCKS_Handshake * ih = cls;
  GNUNET_assert (&ih->inend[available] < &ih->inbuf[1024]);
  memcpy(ih->inend, buf, available);
  ih->inend += available;
  SOCKS5_handshake_step (ih);
}


/**
 * Register callback to read from the SOCKS5 proxy.
 *
 * @param client the service
 * @param handler function to call with the message
 * @param handler_cls closure for @a handler
 */
void
register_reciever (struct GNUNET_SOCKS_Handshake *ih, int want)
{
  GNUNET_CONNECTION_receive (ih->socks5_connection,
                             want,
                             GNUNET_TIME_relative_get_minute_ (),
                             &reciever,
                             ih);
}


/**
 * Register SOCKS5 handshake sender
 *
 * @param cls closure (SOCKS handshake)
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */

size_t
transmit_ready (void *cls, 
                size_t size,
                void *buf)
{
  struct GNUNET_SOCKS_Handshake * ih = cls;

  /* connection.c has many routines that call us with buf == NULL :
   * signal_transmit_error() - DNS, etc. active
   *   connect_fail_continuation()
   *     connect_probe_continuation() - timeout
   *     try_connect_using_address() - DNS failure/timeout
   *     transmit_timeout() - retry failed?
   * GNUNET_CONNECTION_notify_transmit_ready() can schedule :
   *   transmit_timeout() - DNS still working
   *   connect_error() - DNS done but no socket?
   * transmit_ready() - scheduler shutdown or timeout, or signal_transmit_error() 
   * We'd need to dig into the scheduler to guess at the reason, as
   * connection.c tells us nothing itself, but mostly its timouts.
   * Initially, we'll simply ignore this and leave massive timeouts, but
   * maybe that should change for error handling pruposes.  It appears that
   * successful operations, including DNS resolution, do not use this.  */
  if (NULL==buf)
  {
    enum GNUNET_SCHEDULER_Reason reason = GNUNET_SCHEDULER_get_reason ();
    if (0 != (reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      return 0;
    if (0 != (reason & GNUNET_SCHEDULER_REASON_TIMEOUT)) {
      if (0==ih->step) {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Timeout contacting SOCKS server, retrying indefinitely, but probably hopeless.\n");
        register_sender (ih);
      } else {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "Timeout during mid SOCKS handshake (step %u), probably not a SOCKS server.\n",
             ih->step);
        GNUNET_break (0);
      }
      return 0;
    }
    printf("Erronious socks.c transmit_ready() callback on step %u with reason %u.\n", 
       ih->step, reason );
    /* if (reason == 48) register_sender (ih); */
    /* GNUNET_break(0); */
    return 0;
  } else 
    printf("Good socks.c transmit_ready() callback on step %u with reason %u.\n", 
       ih->step, GNUNET_SCHEDULER_get_reason () );

  GNUNET_assert (1024 >= size && size > 0);
  GNUNET_assert (SOCKS5_step_done > ih->step && ih->step >= 0);
  unsigned char * b = ih->outstep[ih->step];
  unsigned char * e = ih->outstep[ih->step++];
  GNUNET_assert (e <= &ih->outbuf[1024]);
  unsigned l = e - b;
  GNUNET_assert (size >= l && l >= 0);
  memcpy(b, buf, l);
  register_reciever (ih, register_reciever_wants(ih));
  return l;
}


/**
 * Register SOCKS5 handshake sender
 *
 * @param ih handshake
 * @return non-NULL if the notify callback was queued,
 *         NULL if we are already going to notify someone else (busy)
 */
struct GNUNET_CONNECTION_TransmitHandle *
register_sender (struct GNUNET_SOCKS_Handshake *ih)
{
  struct GNUNET_TIME_Relative timeout = GNUNET_TIME_UNIT_MINUTES;

  GNUNET_assert (SOCKS5_step_done > ih->step && ih->step >= 0);
  if (0 == ih->step)
    timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 3);
  unsigned char * b = ih->outstep[ih->step];
  unsigned char * e = ih->outstep[ih->step+1];
  GNUNET_assert (ih->outbuf <= b && b < e && e < &ih->outbuf[1024]);
  printf("register_sender on step %u for %u bytes.\n", ih->step, (unsigned)(e - b) );
  ih->th = GNUNET_CONNECTION_notify_transmit_ready (ih->socks5_connection,
                                                    e - b,
                                                    timeout,
                                                    &transmit_ready,
                                                    ih);
  return ih->th;
}


/**
 * Initialize a SOCKS5 handshake for authentication via username and
 * password.  Tor uses SOCKS username and password authentication to assign
 * programs unique circuits. 
 *
 * @param user username for the proxy
 * @param pass password for the proxy
 * @return Valid SOCKS5 hanbdshake handle
 */
struct GNUNET_SOCKS_Handshake *
GNUNET_SOCKS_init_handshake (const char *user, const char *pass)
{
  struct GNUNET_SOCKS_Handshake *ih = GNUNET_new (struct GNUNET_SOCKS_Handshake);
  unsigned char * b = ih->outbuf;

  ih->outstep[SOCKS5_step_greet] = b;
  *(b++) = 5; /* SOCKS5 */
  unsigned char * n = b++;
  *n = 1; /* Number of authentication methods */
  /* We support no authentication even when requesting authentication,
   * but this appears harmless, given the way that Tor uses authentication. 
   * And some SOCKS5 servers might require this.  */
  *(b++) = SOCKS5_AUTH_NOAUTH;
  if (NULL != user) {
    *(b++) = SOCKS5_AUTH_USERPASS;
    (*n)++;
  }
  /* There is no apperent reason to support authentication methods beyond
   * username and password since afaik Tor does not support them. */

  /* We authenticate with an empty username and password if the server demands 
   * them but we do not have any. */
  if (user == NULL)
    user = "";
  if (pass == NULL)
    pass = "";

  ih->outstep[SOCKS5_step_auth] = b;
  *(b++) = 1; /* subnegotiation ver.: 1 */
  b = SOCK5_proto_string(b,user);
  b = SOCK5_proto_string(b,pass);

  ih->outstep[SOCKS5_step_cmd] = b;

  return ih;
}


/**
 * Initialize a SOCKS5 handshake without authentication, thereby possibly 
 * sharing a Tor circuit with another process.
 *
 * @return Valid SOCKS5 hanbdshake handle
 */
struct GNUNET_SOCKS_Handshake *
GNUNET_SOCKS_init_handshake_noauth ()
{
  return GNUNET_SOCKS_init_handshake (NULL,NULL);
}


/**
 * Build request that the SOCKS5 proxy open a TCP/IP stream to the given host
 * and port.  
 *
 * @param ih SOCKS5 handshake
 * @param hostname 
 * @param port 
 */
void
GNUNET_SOCKS_set_handshake_destination (struct GNUNET_SOCKS_Handshake *ih,
                                         const char *host, uint16_t port)
{
  union {
    struct in_addr in4;
    struct in6_addr in6;
  } ia;
  unsigned char * b = ih->outstep[SOCKS5_step_cmd];

  *(b++) = 5;  /* SOCKS5 */
  *(b++) = 1;  /* Establish a TCP/IP stream */
  *(b++) = 0;  /* reserved */

  /* Specify destination */
  if (1 == inet_pton(AF_INET,host,&ia.in4)) {
    *(b++)= 1;  /* IPv4 */
    memcpy (b, &ia.in4, sizeof(struct in_addr));
    b += sizeof(struct in_addr);  /* 4 */
  } else if (1 == inet_pton(AF_INET6,host,&ia.in6)) {
    *(b++)= 4;  /* IPv6 */
    memcpy (b, &ia.in6, sizeof(struct in6_addr));
    b += sizeof(struct in6_addr);  /* 16 */
  } else {
    *(b++)= 3;  /* hostname */
    b = SOCK5_proto_string (b, host);
  }

  /* Specify port */
  *(uint16_t*)b = htons (port);
  b += 2;

  ih->outstep[SOCKS5_step_done] = b;
}


/**
 * Run a SOCKS5 handshake on an open but unused TCP connection.
 *
 * @param ih SOCKS5 handshake, consumed here.
 * @param c open unused connection, consumed here.
 * @return Connection handle that becomes usable when the SOCKS5 handshake completes.
 */
struct GNUNET_CONNECTION_Handle * 
GNUNET_SOCKS_run_handshake(struct GNUNET_SOCKS_Handshake *ih,
                            struct GNUNET_CONNECTION_Handle *c)
{
  ih->socks5_connection=c;
  ih->target_connection = GNUNET_CONNECTION_create_proxied_from_handshake (c);
  register_sender (ih);

  return ih->target_connection;
}


/**
 * Check if a SOCKS proxy is required by a service.  Do not use local service
 * if a SOCKS proxy port is configured as this could deanonymize a user.
 *
 * @param service_name name of service to connect to
 * @param cfg configuration to use
 * @return GNUNET_YES if so, GNUNET_NO if not
 */
int
GNUNET_SOCKS_check_service (const char *service_name,
                            const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  return GNUNET_CONFIGURATION_have_value (cfg, service_name, "SOCKSPORT") ||
         GNUNET_CONFIGURATION_have_value (cfg, service_name, "SOCKSHOST");
}


/**
 * Try to connect to a service configured to use a SOCKS5 proxy.
 *
 * @param service_name name of service to connect to
 * @param cfg configuration to use
 * @return Connection handle that becomes usable when the handshake completes.
 *         NULL if SOCKS not configured or not configured properly
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_SOCKS_do_connect (const char *service_name,
                          const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_SOCKS_Handshake *ih;
  struct GNUNET_CONNECTION_Handle *socks5; /* *proxied */
  char *host0,*host1,*user,*pass;
  unsigned long long port0,port1;

  if (GNUNET_YES != GNUNET_SOCKS_check_service (service_name, cfg))
    return NULL;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, service_name, "SOCKSPORT", &port0))
    port0 = 9050;
  /* A typical Tor client should usually try port 9150 for the TBB too, but 
   * GUNNet can probably assume a system Tor instalation. */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, service_name, "SOCKSHOST", &host0))
    host0 = "127.0.0.1";
  if (port0 > 65535 || port0 <= 0)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _
	 ("Attempting to use invalid port %d as SOCKS proxy for service `%s'.\n"),
	 port0,service_name);
    return NULL;
  }

  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (cfg, service_name, "PORT", &port1))
      || (port1 > 65535) || (port1 <= 0) ||
       (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_string (cfg, service_name, "HOSTNAME", &host1)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _
	 ("Attempting to proxy service `%s' to invalid port %d or hostname `%s'.\n"),
	 service_name,port1,host1);
    return NULL;
  }

  socks5 = GNUNET_CONNECTION_create_from_connect (cfg, host0, port0);
  GNUNET_free (host0);

  /* Sets to NULL if they do not exist */
  GNUNET_CONFIGURATION_get_value_string (cfg, service_name, "SOCKSUSER", &user);
  GNUNET_CONFIGURATION_get_value_string (cfg, service_name, "SOCKSPASS", &pass);
  ih = GNUNET_SOCKS_init_handshake(user,pass);
  if (NULL != user) GNUNET_free (user);
  if (NULL != pass) GNUNET_free (pass);

  GNUNET_SOCKS_set_handshake_destination (ih,host1,port1);
  GNUNET_free (host1);

  return GNUNET_SOCKS_run_handshake(ih,socks5);
}

/* socks.c */
