/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_smtp.c
 * @brief Implementation of the SMTP transport service
 * @author Christian Grothoff
 * @author Renaldo Ferreira
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include <libesmtp.h>
#include <signal.h>


/**
 * The default maximum size of each outbound SMTP message.
 */
#define SMTP_MESSAGE_SIZE 65528

#define DEBUG_SMTP GNUNET_NO

#define FILTER_STRING_SIZE 64

/* how long can a line in base64 encoded
   mime text be? (in characters, excluding "\n") */
#define MAX_CHAR_PER_LINE 76

#define EBUF_LEN 128

/**
 * Host-Address in a SMTP network.
 */
typedef struct
{

  /**
   * Filter line that every sender must include in the E-mails such
   * that the receiver can effectively filter out the GNUnet traffic
   * from the E-mail.
   */
  char filter[FILTER_STRING_SIZE];

  /**
   * Claimed E-mail address of the sender.
   * Format is "foo@bar.com" with null termination, padded to be
   * of a multiple of 8 bytes long.
   */
  char senderAddress[0];

} EmailAddress;

/**
 * Encapsulation of a GNUnet message in the SMTP mail body (before
 * base64 encoding).
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * What is the identity of the sender (GNUNET_hash of public key)
   */
  GNUNET_PeerIdentity sender;

} SMTPMessage;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static GNUNET_CoreAPIForTransport *coreAPI;

static struct GNUNET_GE_Context *ectx;

/**
 * Thread that listens for inbound messages
 */
static struct GNUNET_ThreadHandle *dispatchThread;

/**
 * Flag to indicate that server has been shut down.
 */
static int smtp_shutdown = GNUNET_YES;

/**
 * Set to the SMTP server hostname (and port) for outgoing messages.
 */
static char *smtp_server_name;

static char *pipename;

/**
 * Lock for uses of libesmtp (not thread-safe).
 */
static struct GNUNET_Mutex *lock;

/**
 * Old handler for SIGPIPE (kept to be able to restore).
 */
static struct sigaction old_handler;

static char *email;

static GNUNET_TransportAPI smtpAPI;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

/**
 * How many e-mails are we allowed to send per hour?
 */
static unsigned long long rate_limit;

static GNUNET_CronTime last_transmission;

/** ******************** Base64 encoding ***********/

#define FILLCHAR '='
static char *cvt =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789+/";

/**
 * Encode into Base64.
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
static unsigned int
base64_encode (const char *data, unsigned int len, char **output)
{
  unsigned int i;
  char c;
  unsigned int ret;
  char *opt;

/*    (*output)[ret++] = '\r'; \*/
#define CHECKLINE \
  if ( (ret % MAX_CHAR_PER_LINE) == 0) { \
    (*output)[ret++] = '\n'; \
  }
  ret = 0;
  opt =
      GNUNET_malloc (2 +
                     (((len * 4 / 3) + 8) * (MAX_CHAR_PER_LINE +
                                             2)) / MAX_CHAR_PER_LINE);
  /* message must start with \r\n for libesmtp */
  *output = opt;
  opt[0] = '\r';
  opt[1] = '\n';
  ret += 2;
  for (i = 0; i < len; ++i)
  {
    c = (data[i] >> 2) & 0x3f;
    opt[ret++] = cvt[(int) c];
    CHECKLINE;
    c = (data[i] << 4) & 0x3f;
    if (++i < len)
      c |= (data[i] >> 4) & 0x0f;
    opt[ret++] = cvt[(int) c];
    CHECKLINE;
    if (i < len)
    {
      c = (data[i] << 2) & 0x3f;
      if (++i < len)
        c |= (data[i] >> 6) & 0x03;
      opt[ret++] = cvt[(int) c];
      CHECKLINE;
    }
    else
    {
      ++i;
      opt[ret++] = FILLCHAR;
      CHECKLINE;
    }
    if (i < len)
    {
      c = data[i] & 0x3f;
      opt[ret++] = cvt[(int) c];
      CHECKLINE;
    }
    else
    {
      opt[ret++] = FILLCHAR;
      CHECKLINE;
    }
  }
  opt[ret++] = FILLCHAR;
  return ret;
}

#define cvtfind(a)( (((a) >= 'A')&&((a) <= 'Z'))? (a)-'A'\
                   :(((a)>='a')&&((a)<='z')) ? (a)-'a'+26\
                   :(((a)>='0')&&((a)<='9')) ? (a)-'0'+52\
  	   :((a) == '+') ? 62\
  	   :((a) == '/') ? 63 : -1)
/**
 * Decode from Base64.
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
static unsigned int
base64_decode (const char *data, unsigned int len, char **output)
{
  unsigned int i;
  char c;
  char c1;
  unsigned int ret = 0;

#define CHECK_CRLF  while (data[i] == '\r' || data[i] == '\n') {\
  			GNUNET_GE_LOG(ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER, "ignoring CR/LF\n"); \
  			i++; \
  			if (i >= len) goto END;  \
  		}

  *output = GNUNET_malloc ((len * 3 / 4) + 8);
#if DEBUG_SMTP
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "base64_decode decoding len=%d\n", len);
#endif
  for (i = 0; i < len; ++i)
  {
    CHECK_CRLF;
    if (data[i] == FILLCHAR)
      break;
    c = (char) cvtfind (data[i]);
    ++i;
    CHECK_CRLF;
    c1 = (char) cvtfind (data[i]);
    c = (c << 2) | ((c1 >> 4) & 0x3);
    (*output)[ret++] = c;
    if (++i < len)
    {
      CHECK_CRLF;
      c = data[i];
      if (FILLCHAR == c)
        break;
      c = (char) cvtfind (c);
      c1 = ((c1 << 4) & 0xf0) | ((c >> 2) & 0xf);
      (*output)[ret++] = c1;
    }
    if (++i < len)
    {
      CHECK_CRLF;
      c1 = data[i];
      if (FILLCHAR == c1)
        break;

      c1 = (char) cvtfind (c1);
      c = ((c << 6) & 0xc0) | c1;
      (*output)[ret++] = c;
    }
  }
END:
  return ret;
}

/* ********************* the real stuff ******************* */

#define strAUTOncmp(a,b) strncmp(a,b,strlen(b))

/**
 * Listen to the pipe, decode messages and send to core.
 */
static void *
listenAndDistribute (void *unused)
{
  char *line;
  unsigned int linesize;
  SMTPMessage *mp;
  FILE *fdes;
  char *retl;
  char *out;
  unsigned int size;
  GNUNET_TransportPacket *coreMP;
  int fd;
  unsigned int pos;

  linesize = ((GNUNET_MAX_BUFFER_SIZE * 4 / 3) + 8) * (MAX_CHAR_PER_LINE + 2) / MAX_CHAR_PER_LINE;      /* maximum size of a line supported */
  line = GNUNET_malloc (linesize + 2);  /* 2 bytes for off-by-one errors, just to be safe... */

#define READLINE(l,limit) \
  do { retl = fgets(l, (limit), fdes);				\
    if ( (retl == NULL) || (smtp_shutdown == GNUNET_YES)) {\
      goto END; \
    }\
    if (coreAPI->load_monitor != NULL) \
     GNUNET_network_monitor_notify_transmission(coreAPI->load_monitor, GNUNET_ND_DOWNLOAD, strlen(retl)); \
  } while (0)


  while (smtp_shutdown == GNUNET_NO)
  {
    fd = OPEN (pipename, O_RDONLY | O_ASYNC);
    if (fd == -1)
    {
      if (smtp_shutdown == GNUNET_NO)
        GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);
      continue;
    }
    fdes = fdopen (fd, "r");
    while (smtp_shutdown == GNUNET_NO)
    {
      /* skip until end of header */
      do
      {
        READLINE (line, linesize);
      }
      while ((line[0] != '\r') && (line[0] != '\n'));   /* expect newline */
      READLINE (line, linesize);        /* read base64 encoded message; decode, process */
      pos = 0;
      while (1)
      {
        pos = strlen (line) - 1;        /* ignore new line */
        READLINE (&line[pos], linesize - pos);  /* read base64 encoded message; decode, process */
        if ((line[pos] == '\r') || (line[pos] == '\n'))
          break;                /* empty line => end of message! */
      }
      size = base64_decode (line, pos, &out);
      if (size < sizeof (SMTPMessage))
      {
        GNUNET_GE_BREAK (ectx, 0);
        GNUNET_free (out);
        goto END;
      }

      mp = (SMTPMessage *) &out[size - sizeof (SMTPMessage)];
      if (ntohs (mp->header.size) != size)
      {
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                       _("Received malformed message via %s. Ignored.\n"),
                       "SMTP");
#if DEBUG_SMTP
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                       "Size returned by base64=%d, in the msg=%d.\n", size,
                       ntohl (mp->size));
#endif
        GNUNET_free (out);
        goto END;
      }
      if (stats != NULL)
        stats->change (stat_bytesReceived, size);
      coreMP = GNUNET_malloc (sizeof (GNUNET_TransportPacket));
      coreMP->msg = out;
      coreMP->size = size - sizeof (SMTPMessage);
      coreMP->tsession = NULL;
      coreMP->sender = mp->sender;
#if DEBUG_SMTP
      GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "SMTP message passed to the core.\n");
#endif

      coreAPI->receive (coreMP);
    }
END:
#if DEBUG_SMTP
    GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                   "SMTP message processed.\n");
#endif
    if (fdes != NULL)
      fclose (fdes);
  }
  GNUNET_free (line);
  return NULL;
}

/* *************** API implementation *************** */

/**
 * Verify that a hello-Message is correct (a node is reachable at that
 * address). Since the reply will be asynchronous, a method must be
 * called on success.
 *
 * @param hello the hello message to verify
 *        (the signature/crc have been verified before)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
api_verify_hello (const GNUNET_MessageHello * hello)
{
  const EmailAddress *maddr;

  maddr = (const EmailAddress *) &hello[1];
  if ((ntohs (hello->header.size) !=
       sizeof (GNUNET_MessageHello) + ntohs (hello->senderAddressSize)) ||
      (maddr->senderAddress
       [ntohs (hello->senderAddressSize) - 1 - FILTER_STRING_SIZE] != '\0'))
  {
    GNUNET_GE_BREAK (ectx, 0);
    return GNUNET_SYSERR;       /* obviously invalid */
  }
  if (NULL == strstr (maddr->filter, ": "))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Create a hello-Message for the current node. The hello is created
 * without signature and without a timestamp. The GNUnet core will
 * GNUNET_RSA_sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static GNUNET_MessageHello *
api_create_hello ()
{
  GNUNET_MessageHello *msg;
  char *filter;
  EmailAddress *haddr;
  int i;

  GNUNET_GC_get_configuration_value_string (coreAPI->cfg, "SMTP", "FILTER",
                                            "X-mailer: GNUnet", &filter);
  if (NULL == strstr (filter, ": "))
  {
    GNUNET_GE_LOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                   _("SMTP filter string to invalid, lacks ': '\n"));
    GNUNET_free (filter);
    return NULL;
  }

  if (strlen (filter) > FILTER_STRING_SIZE)
  {
    filter[FILTER_STRING_SIZE] = '\0';
    GNUNET_GE_LOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                   _("SMTP filter string to long, capped to `%s'\n"), filter);
  }
  i = (strlen (email) + 8) & (~7);      /* make multiple of 8 */
  msg =
      GNUNET_malloc (sizeof (GNUNET_MessageHello) + sizeof (EmailAddress) + i);
  memset (msg, 0, sizeof (GNUNET_MessageHello) + sizeof (EmailAddress) + i);
  haddr = (EmailAddress *) &msg[1];
  memset (&haddr->filter[0], 0, FILTER_STRING_SIZE);
  strcpy (&haddr->filter[0], filter);
  memcpy (&haddr->senderAddress[0], email, strlen (email) + 1);
  msg->senderAddressSize = htons (strlen (email) + 1 + sizeof (EmailAddress));
  msg->protocol = htons (GNUNET_TRANSPORT_PROTOCOL_NUMBER_SMTP);
  msg->MTU = htonl (smtpAPI.mtu);
  msg->header.size = htons (GNUNET_sizeof_hello (msg));
  if (api_verify_hello (msg) == GNUNET_SYSERR)
    GNUNET_GE_ASSERT (ectx, 0);
  GNUNET_free (filter);
  return msg;
}

struct GetMessageClosure
{
  unsigned int esize;
  unsigned int pos;
  char *ebody;
};

static const char *
get_message (void **buf, int *len, void *cls)
{
  struct GetMessageClosure *gmc = cls;

  *buf = NULL;
  if (len == NULL)
  {
    gmc->pos = 0;
    return NULL;
  }
  if (gmc->pos == gmc->esize)
    return NULL;                /* done */
  *len = gmc->esize;
  gmc->pos = gmc->esize;
  return gmc->ebody;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the GNUNET_MessageHello identifying the remote node
 * @param msg what to send
 * @param size the size of the message
 * @param important is this message important enough to override typical limits?
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
api_send (GNUNET_TSession * tsession, const void *msg, const unsigned int size,
          int important)
{
  const GNUNET_MessageHello *hello;
  const EmailAddress *haddr;
  char *m;
  char *filter;
  char *fvalue;
  SMTPMessage *mp;
  struct GetMessageClosure gm_cls;
  smtp_session_t session;
  smtp_message_t message;
  smtp_recipient_t recipient;

#define EBUF_LEN 128
  char ebuf[EBUF_LEN];
  GNUNET_CronTime now;

  if (smtp_shutdown == GNUNET_YES)
    return GNUNET_SYSERR;
  if ((size == 0) || (size > smtpAPI.mtu))
  {
    GNUNET_GE_BREAK (ectx, 0);
    return GNUNET_SYSERR;
  }
  now = GNUNET_get_time ();
  if ((important != GNUNET_YES) &&
      ((now - last_transmission) * rate_limit) < GNUNET_CRON_HOURS)
    return GNUNET_NO;           /* rate too high */
  last_transmission = now;

  hello = (const GNUNET_MessageHello *) tsession->internal;
  if (hello == NULL)
    return GNUNET_SYSERR;
  GNUNET_mutex_lock (lock);
  session = smtp_create_session ();
  if (session == NULL)
  {
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_IMMEDIATE, _("SMTP: `%s' failed: %s.\n"),
                   "smtp_create_session", smtp_strerror (smtp_errno (), ebuf,
                                                         EBUF_LEN));
    GNUNET_mutex_unlock (lock);
    return GNUNET_SYSERR;
  }
  if (0 == smtp_set_server (session, smtp_server_name))
  {
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_IMMEDIATE, _("SMTP: `%s' failed: %s.\n"),
                   "smtp_set_server", smtp_strerror (smtp_errno (), ebuf,
                                                     EBUF_LEN));
    smtp_destroy_session (session);
    GNUNET_mutex_unlock (lock);
    return GNUNET_SYSERR;
  }
  haddr = (const EmailAddress *) &hello[1];
  message = smtp_add_message (session);
  if (message == NULL)
  {
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_BULK, _("SMTP: `%s' failed: %s.\n"),
                   "smtp_add_message", smtp_strerror (smtp_errno (), ebuf,
                                                      EBUF_LEN));
    smtp_destroy_session (session);
    GNUNET_mutex_unlock (lock);
    return GNUNET_SYSERR;
  }
  smtp_set_header (message, "To", NULL, haddr->senderAddress);
  smtp_set_header (message, "From", NULL, email);

  filter = GNUNET_strdup (haddr->filter);
  fvalue = strstr (filter, ": ");
  GNUNET_GE_ASSERT (NULL, NULL != fvalue);
  fvalue[0] = '\0';
  fvalue += 2;
  if (0 == smtp_set_header (message, filter, fvalue))
  {
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_BULK, _("SMTP: `%s' failed: %s.\n"),
                   "smtp_set_header", smtp_strerror (smtp_errno (), ebuf,
                                                     EBUF_LEN));
    smtp_destroy_session (session);
    GNUNET_mutex_unlock (lock);
    GNUNET_free (filter);
    return GNUNET_SYSERR;
  }
  GNUNET_free (filter);
  m = GNUNET_malloc (size + sizeof (SMTPMessage));
  memcpy (m, msg, size);
  mp = (SMTPMessage *) &m[size];
  mp->header.size = htons (size + sizeof (SMTPMessage));
  mp->header.type = htons (0);
  mp->sender = *coreAPI->my_identity;
  gm_cls.ebody = NULL;
  gm_cls.pos = 0;
  gm_cls.esize = base64_encode (m, size + sizeof (SMTPMessage), &gm_cls.ebody);
  GNUNET_free (m);
  if (0 == smtp_size_set_estimate (message, gm_cls.esize))
  {
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_BULK, _("SMTP: `%s' failed: %s.\n"),
                   "smtp_size_set_estimate", smtp_strerror (smtp_errno (), ebuf,
                                                            EBUF_LEN));
  }
  if (0 == smtp_set_messagecb (message, &get_message, &gm_cls))
  {
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_BULK, _("SMTP: `%s' failed: %s.\n"),
                   "smtp_set_messagecb", smtp_strerror (smtp_errno (), ebuf,
                                                        EBUF_LEN));
    smtp_destroy_session (session);
    GNUNET_mutex_unlock (lock);
    GNUNET_free (gm_cls.ebody);
    return GNUNET_SYSERR;
  }
  recipient = smtp_add_recipient (message, haddr->senderAddress);
  if (recipient == NULL)
  {
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_BULK, _("SMTP: `%s' failed: %s.\n"),
                   "smtp_add_recipient", smtp_strerror (smtp_errno (), ebuf,
                                                        EBUF_LEN));
    smtp_destroy_session (session);
    GNUNET_mutex_unlock (lock);
    return GNUNET_SYSERR;
  }
  if (0 == smtp_start_session (session))
  {
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_BULK, _("SMTP: `%s' failed: %s.\n"),
                   "smtp_start_session", smtp_strerror (smtp_errno (), ebuf,
                                                        EBUF_LEN));
    smtp_destroy_session (session);
    GNUNET_mutex_unlock (lock);
    GNUNET_free (gm_cls.ebody);
    return GNUNET_SYSERR;
  }
  if (stats != NULL)
    stats->change (stat_bytesSent, size);
  if (coreAPI->load_monitor != NULL)
    GNUNET_network_monitor_notify_transmission (coreAPI->load_monitor,
                                                GNUNET_ND_UPLOAD, gm_cls.esize);
  smtp_message_reset_status (message);  /* this is needed to plug a 28-byte/message memory leak in libesmtp */
  smtp_destroy_session (session);
  GNUNET_mutex_unlock (lock);
  GNUNET_free (gm_cls.ebody);
  return GNUNET_OK;
}

/**
 * Establish a connection to a remote node.
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @param may_reuse can we re-use an existing connection?
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
api_connect (const GNUNET_MessageHello * hello, GNUNET_TSession ** tsessionPtr,
             int may_reuse)
{
  GNUNET_TSession *tsession;

  tsession = GNUNET_malloc (sizeof (GNUNET_TSession));
  tsession->internal = GNUNET_malloc (GNUNET_sizeof_hello (hello));
  tsession->peer = hello->senderIdentity;
  memcpy (tsession->internal, hello, GNUNET_sizeof_hello (hello));
  tsession->ttype = smtpAPI.protocol_number;
  (*tsessionPtr) = tsession;
  return GNUNET_OK;
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
api_disconnect (GNUNET_TSession * tsession)
{
  if (tsession != NULL)
  {
    if (tsession->internal != NULL)
      GNUNET_free (tsession->internal);
    GNUNET_free (tsession);
  }
  return GNUNET_OK;
}

/**
 * Start the server process to receive inbound traffic.
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
api_start_transport_server ()
{
  smtp_shutdown = GNUNET_NO;
  /* initialize SMTP network */
  dispatchThread = GNUNET_thread_create (&listenAndDistribute, NULL, 1024 * 4);
  if (dispatchThread == NULL)
  {
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_ADMIN | GNUNET_GE_BULK | GNUNET_GE_FATAL,
                            "pthread_create");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int
api_stop_transport_server ()
{
  void *unused;

  smtp_shutdown = GNUNET_YES;
  GNUNET_thread_stop_sleep (dispatchThread);
  GNUNET_thread_join (dispatchThread, &unused);
  return GNUNET_OK;
}

/**
 * Convert SMTP hello to an IP address (always fails).
 */
static int
api_hello_to_address (const GNUNET_MessageHello * hello, void **sa,
                      unsigned int *sa_len)
{
  return GNUNET_SYSERR;
}

/**
 * Always fails.
 */
static int
api_associate (GNUNET_TSession * tsession)
{
  return GNUNET_SYSERR;         /* SMTP connections can never be associated */
}

/**
 * Always succeeds (for now; we should look at adding
 * frequency limits to SMTP in the future!).
 */
static int
api_test_would_try (GNUNET_TSession * tsession, const unsigned int size,
                    int important)
{
  return GNUNET_OK;             /* we always try... */
}

/**
 * The exported method. Makes the core api available via a global and
 * returns the smtp transport API.
 */
GNUNET_TransportAPI *
inittransport_smtp (GNUNET_CoreAPIForTransport * core)
{


  unsigned long long mtu;
  struct sigaction sa;

  coreAPI = core;
  ectx = core->ectx;
  if (!GNUNET_GC_have_configuration_value (coreAPI->cfg, "SMTP", "EMAIL"))
  {
    GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                   _
                   ("No email-address specified, can not start SMTP transport.\n"));
    return NULL;
  }
  GNUNET_GC_get_configuration_value_number (coreAPI->cfg, "SMTP", "MTU", 1200,
                                            SMTP_MESSAGE_SIZE,
                                            SMTP_MESSAGE_SIZE, &mtu);
  GNUNET_GC_get_configuration_value_number (coreAPI->cfg, "SMTP", "RATELIMIT",
                                            0, 0, 1024 * 1024, &rate_limit);
  stats = coreAPI->service_request ("stats");
  if (stats != NULL)
  {
    stat_bytesReceived =
        stats->create (gettext_noop ("# bytes received via SMTP"));
    stat_bytesSent = stats->create (gettext_noop ("# bytes sent via SMTP"));
    stat_bytesDropped =
        stats->create (gettext_noop ("# bytes dropped by SMTP (outgoing)"));
  }
  GNUNET_GC_get_configuration_value_filename (coreAPI->cfg, "SMTP", "PIPE",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                              "/smtp-pipe", &pipename);
  UNLINK (pipename);
  if (0 != mkfifo (pipename, S_IWUSR | S_IRUSR | S_IWGRP | S_IWOTH))
  {
    GNUNET_GE_LOG_STRERROR (ectx,
                            GNUNET_GE_ADMIN | GNUNET_GE_BULK | GNUNET_GE_FATAL,
                            "mkfifo");
    GNUNET_free (pipename);
    coreAPI->service_release (stats);
    stats = NULL;
    return NULL;
  }
  /* we need to allow the mailer program to send us messages;
   * easiest done by giving it write permissions (see Mantis #1142) */
  if (0 != chmod (pipename, S_IWUSR | S_IRUSR | S_IWGRP | S_IWOTH))
    GNUNET_GE_LOG_STRERROR (ectx,
                            GNUNET_GE_ADMIN | GNUNET_GE_BULK |
                            GNUNET_GE_WARNING, "chmod");
  GNUNET_GC_get_configuration_value_string (coreAPI->cfg, "SMTP", "EMAIL", NULL,
                                            &email);
  lock = GNUNET_mutex_create (GNUNET_NO);
  GNUNET_GC_get_configuration_value_string (coreAPI->cfg, "SMTP", "SERVER",
                                            "localhost:25", &smtp_server_name);
  sa.sa_handler = SIG_IGN;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction (SIGPIPE, &sa, &old_handler);

  smtpAPI.protocol_number = GNUNET_TRANSPORT_PROTOCOL_NUMBER_SMTP;
  smtpAPI.mtu = mtu - sizeof (SMTPMessage);
  smtpAPI.cost = 50;
  smtpAPI.hello_verify = &api_verify_hello;
  smtpAPI.hello_create = &api_create_hello;
  smtpAPI.connect = &api_connect;
  smtpAPI.send = &api_send;
  smtpAPI.associate = &api_associate;
  smtpAPI.disconnect = &api_disconnect;
  smtpAPI.server_start = &api_start_transport_server;
  smtpAPI.server_stop = &api_stop_transport_server;
  smtpAPI.hello_to_address = &api_hello_to_address;
  smtpAPI.send_now_test = &api_test_would_try;
  return &smtpAPI;
}

void
donetransport_smtp ()
{
  sigaction (SIGPIPE, &old_handler, NULL);
  GNUNET_free (smtp_server_name);
  if (stats != NULL)
  {
    coreAPI->service_release (stats);
    stats = NULL;
  }
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  UNLINK (pipename);
  GNUNET_free (pipename);
  pipename = NULL;
  GNUNET_free (email);
  email = NULL;
}

/* end of smtp.c */
