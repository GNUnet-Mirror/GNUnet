#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>

#include <openssl/ssl.h>
#include <auth-client.h>
#include <libesmtp.h>

#if !defined (__GNUC__) || __GNUC__ < 2
# define __attribute__(x)
#endif
#define unused      __attribute__((unused))


int
handle_invalid_peer_certificate(long vfy_result)
{
  const char *k ="rare error";
  switch(vfy_result) {
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    k="X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT"; break;
  case X509_V_ERR_UNABLE_TO_GET_CRL:
    k="X509_V_ERR_UNABLE_TO_GET_CRL"; break;
  case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    k="X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE"; break;
  case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
    k="X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE"; break;
  case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    k="X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY"; break;
  case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    k="X509_V_ERR_CERT_SIGNATURE_FAILURE"; break;
  case X509_V_ERR_CRL_SIGNATURE_FAILURE:
    k="X509_V_ERR_CRL_SIGNATURE_FAILURE"; break;
  case X509_V_ERR_CERT_NOT_YET_VALID:
    k="X509_V_ERR_CERT_NOT_YET_VALID"; break;
  case X509_V_ERR_CERT_HAS_EXPIRED:
    k="X509_V_ERR_CERT_HAS_EXPIRED"; break;
  case X509_V_ERR_CRL_NOT_YET_VALID:
    k="X509_V_ERR_CRL_NOT_YET_VALID"; break;
  case X509_V_ERR_CRL_HAS_EXPIRED:
    k="X509_V_ERR_CRL_HAS_EXPIRED"; break;
  case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    k="X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD"; break;
  case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    k="X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD"; break;
  case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    k="X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD"; break;
  case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
    k="X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD"; break;
  case X509_V_ERR_OUT_OF_MEM:
    k="X509_V_ERR_OUT_OF_MEM"; break;
  case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    k="X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT"; break;
  case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    k="X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN"; break;
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    k="X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY"; break;
  case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    k="X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE"; break;
  case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    k="X509_V_ERR_CERT_CHAIN_TOO_LONG"; break;
  case X509_V_ERR_CERT_REVOKED:
    k="X509_V_ERR_CERT_REVOKED"; break;
  case X509_V_ERR_INVALID_CA:
    k="X509_V_ERR_INVALID_CA"; break;
  case X509_V_ERR_PATH_LENGTH_EXCEEDED:
    k="X509_V_ERR_PATH_LENGTH_EXCEEDED"; break;
  case X509_V_ERR_INVALID_PURPOSE:
    k="X509_V_ERR_INVALID_PURPOSE"; break;
  case X509_V_ERR_CERT_UNTRUSTED:
    k="X509_V_ERR_CERT_UNTRUSTED"; break;
  case X509_V_ERR_CERT_REJECTED:
    k="X509_V_ERR_CERT_REJECTED"; break;
  }
  printf("SMTP_EV_INVALID_PEER_CERTIFICATE: %ld: %s\n", vfy_result, k);
  return 1; /* Accept the problem */
}


void event_cb (smtp_session_t session, int event_no, void *arg,...)
{
  va_list alist;
  int *ok;

  va_start(alist, arg);
  switch(event_no) {
  case SMTP_EV_CONNECT: 
  case SMTP_EV_MAILSTATUS:
  case SMTP_EV_RCPTSTATUS:
  case SMTP_EV_MESSAGEDATA:
  case SMTP_EV_MESSAGESENT:
  case SMTP_EV_DISCONNECT: break;
  case SMTP_EV_WEAK_CIPHER: {
    int bits;
    bits = va_arg(alist, long); ok = va_arg(alist, int*);
    printf("SMTP_EV_WEAK_CIPHER, bits=%d - accepted.\n", bits);
    *ok = 1; break;
  }
  case SMTP_EV_STARTTLS_OK:
    puts("SMTP_EV_STARTTLS_OK - TLS started here."); break;
  case SMTP_EV_INVALID_PEER_CERTIFICATE: {
    long vfy_result;
    vfy_result = va_arg(alist, long); ok = va_arg(alist, int*);
    *ok = handle_invalid_peer_certificate(vfy_result);
    break;
  }
  case SMTP_EV_NO_PEER_CERTIFICATE: {
    ok = va_arg(alist, int*); 
    puts("SMTP_EV_NO_PEER_CERTIFICATE - accepted.");
    *ok = 1; break;
  }
  case SMTP_EV_WRONG_PEER_CERTIFICATE: {
    ok = va_arg(alist, int*);
    puts("SMTP_EV_WRONG_PEER_CERTIFICATE - accepted.");
    *ok = 1; break;
  }
  case SMTP_EV_NO_CLIENT_CERTIFICATE: {
    ok = va_arg(alist, int*); 
    puts("SMTP_EV_NO_CLIENT_CERTIFICATE - accepted.");
    *ok = 1; break;
  }
  default:
    printf("Got event: %d - ignored.\n", event_no);
  }
  va_end(alist);
}


/* Callback to prnt the recipient status */
void
print_recipient_status (smtp_recipient_t recipient,
			const char *mailbox, void *arg unused)
{
  const smtp_status_t *status;

  status = smtp_recipient_status (recipient);
  printf ("%s: %d %s", mailbox, status->code, status->text);
}


void sendMail() 
{
	smtp_session_t session;
	smtp_message_t message;
	smtp_recipient_t recipient;
	// auth_context_t authctx;
	const smtp_status_t *status;
	struct sigaction sa;
	char *host = "localhost:25";
	char *from = "gnunet-monkey";
	char *subject = "e-mail from Libesmtp!";
	const char *recipient_address = "halims@in.tum.de";
	char tempFileName[1000];
	int tempFd;
	FILE *fp;
	enum notify_flags notify = Notify_SUCCESS | Notify_FAILURE;

	auth_client_init();
	session = smtp_create_session();
	message = smtp_add_message(session);
	
	/* Ignore sigpipe */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);
	
	
	smtp_set_server(session, host);
	smtp_set_eventcb(session, event_cb, NULL);

	/* Set the reverse path for the mail envelope.  (NULL is ok)
	 */
	smtp_set_reverse_path(message, from);

	/* Set the Subject: header.  For no reason, we want the supplied subject
	 to override any subject line in the message headers. */
	if (subject != NULL) {
		smtp_set_header(message, "Subject", subject);
		smtp_set_header_option(message, "Subject", Hdr_OVERRIDE, 1);
	}

	
	/* Prepare message */
	memset(tempFileName, 0, sizeof(tempFileName));
	sprintf(tempFileName, "/tmp/messageXXXXXX");
	tempFd = mkstemp(tempFileName);
	fp = fdopen(tempFd, "w");
	fprintf(fp, "Hello! This is a test message!\r\n");
	fclose(fp);	
	fp = fopen(tempFileName, "r");
	smtp_set_message_fp(message, fp);

	
	recipient = smtp_add_recipient(message, recipient_address);

	smtp_dsn_set_notify (recipient, notify);
	
	/* Initiate a connection to the SMTP server and transfer the
	 message. */
	if (!smtp_start_session(session)) {
		char buf[128];

		fprintf(stderr, "SMTP server problem %s\n", smtp_strerror(smtp_errno(),
				buf, sizeof buf));
	} else {
		/* Report on the success or otherwise of the mail transfer.
		 */
		status = smtp_message_transfer_status(message);
		printf("%d %s", status->code, (status->text != NULL) ? status->text
				: "\n");
		smtp_enumerate_recipients(message, print_recipient_status, NULL);
	}

	/* Free resources consumed by the program.
	 */
	smtp_destroy_session(session);
	// auth_destroy_context(authctx);
	fclose(fp);
	auth_client_exit();
	exit(0);
}

int main()
{
	sendMail();
	return 0;
}
