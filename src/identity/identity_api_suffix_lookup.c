/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file identity/identity_api_suffix_lookup.c
 * @brief api to lookup an ego
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "identity.h"

#define LOG(kind, ...) GNUNET_log_from(kind, "identity-api", __VA_ARGS__)


/**
 * Handle for ego lookup.
 */
struct GNUNET_IDENTITY_EgoSuffixLookup {
  /**
   * Connection to service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Suffix we are looking up.
   */
  char *suffix;

  /**
   * Function to call with the result.
   */
  GNUNET_IDENTITY_EgoSuffixCallback cb;

  /**
   * Closure for @e cb
   */
  void *cb_cls;
};


/**
 * We received a result code from the service.  Check the message
 * is well-formed.
 *
 * @param cls closure
 * @param rcm result message received
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_identity_result_code(void *cls, const struct ResultCodeMessage *rcm)
{
  (void)cls;
  if (sizeof(*rcm) != htons(rcm->header.size))
    GNUNET_MQ_check_zero_termination(rcm);
  return GNUNET_OK;
}


/**
 * We received a result code from the service.
 *
 * @param cls closure
 * @param rcm result message received
 */
static void
handle_identity_result_code(void *cls, const struct ResultCodeMessage *rcm)
{
  struct GNUNET_IDENTITY_EgoSuffixLookup *el = cls;

  (void)rcm;
  el->cb(el->cb_cls, NULL, NULL);
  GNUNET_IDENTITY_ego_lookup_by_suffix_cancel(el);
}


/**
 * Check validity of identity update message.
 *
 * @param cls closure
 * @param um message received
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_identity_update(void *cls, const struct UpdateMessage *um)
{
  uint16_t size = ntohs(um->header.size);
  uint16_t name_len = ntohs(um->name_len);
  const char *str = (const char *)&um[1];

  (void)cls;
  if ((size != name_len + sizeof(struct UpdateMessage)) ||
      ((0 != name_len) && ('\0' != str[name_len - 1])))
    {
      GNUNET_break(0);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


/**
 * Handle identity update message.
 *
 * @param cls closure
 * @param um message received
 */
static void
handle_identity_update(void *cls, const struct UpdateMessage *um)
{
  struct GNUNET_IDENTITY_EgoSuffixLookup *el = cls;
  uint16_t name_len = ntohs(um->name_len);
  const char *str = (0 == name_len) ? NULL : (const char *)&um[1];

  el->cb(el->cb_cls, &um->private_key, str);
  GNUNET_IDENTITY_ego_lookup_by_suffix_cancel(el);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_IDENTITY_EgoSuffixLookup *`
 * @param error error code
 */
static void
mq_error_handler(void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_IDENTITY_EgoSuffixLookup *el = cls;

  (void)error;
  el->cb(el->cb_cls, NULL, NULL);
  GNUNET_IDENTITY_ego_lookup_by_suffix_cancel(el);
}


/**
 * Lookup an ego by name.
 *
 * @param cfg configuration to use
 * @param name name to look up
 * @param cb callback to invoke with the result
 * @param cb_cls closure for @a cb
 * @return NULL on error
 */
struct GNUNET_IDENTITY_EgoSuffixLookup *
GNUNET_IDENTITY_ego_lookup_by_suffix(const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     const char *suffix,
                                     GNUNET_IDENTITY_EgoSuffixCallback cb,
                                     void *cb_cls)
{
  struct GNUNET_IDENTITY_EgoSuffixLookup *el;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *req;
  size_t nlen;

  GNUNET_assert(NULL != cb);
  el = GNUNET_new(struct GNUNET_IDENTITY_EgoSuffixLookup);
  el->cb = cb;
  el->cb_cls = cb_cls;
  {
    struct GNUNET_MQ_MessageHandler handlers[] =
    { GNUNET_MQ_hd_var_size(identity_result_code,
                            GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE,
                            struct ResultCodeMessage,
                            el),
      GNUNET_MQ_hd_var_size(identity_update,
                            GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE,
                            struct UpdateMessage,
                            el),
      GNUNET_MQ_handler_end() };

    el->mq =
      GNUNET_CLIENT_connect(cfg, "identity", handlers, &mq_error_handler, el);
  }
  if (NULL == el->mq)
    {
      GNUNET_break(0);
      GNUNET_free(el);
      return NULL;
    }
  el->suffix = GNUNET_strdup(suffix);
  nlen = strlen(suffix) + 1;
  env = GNUNET_MQ_msg_extra(req, nlen, GNUNET_MESSAGE_TYPE_IDENTITY_LOOKUP_BY_SUFFIX);
  memcpy(&req[1], suffix, nlen);
  GNUNET_MQ_send(el->mq, env);
  return el;
}


/**
 * Abort ego lookup attempt.
 *
 * @param el handle for lookup to abort
 */
void
GNUNET_IDENTITY_ego_lookup_by_suffix_cancel(struct GNUNET_IDENTITY_EgoSuffixLookup *el)
{
  GNUNET_MQ_destroy(el->mq);
  GNUNET_free(el->suffix);
  GNUNET_free(el);
}


/* end of identity_api_suffix_lookup.c */
