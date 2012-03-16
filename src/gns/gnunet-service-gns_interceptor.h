#ifndef GNUNET_GNS_INTERCEPTOR_H
#define GNUNET_GNS_INTERCEPTOR_H

/**
 * Initialize dns interceptor
 *
 * @param zone the zone
 * @param c the configuration
 * @return GNUNET_YES on success GNUNET_SYSERR on error
 */
int
gns_interceptor_init(GNUNET_HashCode zone,
                     struct GNUNET_CRYPTO_RsaPrivateKey *key,
                     const struct GNUNET_CONFIGURATION_Handle *c);

void
gns_interceptor_stop(void){};

#endif
